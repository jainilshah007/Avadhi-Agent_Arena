"""
avadhi/agents/hunters/upgradeable_safety.py — Upgradeable Contract Safety Hunter.

Hunts for common vulnerabilities in UUPS/TransparentProxy/Beacon upgradeable contracts:

  1. Missing __gap[N] storage variable  → storage collision on upgrade
  2. Ownable instead of Ownable2Step    → single-tx ownership transfer risk
  3. Uninitialised upgradeable contracts → default values after upgrade
  4. Unprotected initializer functions  → front-run attack surface
  5. Mutable state in constructor       → bypassed on proxy deployment
  6. Missing _disableInitializers()     → re-initialization after upgrade

This is the class of bugs that 4naly3er L-21/L-22/L-19 caught on Morpheus
but Avadhi missed due to no dedicated hunter.
"""
from __future__ import annotations

import re
from avadhi.core.graph import SecurityGraph, FUNCTION
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in UPGRADEABLE CONTRACT vulnerabilities.

You are given source code of upgradeable contracts (using UUPS, TransparentProxy, or Beacon patterns).

Your job is to find REAL vulnerabilities in the upgrade/initialization safety of these contracts.

Focus on these HIGH-VALUE patterns:

1. **Missing __gap Storage Variable**
   - Upgradeable contracts that add storage variables MUST reserve gap slots
   - Pattern: contract inherits from *Upgradeable but has NO `uint256[N] private __gap;` at bottom
   - Risk: Future upgrades adding new storage variables will corrupt existing storage layout
   - Severity: MEDIUM (latent bug that becomes critical on next upgrade)

2. **Ownable instead of Ownable2Step**
   - `OwnableUpgradeable` allows ownership transfer in a single tx (no acceptance step)
   - If the owner calls `transferOwnership(wrongAddress)`, ownership is permanently lost
   - Should use `Ownable2StepUpgradeable` which requires the new owner to accept
   - Severity: MEDIUM

3. **Unprotected Initializer / Missing _disableInitializers()**
   - UUPS implementation contracts should call `_disableInitializers()` in their constructor
   - Without it, the implementation contract itself can be initialized by anyone
   - An attacker can initialize the implementation, become owner, then call `upgradeToAndCall`
     to self-destruct or replace the implementation
   - Look for: constructor() that does NOT call `_disableInitializers()`
   - Severity: CRITICAL if upgradeToAndCall is available, HIGH otherwise

4. **State Variables in Constructors of Upgradeable Contracts**
   - In proxy patterns, the constructor runs on the IMPLEMENTATION, not the proxy
   - State set in constructor is NOT visible through the proxy
   - Look for non-constant state variables initialized in constructor bodies
   - Severity: HIGH (silent data loss)

5. **Initializer Missing initializer/reinitializer Modifier**
   - init functions without `initializer` or `reinitializer` modifier can be called multiple times
   - Look for functions named `initialize*` or `*_init` without OZ initializer modifiers
   - Severity: CRITICAL if it resets access controls

6. **Storage Collision Between Implementation Versions**
   - When new storage variables are added without using __gap, they overwrite existing slots
   - Compare state variable declarations across version contracts (V1, V2, V3)
   - Severity: CRITICAL

For each finding, be SPECIFIC about:
- The exact contract name and function
- Which upgrade pattern is used (UUPS/Transparent/Beacon)
- The exact attack or data corruption scenario
- Whether the vulnerability is exploitable NOW or only on next upgrade

DO NOT flag:
- `_disableInitializers()` calls that ARE present in constructors
- Contracts that DO have `__gap` storage variables
- Libraries (they don't have storage)
- Interfaces"""


_RE_UPGRADEABLE = re.compile(r'UUPSUpgradeable|TransparentUpgradeableProxy|BeaconProxy|Initializable')
_RE_GAP = re.compile(r'uint256\s*\[\s*\d+\s*\]\s*(private\s+)?__gap')
_RE_OWNABLE2STEP = re.compile(r'Ownable2Step')
_RE_OWNABLE = re.compile(r'\bOwnable\b')
_RE_DISABLE_INIT = re.compile(r'_disableInitializers\s*\(\s*\)')
_RE_CONSTRUCTOR = re.compile(r'\bconstructor\s*\(')
_RE_INITIALIZER_MOD = re.compile(r'\binitializer\b|\breinitializer\b')
_RE_INIT_FN = re.compile(r'\b(initialize|__\w+_init)\s*\(')


def _scan_upgradeable_contracts(source_files: dict[str, str]) -> list[dict]:
    """
    Scan source files for upgradeable contract safety issues.
    Returns list of findings with metadata.
    """
    findings = []

    for file_path, content in source_files.items():
        # Skip non-upgradeable contracts, interfaces, mocks, tests
        if not _RE_UPGRADEABLE.search(content):
            continue
        if any(x in file_path for x in ["/interfaces/", "/mock/", "/test/", "Mock.sol", "Test.sol", "Interface"]):
            continue

        # Extract contract name
        contract_match = re.search(r'\bcontract\s+(\w+)', content)
        contract_name = contract_match.group(1) if contract_match else "Unknown"

        # Pattern 1: Missing __gap
        if not _RE_GAP.search(content):
            findings.append({
                "file": file_path,
                "contract": contract_name,
                "pattern": "missing_gap",
                "detail": f"{contract_name} is upgradeable but has no __gap storage variable",
                "severity": "Medium",
            })

        # Pattern 2: Ownable instead of Ownable2Step
        if _RE_OWNABLE.search(content) and not _RE_OWNABLE2STEP.search(content):
            # Only flag if it's genuinely using OwnableUpgradeable
            if "OwnableUpgradeable" in content:
                findings.append({
                    "file": file_path,
                    "contract": contract_name,
                    "pattern": "ownable_not_2step",
                    "detail": f"{contract_name} uses OwnableUpgradeable (single-step) instead of Ownable2StepUpgradeable",
                    "severity": "Medium",
                })

        # Pattern 3: UUPS without _disableInitializers() in constructor
        if "UUPSUpgradeable" in content:
            has_constructor = bool(_RE_CONSTRUCTOR.search(content))
            has_disable = bool(_RE_DISABLE_INIT.search(content))
            if has_constructor and not has_disable:
                findings.append({
                    "file": file_path,
                    "contract": contract_name,
                    "pattern": "missing_disable_initializers",
                    "detail": f"{contract_name} is UUPS upgradeable with a constructor but no _disableInitializers()",
                    "severity": "High",
                })
            elif not has_constructor and not has_disable:
                # No constructor at all — still flagged but lower priority
                findings.append({
                    "file": file_path,
                    "contract": contract_name,
                    "pattern": "missing_disable_initializers",
                    "detail": f"{contract_name} is UUPS upgradeable with no _disableInitializers() — implementation can be initialized",
                    "severity": "Medium",
                })

        # Pattern 4: Initialize function without initializer modifier
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if _RE_INIT_FN.search(line) and "function " in line:
                # Check next 3 lines for initializer modifier
                context_block = "\n".join(lines[i:min(i + 5, len(lines))])
                if not _RE_INITIALIZER_MOD.search(context_block):
                    fn_match = _RE_INIT_FN.search(line)
                    fn_name = fn_match.group(1) if fn_match else "unknown"
                    # Skip internal/private init helpers that call the parent's __init
                    if "internal" in context_block.lower() and "_init" in fn_name:
                        continue
                    findings.append({
                        "file": file_path,
                        "contract": contract_name,
                        "pattern": "unguarded_initializer",
                        "detail": f"{contract_name}.{fn_name}() looks like an initializer but lacks the `initializer` modifier",
                        "severity": "High",
                        "line": i + 1,
                    })

    return findings


def run_upgradeable_safety_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for unsafe upgradeable contract patterns.

    Strategy:
      1. Scan source files for upgradeable contracts
      2. Check for missing __gap, Ownable2Step, _disableInitializers, etc.
      3. Provide full contract source for LLM confirmation
    """
    source_files = sg.metadata.get("source_files", {})
    if not source_files:
        return []

    raw_findings = _scan_upgradeable_contracts(source_files)

    if not raw_findings:
        if verbose:
            print("  UpgradeableSafetyHunter: No upgradeable safety issues detected")
        return []

    # Group by file to consolidate
    by_contract: dict[str, list[dict]] = {}
    for f in raw_findings:
        key = f["contract"]
        by_contract.setdefault(key, []).append(f)

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    pattern_labels = {
        "missing_gap": "Missing __gap storage variable (storage collision risk on upgrade)",
        "ownable_not_2step": "Uses Ownable (single-step) instead of Ownable2Step",
        "missing_disable_initializers": "UUPS without _disableInitializers() — implementation initializable",
        "unguarded_initializer": "Initializer function missing `initializer` modifier — re-entrancy possible",
    }

    context_lines = [
        f"# Upgradeable Contract Safety Analysis\n",
        f"Found {len(raw_findings)} potential safety issue(s) across {len(by_contract)} contract(s).\n",
    ]

    fn_ids_to_pull: list[str] = []
    for contract_name, entries in sorted(by_contract.items(),
                                         key=lambda x: min(severity_order.get(e["severity"], 2) for e in x[1])):
        context_lines.append(f"\n## {contract_name}")
        for entry in entries:
            label = pattern_labels.get(entry["pattern"], entry["pattern"])
            context_lines.append(f"- [{entry['severity']}] {label}")
            context_lines.append(f"  Detail: {entry['detail']}")

        # Try to find relevant function nodes in graph
        for fn_id, data in sg.get_nodes_by_type(FUNCTION):
            if data.get("contract") == contract_name:
                fn_ids_to_pull.append(fn_id)

    context = "\n".join(context_lines)

    # Get source for the affected contracts
    source = get_source_for_functions(sg, fn_ids_to_pull[:15], max_chars=12_000)

    # Supplement with raw file content if graph source is sparse
    if not source or len(source) < 500:
        snippets = []
        total = 0
        seen_contracts = set()
        for entry in raw_findings:
            if entry["contract"] in seen_contracts:
                continue
            seen_contracts.add(entry["contract"])
            file_content = source_files.get(entry["file"], "")
            if file_content and total + len(file_content) < 12000:
                snippets.append(f"// {entry['file']}\n{file_content[:3000]}")
                total += 3000
        if snippets:
            source = "\n\n".join(snippets)

    if verbose:
        high = sum(1 for f in raw_findings if f["severity"] == "High")
        medium = sum(1 for f in raw_findings if f["severity"] == "Medium")
        print(f"  UpgradeableSafetyHunter: {len(by_contract)} upgradeable contracts — {high} High, {medium} Medium patterns")

    return call_hunter(
        hunter_name="UpgradeableSafetyHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
