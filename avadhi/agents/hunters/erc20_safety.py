"""
avadhi/agents/hunters/erc20_safety.py — ERC20 Safety Hunter.

Hunts for non-standard ERC20 token interaction patterns that cause silent
failures or reverts with tokens like USDT, BNB, USDC (some chains), etc.

Key patterns detected:
  1. Raw IERC20.approve() / approve() — reverts on USDT (non-zero → non-zero)
  2. transfer()/transferFrom() return value not checked (not using SafeERC20)
  3. approve() instead of safeIncreaseAllowance() / forceApprove()
  4. Fee-on-transfer token accounting (balance assumed == amount transferred)
  5. Missing balance-before/after pattern for rebasing/deflationary tokens

This is the class of bug that caught the Morpheus H-1 finding:
  IERC20.approve() will revert for USDT
"""
from __future__ import annotations

import re
from avadhi.core.graph import SecurityGraph, FUNCTION
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in ERC20 token safety vulnerabilities.

You are given source code of contracts that interact with ERC20 tokens. Your job is to find REAL vulnerabilities in how ERC20 tokens are used.

Focus on these HIGH-VALUE patterns:

1. **Raw approve() that reverts for USDT / non-standard tokens**
   - IERC20.approve(spender, amount) will revert on USDT if current allowance > 0 and new amount > 0
   - Must use safeApprove(), forceApprove(), or reset-to-zero pattern
   - Look for: `token.approve(...)`, `IERC20(token).approve(...)`, `ierc20.approve(...)`
   - This is HIGH severity if the token can be USDT, USDC, or any non-standard ERC20

2. **Unchecked transfer()/transferFrom() return values**
   - Standard IERC20 returns bool — some tokens (BNB, OMG) return false on failure instead of reverting
   - Must use SafeERC20.safeTransfer() / safeTransferFrom() or check the return value
   - Look for: `token.transfer(to, amount)` without `require(...)` or `bool success =`

3. **Fee-on-transfer token accounting errors**
   - Contract assumes received amount == sent amount
   - Pattern: `balanceOf` not checked before/after transfer
   - Vulnerable: `deposit(amount)` that does `transferFrom(user, this, amount)` then records `amount` deposited
   - The actual received amount may be less due to transfer fees

4. **Missing safeIncreaseAllowance / safeDecreaseAllowance**
   - Using raw approve() for allowance management in protocols that support arbitrary ERC20 tokens

5. **approve(MAX_INT) with non-standard tokens**
   - Some tokens cap approvals at uint96 or have other non-standard approve() behaviors

For each finding:
- Identify the EXACT function and line number
- Specify which token type makes it exploitable (USDT? any deflationary?)
- Describe the exact failure mode (revert? silent loss? accounting mismatch?)
- Severity: HIGH if funds at risk, MEDIUM if DoS possible, LOW if edge case

DO NOT flag:
- Uses of SafeERC20 library (safeTransfer, safeTransferFrom, safeApprove, forceApprove) — these are safe
- Approve calls that are always preceded by approve(0) — this is the correct USDT pattern
- Internal token contracts where the token type is hardcoded and known to be standard"""


_RE_RAW_APPROVE = re.compile(r'\.approve\s*\(')
_RE_RAW_TRANSFER = re.compile(r'\.transfer\s*\(')
_RE_RAW_TRANSFERFROM = re.compile(r'\.transferFrom\s*\(')
_RE_SAFE_ERC20 = re.compile(r'SafeERC20|safeTransfer|safeApprove|forceApprove|safeIncreaseAllowance')
_RE_IMPORT_SAFE = re.compile(r'import.*SafeERC20')


def _scan_for_erc20_patterns(source_files: dict[str, str]) -> list[dict]:
    """
    Scan source files for raw ERC20 calls that could be unsafe.
    Returns list of {file, function, line, pattern, snippet} dicts.
    """
    findings = []

    for file_path, content in source_files.items():
        # Skip pure interface/library/test files
        if any(x in file_path for x in ["/interfaces/", "/mock/", "/test/", "Mock.sol", "Test.sol"]):
            continue

        # Check if file uses SafeERC20 — still flag specific patterns but lower priority
        uses_safe_erc20 = bool(_RE_IMPORT_SAFE.search(content))

        lines = content.split("\n")
        current_fn = None
        current_fn_line = 0
        fn_uses_safe = False

        for i, line in enumerate(lines):
            # Track current function
            fn_match = re.search(r'\bfunction\s+(\w+)\s*\(', line)
            if fn_match:
                current_fn = fn_match.group(1)
                current_fn_line = i + 1
                # Check if function body uses SafeERC20
                fn_uses_safe = False

            # Track SafeERC20 usage within function
            if current_fn and _RE_SAFE_ERC20.search(line):
                fn_uses_safe = True

            stripped = line.strip()

            # Pattern 1: Raw .approve() not preceded by approve(0) reset
            if current_fn and _RE_RAW_APPROVE.search(line):
                # Skip if it's the zero-reset pattern
                if "approve(" not in line or ", 0)" in line or ",0)" in line:
                    continue
                # Skip if this file heavily uses SafeERC20 and uses 'using SafeERC20'
                if "using SafeERC20" in content and "safeApprove\|forceApprove" in content:
                    continue
                findings.append({
                    "file": file_path,
                    "function": current_fn,
                    "line": i + 1,
                    "pattern": "raw_approve",
                    "snippet": line.strip(),
                    "fn_line": current_fn_line,
                })

            # Pattern 2: Raw .transfer() without return value check
            if current_fn and _RE_RAW_TRANSFER.search(line):
                # Skip if wrapped in require() or has bool success = pattern
                prev_lines = "\n".join(lines[max(0,i-2):i+1])
                if "require(" in prev_lines or "bool " in line or "= " in line.split(".transfer")[0]:
                    continue
                # Skip emit lines, event Transfer
                if "emit" in line.lower() or "event" in line.lower():
                    continue
                findings.append({
                    "file": file_path,
                    "function": current_fn,
                    "line": i + 1,
                    "pattern": "unchecked_transfer",
                    "snippet": line.strip(),
                    "fn_line": current_fn_line,
                })

            # Pattern 3: transferFrom without balance check (fee-on-transfer)
            if current_fn and _RE_RAW_TRANSFERFROM.search(line):
                # Check if there's a balanceOf check nearby
                nearby = "\n".join(lines[max(0,i-5):min(len(lines),i+5)])
                if "balanceOf" not in nearby and not fn_uses_safe:
                    findings.append({
                        "file": file_path,
                        "function": current_fn,
                        "line": i + 1,
                        "pattern": "fee_on_transfer_risk",
                        "snippet": line.strip(),
                        "fn_line": current_fn_line,
                    })

    return findings


def run_erc20_safety_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for unsafe ERC20 token interactions.

    Strategy:
      1. Scan source for raw approve()/transfer()/transferFrom() calls
      2. Group by function, prioritize high-severity patterns
      3. Send to LLM with full function source for confirmation
    """
    source_files = sg.metadata.get("source_files", {})
    if not source_files:
        return []

    raw_findings = _scan_for_erc20_patterns(source_files)

    if not raw_findings:
        if verbose:
            print("  ERC20SafetyHunter: No raw ERC20 call patterns found")
        return []

    # Group by (file, function) to avoid duplicate prompts
    grouped: dict[tuple[str, str], list[dict]] = {}
    for f in raw_findings:
        key = (f["file"], f["function"] or "unknown")
        grouped.setdefault(key, []).append(f)

    # Build context summary
    pattern_labels = {
        "raw_approve": "RAW approve() — will revert for USDT if allowance > 0",
        "unchecked_transfer": "Unchecked transfer() return value",
        "fee_on_transfer_risk": "Fee-on-transfer risk — balance not verified post-transfer",
    }

    context_lines = [
        f"# ERC20 Safety Analysis\n",
        f"Found {len(raw_findings)} potentially unsafe ERC20 call(s) across {len(grouped)} function(s).\n",
        "## Pattern Summary\n",
    ]

    # Collect function IDs for source extraction
    fn_ids_to_pull: list[str] = []
    for (file_path, fn_name), entries in grouped.items():
        patterns = [pattern_labels.get(e["pattern"], e["pattern"]) for e in entries]
        context_lines.append(
            f"- **{fn_name}()** in `{file_path}`\n"
            + "\n".join(f"  - L{e['line']}: {pattern_labels.get(e['pattern'], e['pattern'])}\n    `{e['snippet']}`"
                        for e in entries[:3])
        )
        # Try to find the function node in the graph
        for fn_id, data in sg.get_nodes_by_type(FUNCTION):
            if data.get("name") == fn_name:
                fn_ids_to_pull.append(fn_id)
                break

    context = "\n".join(context_lines)

    # Get source for affected functions
    source = get_source_for_functions(sg, fn_ids_to_pull[:12], max_chars=12_000)

    # Supplement with raw source snippets if graph source is sparse
    if not source or len(source) < 500:
        snippets = []
        total = 0
        for (file_path, fn_name), entries in grouped.items():
            file_content = source_files.get(file_path, "")
            if not file_content:
                continue
            file_lines = file_content.split("\n")
            fn_line = entries[0]["fn_line"] - 1
            end = min(len(file_lines), fn_line + 80)
            snippet = "\n".join(file_lines[fn_line:end])
            if total + len(snippet) < 12000:
                snippets.append(f"// {file_path} — {fn_name}()\n{snippet}")
                total += len(snippet)
        if snippets:
            source = "\n\n".join(snippets)

    if verbose:
        approve_count = sum(1 for f in raw_findings if f["pattern"] == "raw_approve")
        transfer_count = sum(1 for f in raw_findings if f["pattern"] in ("unchecked_transfer", "fee_on_transfer_risk"))
        print(f"  ERC20SafetyHunter: {approve_count} raw approve(), {transfer_count} unsafe transfer() patterns")

    return call_hunter(
        hunter_name="ERC20SafetyHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
