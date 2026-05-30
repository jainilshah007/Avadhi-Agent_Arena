"""
avadhi/agents/poc_gen.py — PoC Generation Agent.

Generates Foundry test stubs for confirmed/contested findings.
Only runs for High/Critical severity findings (Immunefi submission requirement).

Approach (inspired by Plamen + SmartInv):
  1. Select category-specific template skeleton
  2. Extract target contract/function source from SecurityGraph
  3. LLM fills in concrete attack steps using Tier of Thought:
     - Tier 1: What invariant is violated?
     - Tier 2: What transaction sequence triggers it?
     - Tier 3: What assertions prove it?
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.schemas import Hypothesis, Severity
from avadhi.utils.llm import get_llm
from avadhi.utils.logging import AuditLogger

if TYPE_CHECKING:
    from avadhi.core.graph import SecurityGraph


SYSTEM_PROMPT = """You are an expert Solidity security researcher who writes Foundry proof-of-concept tests.

Given a vulnerability finding and the relevant source code, generate a COMPLETE, RUNNABLE Foundry test that demonstrates the exploit.

Your test must:
1. Set up the necessary state (deploy contracts, fund accounts, set roles)
2. Execute the attack sequence step by step
3. Assert the unexpected/harmful outcome (stolen funds, DoS, state corruption)

Use this structure:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    // Contract instances
    // ...

    function setUp() public {
        // Deploy or fork contracts
        // Set initial state
        // Fund accounts
    }

    function test_exploit() public {
        // Step 1: ...
        // Step 2: ...
        // Step 3: ...

        // Assert the vulnerability
        // e.g., assertGt(attacker.balance, initialBalance);
        // e.g., vm.expectRevert();
    }
}
```

IMPORTANT RULES:
- Use `vm.prank(address)` for impersonation, NOT `msg.sender` hacks
- Use `vm.deal(address, amount)` to fund ETH, `deal(token, address, amount)` for ERC20
- Use `vm.warp(timestamp)` for time manipulation
- Use `vm.expectRevert()` for DoS proofs
- If you need to fork mainnet, use `vm.createSelectFork()`
- Keep the test focused — one test function, one exploit path
- Add comments explaining each step
- If the exact contract interfaces aren't available, use reasonable mock interfaces
- For gas DoS, use `gasleft()` assertions or demonstrate OOG with large inputs

RETURN ONLY THE SOLIDITY CODE. No markdown, no explanation, just the .sol file content."""


# Category-specific setup hints for the LLM
_CATEGORY_HINTS = {
    "gas": """This is a Gas/DoS vulnerability. Your PoC should:
- Create enough state to trigger the gas issue (e.g., buy many tickets, add many entries)
- Call the vulnerable function and show it reverts with OOG or uses excessive gas
- Use gasleft() before and after to measure, or vm.expectRevert() for OOG""",

    "access": """This is an Access Control vulnerability. Your PoC should:
- Call the vulnerable function from an unauthorized address
- Show that the privileged operation succeeds without proper auth
- Assert the state change that should have been prevented""",

    "accounting": """This is an Accounting/Math vulnerability. Your PoC should:
- Set up initial state with specific amounts
- Execute the sequence that breaks the invariant
- Assert the incorrect balance/total/share value
- Show the difference between expected and actual amounts""",

    "oracle": """This is an Oracle/Randomness vulnerability. Your PoC should:
- Show the admin changing the oracle/entropy/calculator address mid-operation
- Demonstrate the inconsistency between start and end of the operation
- Assert the unexpected outcome (wrong payout, frozen state, etc.)""",

    "governance": """This is a Governance/Temporal vulnerability. Your PoC should:
- Start an operation (e.g., a draw, deposit)
- Have the admin call the setter mid-operation
- Show the operation completes with inconsistent state
- Assert the harm (wrong price, DoS, fund loss)""",

    "reentrancy": """This is a Reentrancy vulnerability. Your PoC should:
- Create an attacker contract with a receive()/fallback() that re-enters
- Trigger the external call that allows re-entrance
- Assert that the attacker extracted more than entitled""",

    "external": """This is an External Call vulnerability. Your PoC should:
- Show the arbitrary call with attacker-controlled parameters
- Demonstrate fund theft or state corruption via the call
- Assert the stolen amount or corrupted state""",
}


def generate_pocs(
    hypotheses: list[Hypothesis],
    sg: "SecurityGraph",
    logger: AuditLogger | None = None,
    verbose: bool = False,
    severity_threshold: Severity = Severity.HIGH,
) -> dict[str, str]:
    """
    Generate Foundry PoC tests for high-severity findings.

    Args:
        hypotheses: List of confirmed/contested hypotheses
        sg: SecurityGraph with source files
        logger: Optional audit logger
        verbose: Print progress
        severity_threshold: Minimum severity to generate PoC (default: High)

    Returns:
        Dict mapping hypothesis ID to PoC Solidity code
    """
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
        Severity.LOW: 3, Severity.INFO: 4,
    }
    threshold = severity_order.get(severity_threshold, 1)

    eligible = [
        h for h in hypotheses
        if severity_order.get(h.severity, 4) <= threshold
    ]

    if not eligible:
        if verbose:
            print("  ℹ️  PoC Generator: No findings at or above severity threshold")
        return {}

    if verbose:
        print(f"  🔧 PoC Generator: Generating PoCs for {len(eligible)} findings")

    pocs: dict[str, str] = {}
    llm = get_llm()

    from avadhi.config import HUNTER_CONCURRENCY

    def _gen_one(h: Hypothesis) -> tuple[str, str | None]:
        if verbose:
            print(f"    Generating PoC for {h.id}: {h.title[:50]}...")
        try:
            poc = _generate_single_poc(h, sg, llm, logger, verbose)
            return h.id, poc
        except Exception as e:
            if verbose:
                print(f"    WARNING  PoC generation failed for {h.id}: {e}")
            return h.id, None

    with ThreadPoolExecutor(max_workers=min(HUNTER_CONCURRENCY, len(eligible))) as pool:
        futures = {pool.submit(_gen_one, h): h for h in eligible}
        for fut in as_completed(futures):
            hyp_id, poc = fut.result()
            if poc:
                pocs[hyp_id] = poc

    return pocs


def _generate_single_poc(
    h: Hypothesis,
    sg: "SecurityGraph",
    llm,
    logger: AuditLogger | None,
    verbose: bool,
) -> str:
    """Generate a single PoC for one hypothesis."""
    # Determine category hint
    category_lower = h.category.lower()
    hint = ""
    for key, text in _CATEGORY_HINTS.items():
        if key in category_lower:
            hint = text
            break
    if not hint:
        # Try matching on hunter agent name
        hunter_lower = h.hunter_agent.lower()
        for key, text in _CATEGORY_HINTS.items():
            if key in hunter_lower:
                hint = text
                break

    # Extract relevant source code
    source_snippets = _get_finding_source(h, sg)

    prompt = f"""## Vulnerability Finding

**Title:** {h.title}
**Severity:** {h.severity.value}
**Category:** {h.category}
**Location:** {h.location}

**Description:**
{h.description}

**Attack Scenario:**
{h.attack_scenario}

**Impact:**
{h.impact}

## Category-Specific Guidance

{hint}

## Relevant Source Code

{source_snippets}

---

Generate a COMPLETE Foundry test that demonstrates this vulnerability.
Use the Tier of Thought approach:
1. What invariant/property is being violated?
2. What exact sequence of transactions triggers the violation?
3. What assertions prove the violation occurred?

Return ONLY the Solidity code."""

    start = time.time()
    from avadhi.agents.hunters.base import _invoke_with_backoff

    try:
        response = _invoke_with_backoff(
            llm,
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)],
            hunter_name=f"PoCGen:{h.id}",
            max_retries=5
        )
        latency_ms = int((time.time() - start) * 1000)
    except Exception as e:
        if verbose:
            print(f"    WARNING  PoC generation failed for {h.id}: {e}")
        return ""

    response_text = response.content if hasattr(response, "content") else str(response)

    if logger:
        usage = getattr(response, "usage_metadata", {}) or {}
        logger.log_llm_call(
            agent="PoC Generator",
            model=str(getattr(llm, "model", "unknown")),
            phase="poc_generation",
            prompt_tokens=usage.get("input_tokens", 0),
            completion_tokens=usage.get("output_tokens", 0),
            latency_ms=latency_ms,
        )

    if verbose:
        print(f"    OK PoC generated ({len(response_text)} chars, {latency_ms}ms)")

    # Clean up: extract just the Solidity code
    return _extract_solidity(response_text)


def _get_finding_source(h: Hypothesis, sg: "SecurityGraph") -> str:
    """Extract source code relevant to a finding from the SecurityGraph."""
    source_files = sg.metadata.get("source_files", {})
    if not source_files:
        return "(no source available)"

    # Try to find source from location field (e.g., "Jackpot.claimWinnings:L418")
    location = h.location
    snippets = []

    # Parse location to get contract and function names
    parts = location.split(",")  # Multiple locations separated by commas
    for part in parts:
        part = part.strip()
        # Try "Contract.function:Lxxx" format
        if "." in part:
            contract_fn = part.split(":")[0] if ":" in part else part
            contract = contract_fn.split(".")[0]
            for file_path, content in source_files.items():
                if contract in content:
                    lines = content.split("\n")
                    # Try to extract around the line number
                    if ":L" in part:
                        try:
                            line_num = int(part.split(":L")[-1].split("-")[0])
                            start = max(0, line_num - 5)
                            end = min(len(lines), line_num + 60)
                            snippet = "\n".join(lines[start:end])
                            snippets.append(f"// {file_path} (L{start+1}-{end})\n{snippet}")
                        except ValueError:
                            pass
                    break

        if len("\n\n".join(snippets)) > 8000:
            break

    return "\n\n".join(snippets) if snippets else "(source not found for this location)"


def _extract_solidity(text: str) -> str:
    """
    Extract Solidity code from LLM response, stripping markdown fences.
    Robust to truncated or missing closing fences.
    """
    text = text.strip()
    if "```solidity" in text:
        parts = text.split("```solidity")
        if len(parts) > 1:
            # Get everything after the opening fence, up to the next closing fence or end of string
            content = parts[1].split("```")[0].strip()
            return content

    if "```" in text:
        parts = text.split("```")
        if len(parts) > 1:
            # Skip optional language identifier line (e.g. "python" or "solidity")
            content = parts[1]
            if "\n" in content:
                first_line = content.split("\n")[0]
                # If first line is a single word (language tag), skip it
                if len(first_line) < 20 and " " not in first_line.strip():
                    content = "\n".join(content.split("\n")[1:])
            # Get everything up to the next closing fence or end of string
            return content.split("```")[0].strip()

    # If no code fences, check if the whole response looks like Solidity
    if text.startswith("//") or text.startswith("pragma") or "contract" in text:
        return text

    return text
