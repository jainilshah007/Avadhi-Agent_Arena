"""
avadhi/agents/hunters/vector_scan.py — Vector Scan Agent.

Inspired by Pashov's Vector Scan Agent: systematically check the codebase
against a curated catalog of known attack vectors.

For each vector, classify as:
  - SKIP: codebase doesn't use the relevant feature
  - DROP: feature is present but properly guarded
  - INVESTIGATE: feature is present and guard may be insufficient

Only report INVESTIGATE classifications as findings.
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, WRITES, READS, EXTERNAL_CALL
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


# Curated attack vector catalog (high-signal subset, inspired by Pashov's 266)
ATTACK_VECTORS = """## Attack Vector Catalog

For each vector below, classify as SKIP (not applicable), DROP (guarded), or INVESTIGATE (potentially vulnerable).

### Access Control & Authorization
V1: Unprotected initializer — initialize() callable by anyone after deployment
V2: Missing access control on state-changing function — public function writes critical state without modifier
V3: Privilege escalation chain — role A can grant itself role B
V4: Inconsistent guards — same state written by functions with different access levels
V5: Signature replay — signed message reusable across chains, contracts, or after state change

### Reentrancy & External Calls
V6: Cross-function reentrancy — function A makes external call, function B reads stale state
V7: Cross-contract reentrancy — external call allows callback to different protocol contract
V8: Read-only reentrancy — view function returns stale data during callback
V9: ERC-777/ERC-721 callback — token transfer triggers onReceived before state update
V10: Unchecked return value — .call()/.send() return value ignored

### Token & Value Handling
V11: Fee-on-transfer token — contract assumes transfer amount equals received amount
V12: Rebasing token — balance changes without transfer, breaking accounting
V13: Token with blacklist — transfer reverts for blacklisted addresses, causing DoS
V14: Missing zero-address check — tokens sent to address(0) are burned
V15: Approval race condition — approve() frontrunnable without increaseAllowance pattern
V16: First depositor inflation attack — first deposit with tiny amount then donate to inflate share price

### Oracle & Price Manipulation
V17: Spot price manipulation — AMM reserve ratio read in same tx as flash loan
V18: Stale oracle data — no freshness check on oracle response
V19: Oracle single point of failure — no fallback if oracle goes down
V20: Flash loan price manipulation — borrow → manipulate price → profit → repay in one tx

### Math & Precision
V21: Division before multiplication — precision loss from wrong operation order
V22: Rounding direction — rounding favors user over protocol (should round against user)
V23: Zero-amount exploit — zero value bypasses checks but triggers state changes
V24: Overflow in intermediate — safe final result but intermediate calculation overflows
V25: Mixed decimals — comparing or combining values with different decimal scales

### State Machine & Logic
V26: State transition skip — can jump from state A to state C without passing through B
V27: Front-running — pending transaction observable and exploitable by MEV
V28: Timestamp manipulation — block.timestamp used for critical logic (manipulable by ~15s)
V29: Missing deadline check — transaction executable long after intended
V30: Governance flash loan — borrow tokens, vote, return in same block

### Protocol-Specific
V31: Donation attack — direct transfer to contract breaks internal accounting
V32: Sandwich attack — front-run + back-run a user's swap transaction
V33: Liquidation cascade — one liquidation triggers another in a feedback loop
V34: Bridge message replay — cross-chain message replayable on same or different chain
V35: Proxy storage collision — implementation upgrade causes storage slot overlap
V36: Uninitialized proxy — implementation contract left uninitialized after deployment
V37: Selfdestruct in implementation — delegatecall to self-destructing contract kills proxy

### Gas & DoS
V38: Unbounded loop — array iteration grows with state, eventually exceeds block gas limit
V39: External call in loop — single revert in loop blocks all operations
V40: Storage write in loop — O(n) storage writes where n is unbounded
"""


def run_vector_scan_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Systematically check the codebase against known attack vectors.
    """
    # Build comprehensive context from the graph
    context_lines = ["# Codebase Security Profile\n"]

    # Entry points
    entries = sg.get_entry_points()
    unrestricted = sg.get_unrestricted_entry_points()
    context_lines.append(f"Entry points: {len(entries)} total, {len(unrestricted)} unrestricted")

    # External calls
    ext_calls = sg.get_external_calls()
    user_controlled = sg.get_user_controlled_calls()
    context_lines.append(f"External calls: {len(ext_calls)} total, {len(user_controlled)} user-controlled")

    # Token flows
    token_flows = sg.get_token_flows()
    context_lines.append(f"Token flows: {len(token_flows)}")

    # Detected patterns
    flags = sg.metadata.get("global_flags", [])
    context_lines.append(f"Detected patterns: {', '.join(flags) if flags else 'none'}")

    # Protocol type
    protocol = sg.metadata.get("enrichment_data", {}).get("protocol_type", "unknown")
    context_lines.append(f"Protocol type: {protocol}")

    # Key functions summary
    context_lines.append("\n# Key Functions\n")
    for fn_id in unrestricted[:10]:
        data = sg.G.nodes.get(fn_id, {})
        writes = [sg.G.nodes.get(v, {}).get("name", v)
                  for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == WRITES]
        mods = data.get("modifiers", [])
        fn_flags = sg.get_flags_for(fn_id)
        context_lines.append(
            f"- {data.get('contract','')}.{data.get('name','')}() "
            f"[{data.get('visibility','')}] mods={mods or 'NONE'} "
            f"writes={writes[:3]} flags={fn_flags}"
        )

    # Invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Invariants")
        for inv in invariants[:6]:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)

    # Get source for highest-risk functions
    fn_ids: list[str] = []
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("mutability") in ("view", "pure"):
            continue
        contract_id = f"contract:{data.get('contract', '')}"
        cnode = sg.G.nodes.get(contract_id, {})
        if cnode.get("is_interface") or cnode.get("is_library"):
            continue
        fn_ids.append(fn_id)

    source = get_source_for_functions(sg, fn_ids[:15], max_chars=12000)

    system = f"""{SYSTEM_PROMPT_PREFIX}

{ATTACK_VECTORS}

For each INVESTIGATE classification, produce a finding with:
- The vector ID (V1-V40) that applies
- The exact function and line where the vulnerability exists
- A concrete attack scenario
- Evidence from the code

Report only INVESTIGATE vectors. Do NOT list SKIP or DROP classifications."""

    return call_hunter(
        hunter_name="VectorScanAgent",
        system_prompt=system,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )


SYSTEM_PROMPT_PREFIX = """You are an expert smart contract security auditor performing a SYSTEMATIC VECTOR SCAN.

Your approach: check EVERY attack vector in the catalog below against this codebase. For each vector:
1. Does the codebase use the relevant feature? If NO → SKIP
2. Is the feature properly guarded against this vector? If YES → DROP
3. Is the guard insufficient or missing? If YES → INVESTIGATE

For INVESTIGATE vectors, try to "break the guard" — find alternate paths around the protection.

When you find a bug via one vector, immediately check if the SAME pattern exists in other contracts/functions (cross-contract pattern weaponization)."""
