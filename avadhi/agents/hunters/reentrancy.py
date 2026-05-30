"""
avadhi/agents/hunters/reentrancy.py — Dedicated Reentrancy Hunter.

Hunts for:
  - Cross-function reentrancy (function A calls external, function B reads stale state)
  - Cross-contract reentrancy (callback to a different contract in the protocol)
  - Read-only reentrancy (view function returns stale data during external call)
  - CEI violations (checks-effects-interactions pattern not followed)
  - Missing or partial nonReentrant guards
  - ERC-777 / ERC-721 callback reentrancy (onERC721Received, tokensReceived)
"""
from __future__ import annotations

from avadhi.core.graph import (
    SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS,
    EXTERNAL_CALL, TOKEN_FLOW,
)
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in REENTRANCY vulnerabilities.

You are given a SecurityGraph view showing functions that make external calls alongside the state they read and write, plus their reentrancy guards. You also have the source code.

Your job is to find REAL reentrancy vulnerabilities:

1. **Classic CEI Violation**: A function makes an external call (transfer, .call, etc.)
   BEFORE updating its own state. An attacker re-enters the function and acts on stale state.
   - Check: does the function have `nonReentrant`? If yes, classic reentrancy is blocked.
   - Even with `nonReentrant`, cross-function reentrancy may still be possible.

2. **Cross-Function Reentrancy**: Function A makes an external call without updating state.
   The attacker's callback calls Function B which reads A's stale state.
   - `nonReentrant` on A blocks re-entering A, but NOT entering B.
   - Unless B also has `nonReentrant` and they share the same lock.
   - Key question: do A and B share a `nonReentrant` modifier from the same contract?

3. **Cross-Contract Reentrancy**: The protocol has multiple contracts. Contract X makes
   an external call. The callback enters Contract Y which reads state that X hasn't updated yet.
   - `nonReentrant` on X does NOT protect Y.

4. **Read-Only Reentrancy**: A view function reads state that is stale during an external
   call. If another protocol integrates and calls this view function during a callback,
   it gets incorrect data.

5. **ERC-721/ERC-777 Callback Reentrancy**: Token transfers that trigger callbacks
   (onERC721Received, tokensReceived, onERC1155Received) before the transfer's effects
   are finalized. The callback can re-enter and act on stale balances.

6. **Token Flow Before State Update**: Function does `token.transfer(user, amount)`
   before setting `balances[user] = 0`. The transfer triggers a callback where the user
   can call withdraw again.

For each finding:
- Identify the EXACT external call that enables re-entry
- Show the EXACT state variable(s) that are stale during the callback
- Name the EXACT function the attacker re-enters through
- Explain what the attacker gains from the stale state

DO NOT flag:
- Functions with `nonReentrant` for SAME-function reentrancy (that's protected)
- Internal calls (they don't transfer execution to untrusted code)
- Functions that only read state but never write (view/pure)
- Transfers to trusted addresses (e.g., protocol-owned contracts with known code)"""


def run_reentrancy_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for reentrancy vulnerabilities.

    Strategy:
      1. Find all functions that make external calls or token transfers
      2. For each, determine what state they write and whether writes happen
         before or after the external call (via line numbers)
      3. Check for nonReentrant modifier
      4. Find cross-function pairs: fn A has external call, fn B reads A's written vars
      5. Ask LLM with focused context
    """
    # Find functions with external calls
    ext_calls = sg.get_external_calls()
    token_flows = sg.get_token_flows()

    # Functions that make external calls
    ext_callers: set[str] = set()
    for caller_id, _, _ in ext_calls:
        ext_callers.add(caller_id)

    # Functions that do token transfers (potential callbacks)
    token_callers: set[str] = set()
    for caller_id, _, data in token_flows:
        flow = data.get("flow_type", "")
        if flow in ("transfer", "transferFrom", "safeTransfer", "safeTransferFrom"):
            token_callers.add(caller_id)

    all_callers = ext_callers | token_callers
    if not all_callers:
        if verbose:
            print("  ℹ️  ReentrancyHunter: No external calls or token transfers found")
        return []

    # For each caller, find what state it writes and reads
    caller_info: dict[str, dict] = {}
    for fn_id in all_callers:
        data = sg.G.nodes.get(fn_id, {})
        if not data:
            continue

        writes = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                  if d.get("type") == WRITES]
        reads = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                 if d.get("type") == READS]
        mods = data.get("modifiers", [])
        has_reentrancy_guard = any("reentrant" in m.lower() or "reentrancy" in m.lower()
                                   for m in mods)

        caller_info[fn_id] = {
            "writes": writes,
            "reads": reads,
            "has_guard": has_reentrancy_guard,
            "modifiers": mods,
            "contract": data.get("contract", ""),
            "name": data.get("name", ""),
        }

    # Find cross-function reentrancy candidates:
    # fn A makes external call and writes var X
    # fn B reads var X and has no shared reentrancy guard
    cross_fn_pairs: list[tuple[str, str, list[str]]] = []
    for fn_a, info_a in caller_info.items():
        if not info_a["writes"]:
            continue
        written_vars = set(info_a["writes"])

        # Find functions in same contract that read these vars
        for fn_b_id, fn_b_data in sg.get_nodes_by_type(FUNCTION):
            if fn_b_id == fn_a:
                continue
            if fn_b_data.get("contract") != info_a["contract"]:
                continue  # Different contract — that's cross-contract, handled separately
            if fn_b_data.get("visibility") not in ("external", "public"):
                continue

            b_reads = {v for _, v, d in sg.G.out_edges(fn_b_id, data=True)
                       if d.get("type") == READS}
            shared_vars = written_vars & b_reads
            if shared_vars:
                var_names = [sg.G.nodes.get(v, {}).get("name", v) for v in shared_vars]
                cross_fn_pairs.append((fn_a, fn_b_id, var_names))

    if verbose:
        print(f"   ReentrancyHunter: {len(all_callers)} functions with external calls, "
              f"{len(cross_fn_pairs)} cross-function pairs")

    # Build context
    context_lines = ["# Functions Making External Calls / Token Transfers\n"]
    for fn_id, info in caller_info.items():
        guard_str = "OK nonReentrant" if info["has_guard"] else "FAILED NO reentrancy guard"
        write_names = [sg.G.nodes.get(v, {}).get("name", v) for v in info["writes"]]
        read_names = [sg.G.nodes.get(v, {}).get("name", v) for v in info["reads"]]

        context_lines.append(
            f"- {info['contract']}.{info['name']}() [{guard_str}]"
        )
        if write_names:
            context_lines.append(f"  WRITES: {', '.join(write_names)}")
        if read_names:
            context_lines.append(f"  READS: {', '.join(read_names)}")

        # Show what external calls this function makes
        for caller, target, data in ext_calls:
            if caller == fn_id:
                tgt = sg.G.nodes.get(target, {})
                context_lines.append(
                    f"  EXTERNAL CALL: → {tgt.get('target', target)} "
                    f"[{data.get('call_type', '')}]"
                )
        for caller, target, data in token_flows:
            if caller == fn_id:
                context_lines.append(
                    f"  TOKEN FLOW: → {data.get('flow_type', '')} "
                    f"{sg.G.nodes.get(target, {}).get('name', target)}"
                )

    if cross_fn_pairs:
        context_lines.append("\n# Cross-Function Reentrancy Candidates")
        context_lines.append("# (Function A has external call + writes var, "
                             "Function B reads same var)")
        for fn_a, fn_b, var_names in cross_fn_pairs[:10]:
            a_info = caller_info[fn_a]
            b_data = sg.G.nodes.get(fn_b, {})
            b_mods = b_data.get("modifiers", [])
            context_lines.append(
                f"- {a_info['contract']}.{a_info['name']}() → "
                f"{b_data.get('contract','')}.{b_data.get('name','')}() "
                f"via: {', '.join(var_names)}"
            )
            context_lines.append(f"  B modifiers: {b_mods or 'NONE'}")

    context = "\n".join(context_lines)

    # Get source for external-calling functions + their cross-fn targets
    fn_ids = list(all_callers)
    for _, fn_b, _ in cross_fn_pairs[:5]:
        if fn_b not in fn_ids:
            fn_ids.append(fn_b)
    source = get_source_for_functions(sg, fn_ids[:15], max_chars=12000)

    return call_hunter(
        hunter_name="ReentrancyHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
