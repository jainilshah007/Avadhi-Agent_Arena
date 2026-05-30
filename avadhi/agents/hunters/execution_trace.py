"""
avadhi/agents/hunters/execution_trace.py — Execution Trace Agent.

Inspired by Pashov's Execution Trace Agent and Plamen's depth-state-trace:
trace parameter flow from entry to final state change, both within a single
transaction and across multiple transactions.

This agent doesn't look for named vulnerability patterns. It traces how data
flows through the protocol and finds where assumptions break.
"""
from __future__ import annotations

from avadhi.core.graph import (
    SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS,
    EXTERNAL_CALL, CALLS,
)
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an elite smart contract security auditor specializing in EXECUTION TRACE ANALYSIS.

Your approach: trace how parameters flow from function entry to final state change. Find where data transforms break assumptions.

## Within a Single Transaction

### Parameter Divergence
Trace every external parameter through ALL code paths:
- Does the parameter reach the state write unchanged?
- Is it transformed (cast, scaled, combined)? Is the transform reversible?
- Can two different parameter values produce the same state change? (collision)
- Can the same parameter value produce different state changes? (non-determinism)

### Value Leaks
- Is value created or destroyed during the flow? (rounding, fees, rebasing)
- After a round-trip (deposit then withdraw), does the user get back exactly what they put in?
- Are intermediate values stored in state? Can they be observed and exploited?

### Encoding/Decoding Mismatches
- abi.encode vs abi.encodePacked (hash collision risk)
- Packed structs: is field ordering consistent between encode and decode?
- Cross-chain messages: is the message format identical on both sides?

### Stale Reads
- Is state read at the top of a function but used at the bottom after an external call?
- Is a storage value cached in memory, then the storage is modified, then the cache is used?
- Is a return value from an external call used after another external call?

## Across Multiple Transactions

### Wrong-State Execution
- Can a function be called in a state it wasn't designed for?
- State machine: can transitions be skipped? (A→C without B)
- Timing: can a function be called before initialization or after finalization?

### Operation Interleaving
- What if user A calls deposit() between user B's two-step operation?
- Can a governance proposal be executed while a migration is in progress?
- Can approve + transferFrom be interleaved with another approve?

### Accumulated State Corruption
- After 1000 operations, do rounding errors accumulate significantly?
- Does a counter/nonce ever reset or wrap around?
- Do mapping entries grow without bound? (storage DoS)

### Config Mutation During Operation
- Can admin change a parameter (fee rate, oracle address, deadline) while a user's multi-step operation is in progress?
- Does the config change retroactively affect pending operations?

## Your Process
1. For each entry point (public/external function):
   - Trace all parameters through every branch
   - Mark where external calls happen (state might be stale after)
   - Mark where state writes happen (ordering matters)
2. For cross-function traces:
   - Find pairs of functions that share state
   - Check if interleaving calls creates inconsistencies
3. Report any trace where an assumption about data integrity breaks

DO NOT:
- Report view/pure functions or interfaces
- Report admin functions unless config change during operation is the issue
- Report standard reentrancy (that's the Reasoning agent's job)
- Flag functions with proper CEI pattern and reentrancy guards"""


def run_execution_trace_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Trace execution flow through the protocol.
    """
    # Find functions with complex execution paths:
    # - Functions that call other functions (call chains)
    # - Functions that make external calls
    # - Functions involved in multi-step operations
    trace_fns: list[tuple[str, float]] = []

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("mutability") in ("view", "pure"):
            continue
        contract_id = f"contract:{data.get('contract', '')}"
        cnode = sg.G.nodes.get(contract_id, {})
        if cnode.get("is_interface") or cnode.get("is_library"):
            continue

        score = 0.0
        internal_calls = []
        ext_calls_list = []

        for _, target, edge_data in sg.G.out_edges(fn_id, data=True):
            edge_type = edge_data.get("type", "")
            if edge_type == CALLS:
                internal_calls.append(target)
                score += 1.0
            elif edge_type == EXTERNAL_CALL:
                ext_calls_list.append(target)
                score += 3.0
            elif edge_type == WRITES:
                score += 1.0

        # Functions with both internal calls and state writes are interesting
        if internal_calls:
            score += 2.0
        if ext_calls_list:
            score += 2.0

        flags = sg.get_flags_for(fn_id)
        trace_flags = {"PROXY_UPGRADEABLE", "CROSS_CHAIN", "CALLBACK", "TEMPORAL",
                       "HAS_SIGNATURES", "MIGRATION", "LOW_LEVEL_CALL"}
        if set(flags) & trace_flags:
            score += 3.0

        if score > 0:
            trace_fns.append((fn_id, score))

    if not trace_fns:
        if verbose:
            print("  ExecutionTraceAgent: No complex execution paths found")
        return []

    trace_fns.sort(key=lambda x: x[1], reverse=True)
    fn_ids = [fn_id for fn_id, _ in trace_fns[:15]]

    if verbose:
        print(f"   ExecutionTraceAgent: tracing {len(fn_ids)} functions")

    # Build call chain context
    context_lines = ["# Execution Trace Targets\n"]

    for fn_id in fn_ids:
        data = sg.G.nodes[fn_id]
        context_lines.append(
            f"## {data.get('contract','')}.{data.get('name','')}() "
            f"[{data.get('visibility','')}]"
        )
        context_lines.append(f"  Params: ({data.get('params', '')})")
        context_lines.append(f"  Modifiers: {data.get('modifiers', []) or 'NONE'}")

        # Call chain
        calls = []
        ext_targets = []
        writes_list = []
        reads_list = []

        for _, target, edge_data in sg.G.out_edges(fn_id, data=True):
            t = edge_data.get("type", "")
            target_data = sg.G.nodes.get(target, {})
            if t == CALLS:
                calls.append(f"{target_data.get('contract','')}.{target_data.get('name','')}")
            elif t == EXTERNAL_CALL:
                ext_targets.append(target_data.get("target", target))
            elif t == WRITES:
                writes_list.append(target_data.get("name", target))
            elif t == READS:
                reads_list.append(target_data.get("name", target))

        if calls:
            context_lines.append(f"  CALLS: {' → '.join(calls)}")
        if ext_targets:
            context_lines.append(f"  EXTERNAL: {', '.join(ext_targets)}")
        if reads_list:
            context_lines.append(f"  READS: {', '.join(reads_list)}")
        if writes_list:
            context_lines.append(f"  WRITES: {', '.join(writes_list)}")

        flags = sg.get_flags_for(fn_id)
        if flags:
            context_lines.append(f"  FLAGS: {', '.join(flags)}")
        context_lines.append("")

    # Cross-function state sharing (for interleaving analysis)
    context_lines.append("# Cross-Function State Sharing")
    context_lines.append("# (Functions that read state written by another function)\n")

    shared_count = 0
    for fn_a in fn_ids[:8]:
        a_writes = {v for _, v, d in sg.G.out_edges(fn_a, data=True) if d.get("type") == WRITES}
        if not a_writes:
            continue
        for fn_b, b_data in sg.get_nodes_by_type(FUNCTION):
            if fn_b == fn_a:
                continue
            if b_data.get("visibility") not in ("external", "public"):
                continue
            b_reads = {v for _, v, d in sg.G.out_edges(fn_b, data=True) if d.get("type") == READS}
            shared = a_writes & b_reads
            if shared:
                var_names = [sg.G.nodes.get(v, {}).get("name", v) for v in shared]
                a_data = sg.G.nodes.get(fn_a, {})
                context_lines.append(
                    f"- {a_data.get('contract','')}.{a_data.get('name','')}() WRITES → "
                    f"{b_data.get('contract','')}.{b_data.get('name','')}() READS: "
                    f"{', '.join(var_names[:3])}"
                )
                shared_count += 1
                if shared_count > 15:
                    break
        if shared_count > 15:
            break

    context = "\n".join(context_lines)

    # Include source for call chain targets too
    all_fn_ids = list(fn_ids)
    for fn_id in fn_ids[:5]:
        for _, target, d in sg.G.out_edges(fn_id, data=True):
            if d.get("type") == CALLS and target not in all_fn_ids:
                all_fn_ids.append(target)

    source = get_source_for_functions(sg, all_fn_ids[:15], max_chars=12000)

    return call_hunter(
        hunter_name="ExecutionTraceAgent",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
