"""
avadhi/agents/hunters/structural.py — Structural Agent (State Coupling Analysis).

Inspired by Nemesis's State Inconsistency Auditor:
  Every system has COUPLED STATE PAIRS — two or more storage values that must
  maintain a relationship. When any operation changes one side without adjusting
  the other, the invariant breaks.

This agent leverages the SecurityGraph's READS/WRITES edges to systematically
build a mutation matrix and find inconsistencies.
"""
from __future__ import annotations

from collections import defaultdict

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an elite smart contract security auditor specializing in STATE COUPLING ANALYSIS.

Your core insight: every protocol has COUPLED STATE PAIRS — storage variables that MUST maintain a relationship. When any operation changes one side without adjusting the other, the invariant breaks.

## Your 5 Rules

RULE 1: MAP BEFORE YOU HUNT — identify all coupled state pairs first.
Examples of coupled pairs:
- totalSupply <-> sum(balances[*])
- totalDeposited <-> sum(userDeposits[*])
- rewardRate <-> rewardPerToken (must update together)
- shares[user] <-> totalShares (must be consistent)

RULE 2: EVERY MUTATION PATH MATTERS — if 4 of 5 functions update BOTH sides
of a coupled pair, the 5th function is the bug. Look at the Mutation Matrix
provided and find the GAPS.

RULE 3: PARTIAL OPERATIONS ARE THE #1 SOURCE — partial reductions (early returns,
reverts after partial state update, try/catch swallowing) frequently forget
coupled state.

RULE 4: COMPARE PARALLEL PATHS — transfer() and burn() both reduce balance.
Do they BOTH update totalSupply? Do they BOTH update reward tracking?

RULE 5: DEFENSIVE CODE MASKS BUGS — look for these 6 masking patterns:
1. Ternary clamps: `x > max ? max : x` — WHY would x exceed max?
2. try/catch swallowing errors silently
3. Early exit on zero: `if (amount == 0) return` — WHY would amount be zero?
4. Min caps: `Math.min(calculated, available)` — WHY would calculated exceed available?
5. SafeMath without root-cause fix
6. Fallback to default values

## Your Analysis Process

1. Read the Mutation Matrix (which functions write which variables)
2. Identify coupled state pairs (variables that MUST stay in sync)
3. For each coupled pair, check: does EVERY function that writes to side A
   also write to side B?
4. Report any function that writes to one side but NOT the other
5. Check ordering: within functions that write both sides, is the order correct?
   (does A get updated before B is read?)
6. Trace multi-step user journeys: deposit→stake→claim→withdraw —
   does accumulated state stay consistent?

## Output Requirements

For each finding:
- Name the EXACT coupled pair that is broken
- Name the EXACT function that fails to update both sides
- Show the other functions that DO update both sides (proving the coupling)
- Describe the concrete state desynchronization
- Give a step-by-step exploit that profits from the desync

DO NOT:
- Report functions that intentionally only update one side (e.g., admin override)
- Report view/pure functions
- Report interface contracts"""


def _build_mutation_matrix(sg: SecurityGraph) -> str:
    """
    Build a Function-State Mutation Matrix from the SecurityGraph.

    Format:
      Variable        | Writers                  | Readers
      totalSupply     | mint(), burn()           | balanceOf(), transfer()
      balances        | mint(), burn(), transfer()| balanceOf()
    """
    var_writers: dict[str, list[str]] = defaultdict(list)
    var_readers: dict[str, list[str]] = defaultdict(list)

    for fn_id, fn_data in sg.get_nodes_by_type(FUNCTION):
        fn_label = f"{fn_data.get('contract', '')}.{fn_data.get('name', '')}()"
        for _, target, edge_data in sg.G.out_edges(fn_id, data=True):
            target_node = sg.G.nodes.get(target, {})
            if target_node.get("type") != STATE_VAR:
                continue
            var_name = f"{target_node.get('contract', '')}.{target_node.get('name', '')}"
            if edge_data.get("type") == WRITES:
                var_writers[var_name].append(fn_label)
            elif edge_data.get("type") == READS:
                var_readers[var_name].append(fn_label)

    if not var_writers:
        return "(no state mutations detected)"

    lines = ["| Variable | Writers | Readers |", "|---|---|---|"]
    for var_name in sorted(var_writers.keys()):
        writers = ", ".join(var_writers[var_name][:6])
        readers = ", ".join(var_readers.get(var_name, [])[:6])
        lines.append(f"| {var_name} | {writers} | {readers} |")

    return "\n".join(lines)


def _find_co_written_pairs(sg: SecurityGraph) -> list[tuple[str, str, list[str], list[str]]]:
    """
    Find state variable pairs that are frequently written together.

    Returns: [(var_a, var_b, functions_writing_both, functions_writing_only_one)]

    If most functions write both A and B, but one writes only A, that one is
    likely a bug (Rule 2: every mutation path matters).
    """
    # Map each function to the set of state vars it writes
    fn_writes: dict[str, set[str]] = defaultdict(set)
    for fn_id, fn_data in sg.get_nodes_by_type(FUNCTION):
        fn_label = f"{fn_data.get('contract', '')}.{fn_data.get('name', '')}()"
        for _, target, edge_data in sg.G.out_edges(fn_id, data=True):
            if edge_data.get("type") == WRITES:
                target_node = sg.G.nodes.get(target, {})
                if target_node.get("type") == STATE_VAR:
                    var_name = f"{target_node.get('contract', '')}.{target_node.get('name', '')}"
                    fn_writes[fn_label].add(var_name)

    # Find all pairs of vars that are co-written by at least 2 functions
    from itertools import combinations
    all_vars = set()
    for vars_set in fn_writes.values():
        all_vars.update(vars_set)

    co_write_pairs: list[tuple[str, str, list[str], list[str]]] = []

    for var_a, var_b in combinations(sorted(all_vars), 2):
        writes_both: list[str] = []
        writes_only_one: list[str] = []

        for fn, vars_written in fn_writes.items():
            a_written = var_a in vars_written
            b_written = var_b in vars_written
            if a_written and b_written:
                writes_both.append(fn)
            elif a_written or b_written:
                writes_only_one.append(fn)

        # Interesting if at least 1 function writes both AND at least 1 writes only one
        if len(writes_both) >= 1 and writes_only_one:
            co_write_pairs.append((var_a, var_b, writes_both, writes_only_one))

    # Sort by gap count (most suspicious first)
    co_write_pairs.sort(key=lambda x: len(x[3]), reverse=True)
    return co_write_pairs[:10]


def run_structural_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Run state coupling analysis using the SecurityGraph's mutation data.
    """
    # Build mutation matrix
    matrix = _build_mutation_matrix(sg)

    # Find co-written pairs with gaps
    co_write_pairs = _find_co_written_pairs(sg)

    if verbose:
        print(f"   StructuralAgent: {len(co_write_pairs)} co-written pairs with gaps detected")

    # Build context
    context_lines = ["# State Variable Mutation Matrix\n", matrix, ""]

    if co_write_pairs:
        context_lines.append("# Coupled State Pairs — Gap Analysis")
        context_lines.append("# (Pairs where MOST functions write both, but SOME write only one)\n")
        for var_a, var_b, both, only_one in co_write_pairs:
            context_lines.append(f"## Coupled Pair: {var_a} <-> {var_b}")
            context_lines.append(f"  Functions writing BOTH: {', '.join(both)}")
            context_lines.append(f"  Functions writing ONLY ONE (SUSPECT): {', '.join(only_one)}")
            context_lines.append("")

    # Add enrichment invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("# Protocol Invariants")
        for inv in invariants[:8]:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)

    # Get source for all functions involved in gaps
    fn_ids_to_show: list[str] = []
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("mutability") in ("view", "pure"):
            continue
        contract_id = f"contract:{data.get('contract', '')}"
        contract_node = sg.G.nodes.get(contract_id, {})
        if contract_node.get("is_interface") or contract_node.get("is_library"):
            continue
        # Check if this function writes state
        has_writes = any(d.get("type") == WRITES for _, _, d in sg.G.out_edges(fn_id, data=True))
        if has_writes:
            fn_ids_to_show.append(fn_id)

    source = get_source_for_functions(sg, fn_ids_to_show[:15], max_chars=12000)

    return call_hunter(
        hunter_name="StructuralAgent",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
