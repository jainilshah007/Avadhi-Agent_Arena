"""
avadhi/agents/hunters/reasoning.py — Reasoning Agent (Feynman Method).

Inspired by Nemesis's Feynman Auditor: if you cannot explain WHY a line of
code exists, you don't understand it — and bugs hide where understanding
breaks down.

Also incorporates Pashov's First Principles Agent: "for every line, this
assumes X — break X." No named vulnerability classes.

This agent applies 7 question categories to every function, producing
SUSPECT/SOUND verdicts. It finds bugs by reasoning, not pattern matching.
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, WRITES, READS, EXTERNAL_CALL
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an elite smart contract security auditor using the FEYNMAN METHOD.

Your approach: if you cannot explain WHY a line of code exists and what invariant it protects, that line is SUSPECT. Bugs hide where understanding breaks down.

## Your 7 Question Categories

For every function you analyze, apply these questions:

### 1. PURPOSE — WHY is this here?
- Q1.1: What invariant does this line protect?
- Q1.2: What happens if I delete this line entirely?
- Q1.3: What attack motivated this check? Is the check sufficient for that attack?
- Q1.4: Does the check cover ALL variations of the attack, or just the obvious one?

### 2. ORDERING — WHAT IF I MOVE THIS?
- Q2.1: What if this check runs BEFORE the state write above it?
- Q2.2: What if the external call happens AFTER the state update?
- Q2.3: Is there a gap between the first write and the last read of the same variable?
- Q2.4: What if execution aborts halfway through this function?
- Q2.5: What if two users call this function in different orders?

### 3. CONSISTENCY — WHY does A have it but B doesn't?
- Q3.1: This function has a guard — do all functions writing the same state have it?
- Q3.2: This is a deposit() — does withdraw() check the exact inverse conditions?
- Q3.3: Parameter validation here — is the same validation applied everywhere this param is used?
- Q3.4: This emits an event — do all similar state changes emit events too?

### 4. ASSUMPTIONS — WHAT IS IMPLICITLY TRUSTED?
- Q4.1: What does this function assume about who calls it?
- Q4.2: What does it assume about external data it reads (oracle, callback, return value)?
- Q4.3: What does it assume about the current contract state?
- Q4.4: What does it assume about timing or ordering?
- Q4.5: What does it assume about token behavior (decimals, fees, rebasing)?

### 5. BOUNDARIES — WHAT BREAKS AT THE EDGES?
- Q5.1: What happens on the FIRST call when all state is zero/empty?
- Q5.2: What happens on the LAST call when resources are almost drained?
- Q5.3: What happens if called TWICE in the same block/transaction?
- Q5.4: What if two DIFFERENT functions are called in the same transaction?
- Q5.5: What if the contract itself is passed as a parameter (self-reference)?

### 6. RETURN & ERROR PATHS
- Q6.1: Is every return value from external calls consumed and checked?
- Q6.2: Does the error/revert path leave side effects (state partially updated)?
- Q6.3: Can an external call fail silently (low-level .call returning false)?

### 7. MASKING CODE — Is defensive code HIDING a bug?
Look for these 6 masking patterns:
- Ternary clamps: `x > max ? max : x` — WHY would x exceed max? That's the real bug.
- try/catch swallowing errors — WHAT error is being hidden?
- Early exit on zero: `if (amount == 0) return` — WHY would amount be zero here?
- Min caps: `Math.min(calculated, available)` — WHY would calculated exceed available?
- SafeMath without root cause — the overflow is a SYMPTOM, not the disease.
- Fallback to defaults — WHY would the primary value be invalid?

## How to Report

For each function, produce findings where you found SUSPECT lines.
Each finding must:
- State the EXACT assumption being made
- Explain HOW to break that assumption
- Give a concrete attack scenario with values
- Reference specific lines

DO NOT:
- Report named vulnerability classes (no "this is a reentrancy")
- Flag view/pure functions or interfaces
- Report admin-only functions doing admin things
- Report standard DeFi tradeoffs (slippage exists, yes)
- Flag functions with proper guards unless the guard is insufficient"""


def run_reasoning_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Run Feynman-method reasoning analysis on all state-changing functions.

    Prioritizes functions by complexity: more external calls, state writes,
    and missing guards = analyzed first.
    """
    # Collect all state-changing functions
    target_fns: list[tuple[str, float]] = []
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("mutability") in ("view", "pure"):
            continue
        contract_id = f"contract:{data.get('contract', '')}"
        contract_node = sg.G.nodes.get(contract_id, {})
        if contract_node.get("is_interface") or contract_node.get("is_library"):
            continue

        # Score by complexity
        score = 0.0
        for _, _, d in sg.G.out_edges(fn_id, data=True):
            edge_type = d.get("type", "")
            if edge_type == EXTERNAL_CALL:
                score += 3.0
            elif edge_type == WRITES:
                score += 2.0
        if not data.get("modifiers"):
            score += 2.0
        score += len(sg.get_flags_for(fn_id))

        if score > 0:
            target_fns.append((fn_id, score))

    if not target_fns:
        if verbose:
            print("  ReasoningAgent: No state-changing functions found")
        return []

    # Sort by score descending, take top functions
    target_fns.sort(key=lambda x: x[1], reverse=True)
    fn_ids = [fn_id for fn_id, _ in target_fns[:15]]

    if verbose:
        print(f"   ReasoningAgent: analyzing {len(fn_ids)} functions "
              f"(from {len(target_fns)} candidates)")

    # Build context: function details + state dependencies
    context_lines = ["# Functions Under Feynman Analysis\n"]
    for fn_id in fn_ids:
        data = sg.G.nodes[fn_id]
        writes = [sg.G.nodes.get(v, {}).get("name", v)
                  for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == WRITES]
        reads = [sg.G.nodes.get(v, {}).get("name", v)
                 for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == READS]
        ext_calls = [(sg.G.nodes.get(v, {}).get("target", v), d.get("call_type", ""))
                     for _, v, d in sg.G.out_edges(fn_id, data=True)
                     if d.get("type") == EXTERNAL_CALL]
        mods = data.get("modifiers", [])
        flags = sg.get_flags_for(fn_id)

        context_lines.append(
            f"## {data.get('contract','')}.{data.get('name','')}() "
            f"[{data.get('visibility', '')}]"
        )
        context_lines.append(f"  Modifiers: {mods or 'NONE'}")
        context_lines.append(f"  Params: ({data.get('params', '')})")
        if writes:
            context_lines.append(f"  WRITES: {', '.join(writes)}")
        if reads:
            context_lines.append(f"  READS: {', '.join(reads)}")
        if ext_calls:
            context_lines.append(f"  EXTERNAL CALLS: {', '.join(f'{t} [{ct}]' for t, ct in ext_calls)}")
        if flags:
            context_lines.append(f"  FLAGS: {', '.join(flags)}")
        context_lines.append("")

    # Add invariants if available
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("# Protocol Invariants (from enrichment)")
        for inv in invariants[:8]:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)
    source = get_source_for_functions(sg, fn_ids, max_chars=12000)

    return call_hunter(
        hunter_name="ReasoningAgent",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
