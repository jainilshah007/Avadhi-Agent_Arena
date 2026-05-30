"""
avadhi/agents/hunters/periphery.py — Periphery Agent.

Inspired by Pashov's Periphery Agent: targets the OVERLOOKED code.

Libraries, helpers, utility contracts, base contracts — the code that nobody
audits carefully because it looks "boring." But these are where the sneaky
bugs hide: unvalidated inputs, corrupt return values, hidden state side
effects, assembly byte-width bugs.

Only activated when the codebase has >= 5 contracts (otherwise everything
is "core" and the other agents cover it).
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an elite smart contract security auditor specializing in PERIPHERY CODE.

Your targets: libraries, helpers, utility functions, base contracts, encoders/decoders — the code that other auditors skip because it looks mundane. This is where the sneaky bugs hide.

## Priority Order
Analyze the SMALLEST contracts first. A 30-line library with a subtle bug affects every contract that imports it.

## What to Look For

### 1. Unvalidated Inputs in Libraries
- Library functions that don't validate inputs because "the caller will validate"
- But different callers validate differently (or not at all)
- Math libraries with unchecked edge cases (division by zero, overflow at boundaries)

### 2. Corrupt Return Values
- Functions that return stale data after a state change
- Functions that return a success bool that callers ignore
- Encoding functions that truncate or pad data incorrectly

### 3. Hidden State Side Effects
- "Pure" functions that actually read state through inline assembly
- Functions that modify state in a way callers don't expect
- Storage vs memory confusion in struct handling

### 4. Assembly & Low-Level Bugs
- Byte-width mismatches (bytes32 vs bytes20 for addresses)
- Memory pointer corruption in assembly blocks
- Missing overflow checks in unchecked{} blocks
- Incorrect returndata handling after external calls

### 5. Base Contract Vulnerabilities
- Initializer functions in base contracts that can be called by inheritors
- Virtual functions with incorrect default implementations
- Storage layout conflicts between base and derived contracts
- Constructor vs initializer inconsistencies

### 6. Cross-Contract Interface Mismatches
- Contract A calls B with different parameter types than B expects
- Enum values that don't match between contracts
- Event definitions that differ between interface and implementation

## Your Process
1. Start with the smallest contracts (by function count)
2. Read EVERY function in each contract
3. For each function, ask: "If a caller passes unexpected input, what happens?"
4. Trace how this function's output is used by callers
5. Check if the function's assumptions match what callers actually guarantee

DO NOT:
- Analyze the main protocol contracts (other agents handle those)
- Report standard library code from OpenZeppelin (unless used incorrectly)
- Report view/pure functions that genuinely have no side effects
- Report missing NatSpec or style issues"""


def run_periphery_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Analyze peripheral contracts: libraries, helpers, base contracts.
    """
    # Classify contracts by size and type
    contracts: list[tuple[str, dict, int]] = []
    for node_id, data in sg.G.nodes(data=True):
        if data.get("type") != "Contract":
            continue
        if data.get("is_interface"):
            continue

        # Count functions in this contract
        fn_count = sum(
            1 for fn_id, fn_data in sg.get_nodes_by_type(FUNCTION)
            if fn_data.get("contract") == data.get("name")
        )
        contracts.append((node_id, data, fn_count))

    if not contracts:
        if verbose:
            print("  PeripheryAgent: No contracts found")
        return []

    # Sort by function count (smallest first — that's the periphery)
    contracts.sort(key=lambda x: x[2])

    # Identify periphery: libraries, small contracts, contracts with "helper/util/lib" in name
    periphery_fns: list[str] = []
    periphery_names: list[str] = []

    for node_id, data, fn_count in contracts:
        name = data.get("name", "").lower()
        is_library = data.get("is_library", False)
        is_peripheral = (
            is_library
            or fn_count <= 5
            or any(kw in name for kw in ("helper", "util", "lib", "math", "safe",
                                          "base", "abstract", "common", "shared",
                                          "encoder", "decoder", "converter"))
        )

        if is_peripheral:
            periphery_names.append(data.get("name", ""))
            # Get all functions in this contract
            for fn_id, fn_data in sg.get_nodes_by_type(FUNCTION):
                if fn_data.get("contract") == data.get("name"):
                    periphery_fns.append(fn_id)

    if not periphery_fns:
        # Fallback: take the smallest half of contracts as periphery
        half = max(1, len(contracts) // 2)
        for node_id, data, fn_count in contracts[:half]:
            periphery_names.append(data.get("name", ""))
            for fn_id, fn_data in sg.get_nodes_by_type(FUNCTION):
                if fn_data.get("contract") == data.get("name"):
                    periphery_fns.append(fn_id)

    if not periphery_fns:
        if verbose:
            print("  PeripheryAgent: No peripheral functions found")
        return []

    if verbose:
        print(f"   PeripheryAgent: {len(periphery_fns)} functions in "
              f"{len(periphery_names)} peripheral contracts: {', '.join(periphery_names[:5])}")

    # Build context
    context_lines = [f"# Peripheral Contracts ({len(periphery_names)} contracts)\n"]

    for name in periphery_names:
        # Find all functions in this contract and their callers
        context_lines.append(f"\n## {name}")
        for fn_id, fn_data in sg.get_nodes_by_type(FUNCTION):
            if fn_data.get("contract") != name:
                continue
            # Who calls this function?
            callers = [
                sg.G.nodes.get(u, {}).get("name", u)
                for u, _, d in sg.G.in_edges(fn_id, data=True)
                if d.get("type") == CALLS
            ]
            writes = [sg.G.nodes.get(v, {}).get("name", v)
                      for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == WRITES]

            context_lines.append(
                f"  - {fn_data.get('name','')}() "
                f"[{fn_data.get('visibility','')}] "
                f"params=({fn_data.get('params', '')})"
            )
            if callers:
                context_lines.append(f"    Called by: {', '.join(callers[:5])}")
            if writes:
                context_lines.append(f"    WRITES: {', '.join(writes[:3])}")

    context = "\n".join(context_lines)
    source = get_source_for_functions(sg, periphery_fns[:15], max_chars=12000)

    return call_hunter(
        hunter_name="PeripheryAgent",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
