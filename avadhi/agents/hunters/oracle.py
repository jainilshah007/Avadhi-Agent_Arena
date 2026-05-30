"""
avadhi/agents/hunters/oracle.py — Oracle & Randomness Manipulation Hunter.

Hunts for:
  - Price oracle manipulation (spot price read without TWAP)
  - Single-source oracle dependence
  - Stale oracle data (no freshness check)
  - Randomness manipulation (commit-reveal issues, VRF abuse)
  - Admin ability to change oracle/entropy source mid-operation
  - Flash loan amplified oracle attacks
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS, EXTERNAL_CALL
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in ORACLE MANIPULATION and RANDOMNESS vulnerabilities.

You are given a SecurityGraph view showing functions that interact with external data sources (oracles, VRF, entropy providers) along with source code.

Your job is to find REAL oracle/randomness vulnerabilities:

1. **Oracle Manipulation**: Protocol reads a price/rate from an external source that can
   be manipulated within a single transaction.
   - Spot price reads from Uniswap/AMM pools (manipulable via flash loans)
   - Single-source oracle with no fallback
   - Missing staleness checks (no `require(block.timestamp - updatedAt < maxAge)`)
   - Missing min/max bounds on oracle values

2. **Randomness Manipulation**: The source of randomness can be predicted or influenced.
   - Using `block.timestamp`, `block.difficulty`, `blockhash` for randomness
   - Commit-reveal schemes where the reveal can be front-run
   - VRF where the operator can withhold unfavorable results
   - Entropy provider that can be changed mid-operation by admin

3. **Admin Can Change Data Source Mid-Operation**: Admin can swap the oracle address,
   entropy provider, or payout calculator while an operation (draw, settlement, auction)
   is in progress. This creates inconsistency between data used at start vs end.

4. **Flash Loan + Oracle**: An attacker borrows via flash loan, manipulates a pool's
   spot price, calls a protocol function that reads the manipulated price, then repays.
   The protocol acts on the wrong price.

5. **Callback Manipulation**: If the protocol uses an async callback pattern (e.g., VRF
   callback, Pyth entropy callback), an attacker may be able to:
   - Trigger the callback at a favorable time
   - Block the callback to freeze the protocol
   - Change protocol state between request and callback

For each finding:
- Identify the EXACT external data source being read
- Explain HOW an attacker manipulates it (flash loan amount, front-run timing, etc.)
- Describe the state change that occurs based on the manipulated data
- Quantify impact where possible

DO NOT flag:
- Protocols that correctly use Chainlink TWAP with staleness checks
- Randomness from properly configured VRF with adequate confirmations
- View/pure functions or interface contracts"""


def run_oracle_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for oracle/randomness vulnerabilities.

    Strategy:
      1. Find state variables related to oracles, entropy, randomness, VRF, price
      2. Find functions that read from or write to these variables
      3. Find external calls that might be oracle reads
      4. Find admin-settable addresses (oracle/entropy/calculator setters)
      5. Ask LLM with focused source code
    """
    oracle_keywords = {
        "oracle", "price", "feed", "twap", "chainlink", "pyth", "uniswap",
        "entropy", "random", "vrf", "seed", "nonce", "reveal", "commit",
        "callback", "request", "provider", "calculator", "resolver",
    }

    # Step 1: Find oracle/randomness state variables
    oracle_vars: list[str] = []
    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        var_name = data.get("name", "").lower()
        var_type = data.get("var_type", "").lower()
        if any(kw in var_name or kw in var_type for kw in oracle_keywords):
            oracle_vars.append(var_id)

    # Step 2: Find functions that interact with oracle vars
    oracle_fns: set[str] = set()
    for var_id in oracle_vars:
        oracle_fns.update(sg.get_writers(var_id))
        oracle_fns.update(sg.get_readers(var_id))

    # Step 3: Find functions with oracle-related names
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        if any(kw in fn_name for kw in oracle_keywords):
            oracle_fns.add(fn_id)

    # Step 4: Find functions that make external calls (potential oracle reads)
    ext_calls = sg.get_external_calls()
    for caller_id, _, _ in ext_calls:
        caller_data = sg.G.nodes.get(caller_id, {})
        fn_name = caller_data.get("name", "").lower()
        # Functions making external calls that also read price/oracle state
        reads = {sg.G.nodes.get(v, {}).get("name", "").lower()
                 for _, v, d in sg.G.out_edges(caller_id, data=True)
                 if d.get("type") == READS}
        if any(kw in r for r in reads for kw in oracle_keywords):
            oracle_fns.add(caller_id)

    # Step 5: Find admin setter functions for oracle/entropy addresses
    setter_fns: list[str] = []
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        if fn_name.startswith("set") and any(kw in fn_name for kw in
                                              ("oracle", "entropy", "provider",
                                               "calculator", "payout", "feed")):
            setter_fns.append(fn_id)
            oracle_fns.add(fn_id)

    if not oracle_fns:
        if verbose:
            print("  ℹ️  OracleHunter: No oracle/randomness interactions found")
        return []

    if verbose:
        print(f"   OracleHunter: {len(oracle_vars)} oracle vars, "
              f"{len(oracle_fns)} related functions, "
              f"{len(setter_fns)} admin setters")

    # Build context
    context_lines = ["# Oracle / Randomness State Variables\n"]
    for var_id in oracle_vars:
        data = sg.G.nodes.get(var_id, {})
        writers = sg.get_writers(var_id)
        writer_names = [sg.G.nodes.get(w, {}).get("name", w) for w in writers]
        context_lines.append(
            f"- {data.get('contract','')}.{data.get('name','')} "
            f"(type={data.get('var_type','?')}, "
            f"immutable={data.get('is_immutable', False)})"
        )
        context_lines.append(f"  WRITERS: {', '.join(writer_names) or 'NONE'}")

    if setter_fns:
        context_lines.append("\n# Admin Setter Functions (can change oracle/entropy)")
        for fn_id in setter_fns:
            data = sg.G.nodes.get(fn_id, {})
            mods = data.get("modifiers", [])
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"modifiers={mods or 'NONE'} "
                f"params=({data.get('params', '')})"
            )

    # Show functions that read oracle state and write protocol state
    context_lines.append("\n# Functions That Read Oracle Data AND Write State")
    for fn_id in oracle_fns:
        data = sg.G.nodes.get(fn_id, {})
        if data.get("mutability") in ("view", "pure"):
            continue
        reads = [sg.G.nodes.get(v, {}).get("name", "") for _, v, d in
                 sg.G.out_edges(fn_id, data=True) if d.get("type") == READS]
        writes = [sg.G.nodes.get(v, {}).get("name", "") for _, v, d in
                  sg.G.out_edges(fn_id, data=True) if d.get("type") == WRITES]
        oracle_reads = [r for r in reads if any(kw in r.lower() for kw in oracle_keywords)]
        if oracle_reads and writes:
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"READS oracle: {', '.join(oracle_reads)} → "
                f"WRITES: {', '.join(writes)}"
            )

    # Add enrichment invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Protocol Invariants")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)
    source = get_source_for_functions(sg, list(oracle_fns)[:15], max_chars=12000)

    return call_hunter(
        hunter_name="OracleHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
