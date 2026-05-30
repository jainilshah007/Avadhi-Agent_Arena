"""
avadhi/agents/hunters/economic.py — Economic Security Agent.

Consolidates the old Oracle, DefiMath, FeeAccounting, and Accounting hunters
into a single broad economic agent.

Inspired by Pashov's Economic Security Agent: "You have unlimited capital and
flash loans. Exploit external dependencies, value flows, and economic incentives."

Also incorporates Plamen's depth-token-flow and depth-edge-case methodologies.
"""
from __future__ import annotations

from avadhi.core.graph import (
    SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS,
    EXTERNAL_CALL, TOKEN_FLOW,
)
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an elite smart contract security auditor specializing in ECONOMIC SECURITY.

You have UNLIMITED CAPITAL and FLASH LOANS. Your goal is to extract value from or break this protocol through economic means.

## Your Attack Domains

### 1. Oracle & Price Manipulation
- Spot price reads from AMM pools (manipulable via flash loans)
- Single-source oracle with no fallback
- Missing staleness checks on oracle data
- Missing min/max bounds on oracle values
- Admin can change oracle address mid-operation
- Flash loan → manipulate pool price → call protocol → repay

### 2. Token Misbehavior
- Fee-on-transfer tokens: amount received < amount sent
- Rebasing tokens: balance changes without transfer
- ERC-777 hooks: callback during transfer enables reentrancy
- Tokens with blacklists: transfer reverts, causing DoS
- Tokens with >18 or <6 decimals: precision mismatches
- Return value quirks: some tokens don't return bool on transfer

### 3. Accounting & Math
- Division before multiplication (precision loss)
- Rounding direction favoring user over protocol
- Zero-amount exploits (bypass checks, trigger state changes)
- Share price inflation (first depositor attack)
- Overflow in intermediate calculations
- Mixed decimal operations without normalization
- Fee calculation: fees deducted before or after amount check?

### 4. Value Flow Extraction
- Donation attacks: direct transfer breaks internal accounting
- Sandwich attacks: front-run + back-run user transactions
- Flash loan precondition manipulation: borrow → set up conditions → exploit → repay
- MEV extraction: profitable reordering of pending transactions
- Liquidation manipulation: trigger liquidation of healthy position

### 5. Balance Invariant Breaking
- totalSupply != sum(balances) after a sequence of operations
- Stranded assets: tokens stuck with no withdrawal path
- Reward distribution: claimed > distributed when accumulated over time
- Share/asset exchange rate manipulation

### 6. Boundary Conditions
- Zero-state: what happens on first deposit/withdrawal?
- Depletion: what happens when pool is nearly empty?
- Maximum: what happens at uint256 max values?
- Exchange rate: what happens at extreme rates (1:10^18)?
- Time: what happens at epoch boundaries?

## Methodology
For each function that handles value:
1. Map the COMPLETE value flow (where does money come from, where does it go?)
2. Check every arithmetic operation for precision loss
3. Check every token interaction for quirky token behavior
4. Check if flash loans can manipulate preconditions
5. Substitute REAL numbers — don't just say "precision loss", show: input=X, expected=Y, actual=Z

DO NOT:
- Report admin-only functions doing admin things
- Report standard slippage in AMMs (that's by design)
- Report theoretical precision loss < 1 wei
- Report self-harm-only bugs (user can only hurt themselves)
- Flag view/pure functions or interfaces"""


def run_economic_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Run economic security analysis on value-handling functions.
    """
    # Collect all functions involved in value handling
    value_fns: set[str] = set()

    # Functions with token flows
    for caller_id, _, _ in sg.get_token_flows():
        value_fns.add(caller_id)

    # Functions with external calls (potential value transfer)
    for caller_id, _, d in sg.get_external_calls():
        if d.get("value_sent") or d.get("call_type") in ("call", "delegatecall"):
            value_fns.add(caller_id)

    # Functions that write to oracle/price/balance-related state
    oracle_keywords = {
        "oracle", "price", "rate", "balance", "supply", "total", "reserve",
        "share", "asset", "debt", "collateral", "fee", "reward", "stake",
        "deposit", "withdraw", "amount", "value",
    }
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("mutability") in ("view", "pure"):
            continue
        fn_name = data.get("name", "").lower()
        if any(kw in fn_name for kw in oracle_keywords):
            value_fns.add(fn_id)

    # Functions that read/write flagged state variables
    for fn_id in list(value_fns):
        for _, v, d in sg.G.out_edges(fn_id, data=True):
            if d.get("type") in (READS, WRITES):
                var_data = sg.G.nodes.get(v, {})
                var_name = var_data.get("name", "").lower()
                if any(kw in var_name for kw in oracle_keywords):
                    # Also include functions that interact with this var
                    for reader_id in sg.get_readers(v):
                        value_fns.add(reader_id)
                    for writer_id in sg.get_writers(v):
                        value_fns.add(writer_id)

    # Filter out interfaces/libraries
    filtered_fns: list[str] = []
    for fn_id in value_fns:
        data = sg.G.nodes.get(fn_id, {})
        if data.get("mutability") in ("view", "pure"):
            continue
        contract_id = f"contract:{data.get('contract', '')}"
        cnode = sg.G.nodes.get(contract_id, {})
        if cnode.get("is_interface") or cnode.get("is_library"):
            continue
        filtered_fns.append(fn_id)

    if not filtered_fns:
        if verbose:
            print("  EconomicAgent: No value-handling functions found")
        return []

    if verbose:
        print(f"   EconomicAgent: {len(filtered_fns)} value-handling functions")

    # Build context
    context_lines = ["# Value-Handling Functions\n"]

    # Token flows
    token_flows = sg.get_token_flows()
    if token_flows:
        context_lines.append("## Token Flows")
        for u, v, d in token_flows:
            src = sg.G.nodes.get(u, {})
            token = sg.G.nodes.get(v, {}).get("name", v)
            context_lines.append(
                f"- {src.get('contract','')}.{src.get('name','')}() "
                f"→ {d.get('flow_type', '')} {token}"
            )

    # Oracle-related state
    context_lines.append("\n## State Variables Involved in Value Calculations")
    for fn_id in filtered_fns[:10]:
        data = sg.G.nodes.get(fn_id, {})
        writes = [sg.G.nodes.get(v, {}).get("name", v)
                  for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == WRITES]
        reads = [sg.G.nodes.get(v, {}).get("name", v)
                 for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == READS]
        if writes or reads:
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"reads=[{', '.join(reads[:4])}] writes=[{', '.join(writes[:4])}]"
            )

    # Detected flags
    flags = sg.metadata.get("global_flags", [])
    economic_flags = [f for f in flags if f in (
        "ORACLE", "FLASH_LOAN", "DEX_INTERACTION", "LENDING", "BALANCE_DEPENDENT",
        "STAKING", "ERC4626", "MIXED_DECIMALS", "SHARE_ALLOCATION", "LOTTERY",
    )]
    if economic_flags:
        context_lines.append(f"\n## Economic Flags Detected: {', '.join(economic_flags)}")

    # Invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n## Protocol Invariants")
        for inv in invariants[:8]:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)
    source = get_source_for_functions(sg, filtered_fns[:15], max_chars=12000)

    return call_hunter(
        hunter_name="EconomicAgent",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        vulnerability_type="economic",
        sg=sg,
    )
