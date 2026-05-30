"""
avadhi/agents/hunters/defi_math.py — Dedicated Math, Rounding & Precision Hunter.

Hunts for:
  - ERC4626 Vault Inflation (rounding down vulnerable mints)
  - Division before multiplication precision loss
  - Missing slippage parameters (minOut) when routing assets
  - Integer overflow/underflow (in versions < 0.8.0, though mostly legacy)
  - Hardcoded AMM minimums that ignore decimals
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, WRITES, TOKEN_FLOW
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in DEFI MATH and PRECISION vulnerabilities.

You look for flaws in how protocols calculate shares, swap tokens, or distribute yield.

Your job is to find REAL math vulnerabilities:

1. **ERC-4626 Vault Inflation (Rounding Down to 0):**
   If a vault calculates shares to mint as `shares = (assets * totalShares) / totalAssets`, the first depositor can mint 1 wei of a share, then directly transfer huge amounts of assets to the vault (inflating `totalAssets` massively without minting shares). Subsequent depositors requesting shares will have their mathematical equation evaluate to 0 (rounding down in Solidity), effectively stealing their deposit.
   - Look for: Missing `require(shares != 0)` or missing dead-share minting (`_mint(address(0), 10**3)`).

2. **Division Before Multiplication:**
   Solidity does not support floating point math. If the protocol calculates `a / b * c` rather than `(a * c) / b`, massive precision is lost. This is extremely common in staking reward distributions.

3. **Slippage / Sandwich Attacks (Missing minAmountOut):**
   When swapping assets through an AMM, if the contract uses a hardcoded `minAmountOut = 0` or uses the current instantaneously queried pool price, MEV bots can sandwich the transaction, causing massive slippage losses.
   - Look for: Functions taking token inputs for swaps but failing to accept a user-supplied parameter for the minimum acceptable return.

4. **Fee-on-Transfer Mismatches:**
   If a protocol calculates `amount = reqAmount` and does `token.transferFrom(user, here, reqAmount)`, but the token is a fee-on-transfer token, the protocol actually receives LESS than `reqAmount`. Any subsequent accounting based on `reqAmount` is functionally insolvent.

For each finding:
- Identify the exact mathematical expression or swap function.
- Explain the manipulation edge-case.
- Provide a concrete numerical walk-through of the exploit.

DO NOT flag standard logic if checks exist. DO NOT flag basic multiplications where no precision loss occurs.
"""

def run_defi_math_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for DeFi math and rounding vulnerabilities.
    """
    # 1. Look for vault-like functions (deposit, mint, swap, claim, stake)
    # 2. Look for functions doing token math
    target_fns: list[str] = []
    
    token_flows = sg.get_token_flows()
    token_fns = {caller for caller, _, _ in token_flows}
    
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        name = data.get("name", "").lower()
        if any(keyword in name for keyword in ["mint", "deposit", "withdraw", "redeem", "swap", "stake", "claim", "reward", "fee"]):
            target_fns.append(fn_id)
            continue
            
        if fn_id in token_fns:
            target_fns.append(fn_id)

    if not target_fns:
        if verbose:
            print("  ℹ️  DefiMathHunter: No vault or math-heavy token algorithms detected.")
        return []

    # Build context
    context_lines = ["# Functions Utilizing Heavy Math / Shares / Token Swaps\n"]
    for fn_id in target_fns:
        data = sg.G.nodes.get(fn_id, {})
        context_lines.append(f"- Contract: {data.get('contract', 'Unknown')}")
        context_lines.append(f"  Function: {data.get('name', fn_id)}")
        
        # Check what state it reads/writes related to math (like totalShares, totalAssets)
        writes = [sg.G.nodes.get(v, {}).get("name", v) for _, v, d in sg.G.out_edges(fn_id, data=True) if d.get("type") == WRITES]
        if writes:
            context_lines.append(f"  Writes: {', '.join(writes)}")
        context_lines.append("  --")
        
    context = "\n".join(context_lines)

    if verbose:
        print(f"   DefiMathHunter: Analyzing {len(target_fns)} math-related endpoints")

    source = get_source_for_functions(sg, target_fns, max_chars=12000)

    return call_hunter(
        hunter_name="DefiMathHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
