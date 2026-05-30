"""
avadhi/agents/hunters/integration.py — External Protocol Integration Hunter.

Hunts for DeFi composability risks arising from interactions with external
protocols via their interface contracts (IPool, IStETH, IERC20, etc.).

Common issues caught:
  - Rebasing/fee-on-transfer tokens used as if they are standard ERC-20
  - Unchecked return values from external protocol calls (Aave, Uniswap, etc.)
  - Precision loss in cross-protocol accounting (stETH shares vs. balances)
  - Trust assumptions on external protocol state (oracle/price staleness)
  - Approval/allowance misuse with deflationary tokens
"""
from __future__ import annotations

import re
from avadhi.core.graph import SecurityGraph, STATE_VAR, FUNCTION
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


# Known external protocol interface prefixes and their associated risk tags
_KNOWN_RISKY_INTERFACES: dict[str, list[str]] = {
    "IPool":               ["aave", "lending pool", "supply", "borrow", "withdraw"],
    "IAavePool":           ["aave", "lending pool"],
    "ILendingPool":        ["aave", "lending"],
    "IStETH":              ["steth", "rebasing token", "shares"],
    "IWStETH":             ["wsteth", "steth wrapper", "shares vs balance"],
    "IWETH":               ["weth", "wrap", "unwrap"],
    "IUniswapV2Router":    ["uniswap", "swap", "slippage", "deadline"],
    "IUniswapV3Pool":      ["uniswap v3", "tick", "liquidity", "sqrt price"],
    "ISwapRouter":         ["uniswap v3", "swap", "slippage"],
    "ICurvePool":          ["curve", "stableswap", "slippage"],
    "IBalancerVault":      ["balancer", "flash loan", "swap"],
    "IChainlinkAggregator": ["chainlink", "oracle", "stale price", "round"],
    "AggregatorV3Interface": ["chainlink", "oracle", "stale price"],
    "IERC20":              ["erc20", "fee-on-transfer", "approval"],
    "IERC4626":            ["erc4626", "vault", "shares", "assets"],
    "IRewardsController":  ["aave rewards", "claim"],
    "IPoolDataProvider":   ["aave data", "reserve"],
}

# Regex to detect interface-typed state variables
_RE_INTERFACE_VAR = re.compile(r"\bI[A-Z][A-Za-z0-9]+\b")


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in
EXTERNAL PROTOCOL INTEGRATION vulnerabilities and DeFi composability risks.

You are given a map of external protocol interfaces used in this codebase, the
functions that interact with them, and relevant source code.

Your job is to find REAL integration vulnerabilities caused by incorrect assumptions
about external protocol behavior. Focus specifically on:

1. REBASING / FEE-ON-TRANSFER TOKENS
   - stETH rebases: balance changes between blocks without a transfer
   - If the protocol stores stETH amounts as raw balances rather than shares,
     users can gain or lose value silently across rebase events
   - Fee-on-transfer tokens: transferFrom delivers less than the amount specified

2. AAVE / LENDING PROTOCOL INTEGRATION
   - aToken balance vs. underlying balance confusion
   - Incorrect assumption that withdraw(amount) delivers exactly `amount`
   - Failing to check return values of supply(), borrow(), withdraw()
   - RewardsController.claimRewards() receiving tokens not accounted for

3. CROSS-PROTOCOL PRECISION LOSS
   - wstETH shares vs. stETH amounts: getWstETHByStETH / getStETHByWstETH
   - Accumulating rounding errors across multi-step token conversions

4. UNCHECKED EXTERNAL RETURN VALUES
   - low-level calls into external protocols that ignore success bool
   - safeTransfer wrappers that silently succeed on non-reverting failures

5. TRUST / ORACLE ASSUMPTIONS
   - Assuming Chainlink price is always fresh (check updatedAt vs. block.timestamp)
   - Single-source oracle with no fallback or staleness check

DO NOT flag:
- Simple ERC-20 transfer/approve that cannot be fee-on-transfer in this context
- Well-guarded oracle reads that already check staleness
- Theoretical issues with no code path that triggers them

For each finding, cite the exact function, state variable type, and the external
protocol call that creates the risk."""


def run_integration_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for external protocol integration vulnerabilities.

    Strategy:
      1. Collect all state variables whose type is an interface (I*)
      2. Map each interface to the functions that use it
      3. Score by known-risky interface names
      4. Build context + source, ask LLM with interface-specific RAG query
    """
    source_files = sg.metadata.get("source_files", {})

    # --- Step 1: Collect interface-typed state variables ------------------
    interface_vars: dict[str, list[str]] = {}   # interface_type -> [contract.var]
    for node_id, data in sg.G.nodes(data=True):
        if data.get("type") != STATE_VAR:
            continue
        var_type = data.get("var_type", "")
        m = _RE_INTERFACE_VAR.search(var_type)
        if not m:
            continue
        iface = m.group(0)
        key = f"{data.get('contract', '?')}.{data.get('name', '?')}"
        interface_vars.setdefault(iface, []).append(key)

    # Also scan source files for local interface-typed variables not in graph
    _extra = _scan_sources_for_interfaces(source_files)
    for iface, sites in _extra.items():
        for site in sites:
            if site not in interface_vars.get(iface, []):
                interface_vars.setdefault(iface, []).append(site)

    if not interface_vars:
        if verbose:
            print("  IntegrationHunter: no external protocol interfaces found")
        return []

    # --- Step 2: Map interfaces to functions that call them ---------------
    fn_ids_of_interest: list[str] = []
    for node_id, data in sg.G.nodes(data=True):
        if data.get("type") != FUNCTION:
            continue
        if data.get("mutability") in ("view", "pure"):
            continue
        contract_id = f"contract:{data.get('contract', '')}"
        cdata = sg.G.nodes.get(contract_id, {})
        if cdata.get("is_interface") or cdata.get("is_library"):
            continue
        fn_ids_of_interest.append(node_id)

    # --- Step 3: Build context string ------------------------------------
    known_risky = {k: v for k, v in interface_vars.items()
                   if k in _KNOWN_RISKY_INTERFACES}
    all_ifaces = interface_vars  # show all but highlight risky

    if verbose:
        print(f"  IntegrationHunter: {len(all_ifaces)} external interfaces, "
              f"{len(known_risky)} high-risk")

    context_lines = ["# External Protocol Interface Map\n"]
    context_lines.append("## High-Risk Interfaces (known gotchas)")
    for iface, vars_list in sorted(known_risky.items()):
        risk_tags = ", ".join(_KNOWN_RISKY_INTERFACES[iface])
        context_lines.append(f"\n### {iface}  [risk: {risk_tags}]")
        for v in vars_list[:8]:
            context_lines.append(f"  - used as: {v}")

    other_ifaces = {k: v for k, v in all_ifaces.items() if k not in known_risky}
    if other_ifaces:
        context_lines.append("\n## Other External Interfaces")
        for iface, vars_list in sorted(other_ifaces.items()):
            context_lines.append(f"  - {iface}: {', '.join(vars_list[:4])}")

    # Add protocol type from enrichment
    protocol = sg.metadata.get("enrichment_data", {}).get("protocol_type", "DeFi")
    context_lines.insert(0, f"# Protocol Type: {protocol}\n")

    context = "\n".join(context_lines)

    # --- Step 4: Build RAG query from the actual interface names ----------
    risky_names = list(known_risky.keys())[:5]
    if risky_names:
        rag_query = (
            f"External protocol integration vulnerability in {protocol} smart contract. "
            f"Interfaces used: {', '.join(risky_names)}. "
            "Known risks: rebasing tokens, stETH shares vs balance, "
            "Aave aToken accounting, fee-on-transfer, unchecked return values."
        )
    else:
        rag_query = (
            f"External protocol composability vulnerability in {protocol} smart contract. "
            f"Interfaces: {', '.join(list(all_ifaces.keys())[:5])}."
        )

    # Get source for the most connected functions
    source = get_source_for_functions(sg, fn_ids_of_interest, max_chars=10_000)

    return call_hunter(
        hunter_name="IntegrationHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        rag_query=rag_query,
        vulnerability_type="integration composability",
        sg=sg,
        include_methodology=True,
    )


def _scan_sources_for_interfaces(
    source_files: dict[str, str],
) -> dict[str, list[str]]:
    """
    Quick regex scan over raw source to catch interface usages not yet in the
    graph (e.g. local variables, function parameters, return types).
    Returns {interface_name: [location_strings]}.
    """
    result: dict[str, list[str]] = {}
    for file_path, content in source_files.items():
        for m in _RE_INTERFACE_VAR.finditer(content):
            iface = m.group(0)
            if iface in _KNOWN_RISKY_INTERFACES:
                short_path = file_path.split("/")[-1]
                entry = f"{short_path}:{m.start()}"
                if entry not in result.get(iface, []):
                    result.setdefault(iface, []).append(entry)
    return result
