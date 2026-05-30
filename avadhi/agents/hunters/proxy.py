"""
avadhi/agents/hunters/proxy.py — Dedicated Upgradability & Proxy Hunter.

Hunts for:
  - Uninitialized implementation contracts (allowing selfdestruct bricking)
  - Unprotected initialize() functions (front-running logic initialization)
  - Dangerous delegatecall leading to arbitrary code execution in facet/implementations
  - Storage collision issues (EIP-1967 overrides, Diamond facet storage clashes)
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, EXTERNAL_CALL
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in PROXY and UPGRADABILITY vulnerabilities.

You look for flaws in how a protocol manages uninitialized logic contracts, UUPS patterns, or delegatecalls.

Your job is to find REAL proxy vulnerabilities:

1. **Uninitialized Implementation Contracts:**
   If an implementation contract has an `initialize()` function (using `@openzeppelin/contracts-upgradeable` `Initializable`) but does not call `_disableInitializers()` in its constructor, an attacker can call `initialize()` directly on the implementation contract (not the proxy). 
   If they elevate themselves to `owner`, they might be able to call `upgradeToAndCall()` and execute a `selfdestruct`, completely bricking the logic contract for ALL proxies that point to it.

2. **Unprotected initialize():**
   If `initialize` does not have `initializer` modifiers, it can be called multiple times, overwriting protocol state. Or if the protocol deployment scripts leave a delay between proxy deployment and initialization, a MEV bot can front-run the `initialize()` transaction.

3. **Arbitrary Delegatecall:**
   If any function inside the protocol uses `target.delegatecall(data)` where `target` or `data` are at all controllable by a user, the user can execute code in the context of the proxy, granting them the ability to wipe out storage or drain the contract entirely.

For each finding:
- Identify the exact implementation contract and state the missing safeguard (e.g. `_disableInitializers()`).
- Walk through the exact exploit path (how does the bricking/takeover legally execute based on the code).
- Distinguish between the proxy context and the implementation context.

DO NOT flag custom initialization if it uses a standard `false/true` boolean correctly. DO NOT flag `delegatecall` if the target is strictly hardcoded to a trusted protocol address.
"""

def run_proxy_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for proxy and upgradeability vulnerabilities.
    """
    target_fns: list[str] = []
    
    # 1. Catch functions related to init
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        name = data.get("name", "").lower()
        if "initialize" in name or "upgrade" in name:
            target_fns.append(fn_id)
            
    # 2. Check for delegatecalls
    ext_calls = sg.get_external_calls()
    for caller_id, target, metadata in ext_calls:
        call_type = metadata.get("call_type", "").lower()
        if call_type == "delegatecall":
            if caller_id not in target_fns:
                target_fns.append(caller_id)

    if not target_fns:
        if verbose:
            print("  ℹ️  ProxyHunter: No initialization, upgradeability, or delegatecalls detected.")
        return []

    # Build context
    context_lines = ["# Functions Handing Initialization / Proxy Delegatecalls\n"]
    for fn_id in target_fns:
        data = sg.G.nodes.get(fn_id, {})
        context_lines.append(f"- Contract: {data.get('contract', 'Unknown')}")
        context_lines.append(f"  Function: {data.get('name', fn_id)}")
        context_lines.append(f"  Modifiers: {data.get('modifiers', [])}")
        context_lines.append("  --")
        
    context = "\n".join(context_lines)

    if verbose:
        print(f"   ProxyHunter: Analyzing {len(target_fns)} upgrade/proxy-related functions")

    source = get_source_for_functions(sg, target_fns, max_chars=12000)

    return call_hunter(
        hunter_name="ProxyHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
