"""
avadhi/agents/hunters/cross_chain.py — Dedicated Cross-Chain & Bridge Hunter.

Hunts for:
  - LayerZero lzReceive / Endpoint validation bypasses
  - Missing srcChainID equivalence checks
  - Forged payloads / improper abi.decode unpacking lengths
  - Missing trusted remote verifications (allowing anyone to mock a cross-chain message)
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in CROSS-CHAIN and BRIDGE vulnerabilities.

You look for flaws in how a protocol inherits and implements arbitrary messaging layers like LayerZero, Wormhole, Axelar, or CCIP.

Your job is to find REAL cross-chain vulnerabilities:

1. **Missing Trusted Remote Validation:**
   If a protocol implements `lzReceive` but doesn't check `require(msg.sender == endpoint)` AND `require(_srcAddress == trustedRemoteLookup[_srcChainId])`, any user can directly call the function and forge the payload to mint tokens or drain the vault locally.

2. **Payload Forgery (abi.decode malleability):**
   If the decoding of the `_payload` assumes fixed lengths but uses `abi.decode` loosely, attackers can shift arrays or append bytes to trick the protocol into processing malicious sub-commands.

3. **Failed Rollback Mechanisms:**
   If a cross-chain bridge transaction fails on the destination side, but the source chain does not properly unlock the user's funds (or unlocks them incorrectly), funds can become permanently locked, or conversely, an attacker can intentionally revert the destination to double-spend on the source.

For each finding:
- Identify the exact messaging entrypoint (e.g., `lzReceive`, `_nonblockingLzReceive`, `executeMessage`).
- Explicitly walk through the missing access control check or the manipulated payload variable.
- Explain the resulting local impact (e.g., arbitrary minting).

DO NOT flag general parameter checks if the `OApp` abstract contract already securely handles the remote validation natively.
"""

def run_cross_chain_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for cross-chain specific vulnerabilities.
    """
    target_fns: list[str] = []
    
    # 1. Look for typical cross-chain entrypoints or imports
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        name = data.get("name", "").lower()
        if any(keyword in name for keyword in ["lzreceive", "nonblockinglzreceive", "execute", "sgreceive", "ccipreceive"]):
            target_fns.append(fn_id)

    if not target_fns:
        if verbose:
            print("  ℹ️  CrossChainHunter: No cross-chain messaging endpoints detected.")
        return []

    # Build context
    context_lines = ["# Functions Handing Cross-Chain Messaging\n"]
    for fn_id in target_fns:
        data = sg.G.nodes.get(fn_id, {})
        context_lines.append(f"- Contract: {data.get('contract', 'Unknown')}")
        context_lines.append(f"  Function: {data.get('name', fn_id)}")
        context_lines.append(f"  Modifiers: {data.get('modifiers', [])}")
        context_lines.append("  --")
        
    context = "\n".join(context_lines)

    if verbose:
        print(f"   CrossChainHunter: Analyzing {len(target_fns)} cross-chain endpoints")

    source = get_source_for_functions(sg, target_fns, max_chars=12000)

    return call_hunter(
        hunter_name="CrossChainHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
