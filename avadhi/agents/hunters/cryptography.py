"""
avadhi/agents/hunters/cryptography.py — Dedicated Cryptography & Signature Hunter.

Hunts for:
  - ECDSA Signature Malleability (missing `s` value bound checks)
  - Signature Replay (missing/reused nonces, missing EIP-712 domain separators/chainID)
  - Unchecked ecrecover (return value `address(0)` allows forged signatures)
  - Signature reuse across different protocols or targets
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in ADVANCED CRYPTOGRAPHY and SIGNATURE vulnerabilities.

You look for flaws in how protocols verify ECDSA or BLS signatures (e.g., ecrecover, Permit, or custom bridging logic).
You are evaluating the provided subgraph of functions that handle signatures or cryptographic parameters.

Your job is to find REAL cryptography vulnerabilities:

1. **Unchecked ecrecover (Zero Address Return):** 
   `ecrecover` returns `address(0)` on an invalid signature. If the code does not check `require(signer != address(0))` and does not validate the signer strictly, an attacker can pass an invalid signature (getting `0`), and if `owner == address(0)`, the check passes!

2. **Signature Replay (Missing Nonces):**
   A signature can be used infinitely if its hash does not strictly include a monotonically increasing user-specific `nonce`.

3. **Cross-Chain Replay (Missing Chain ID):**
   If `block.chainid` is not included in the digest (often via EIP-712 Domain Separator), a signature valid on Ethereum can be replayed by an attacker on heavily-forked chains (Polygon, Arbitrum) on identical contract deployments.

4. **ECDSA Malleability:**
   A valid signature `(v, r, s)` has a mathematically identical, equally valid symmetric twin `(v, r, -s)`. If the protocol tracks "used signatures" strictly by passing the exact signature bytes rather than the hashed message digest, an attacker can flip `s` to mathematically forge a "new" unused signature to replay the action. 

For each finding:
- Identify the exact function utilizing `ecrecover` or signature processing.
- Point out the missing check (e.g. tracking `used[signature]`, missing `chainid`, or missing `signer != 0`).
- Provide an attacker flow to exploit it.

DO NOT flag OpenZeppelin's `ECDSA.recover` library usage unless the implementation misuses it (OZ securely handles malleability and zero address internally).
"""

def run_cryptography_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for Cryptography & Signature vulnerabilities.
    """
    # Find functions dealing with signatures
    target_fns: list[str] = []
    
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        name = data.get("name", "").lower()
        mods = [m.lower() for m in data.get("modifiers", [])]
        
        # Look for signature-related names
        if any(keyword in name for keyword in ["sign", "permit", "verify", "recover", "ecrecover", "hash"]):
            target_fns.append(fn_id)
            continue
            
        # Or param names like /sig/ /v/ /r/ /s/ (This is harder without param data easily exposed, but we can check if it calls OZ ECDSA library or ecrecover)
        
    # We also check edges: does anything call ecrecover?
    # ecrecover is a built-in precompile, usually modeled as an external call or built-in node in Slither.
    ext_calls = sg.get_external_calls()
    for caller_id, target, metadata in ext_calls:
        if "ecrecover" in target.lower() or "ecdsa" in target.lower():
            if caller_id not in target_fns:
                target_fns.append(caller_id)

    if not target_fns:
        if verbose:
            print("  ℹ️  CryptographyHunter: No signature handling or ecrecover detected.")
        return []

    # Build context
    context_lines = ["# Functions Handing Signatures/Cryptography\n"]
    for fn_id in target_fns:
        data = sg.G.nodes.get(fn_id, {})
        context_lines.append(f"- Contract: {data.get('contract', 'Unknown')}")
        context_lines.append(f"  Function: {data.get('name', fn_id)}")
        context_lines.append(f"  Modifiers: {data.get('modifiers', [])}")
        context_lines.append("  --")
        
    context = "\n".join(context_lines)

    if verbose:
        print(f"  🎯 CryptographyHunter: Analyzing {len(target_fns)} crypto-related functions")

    # Fetch targeted source snippets
    source = get_source_for_functions(sg, target_fns, max_chars=12000)

    return call_hunter(
        hunter_name="CryptographyHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
