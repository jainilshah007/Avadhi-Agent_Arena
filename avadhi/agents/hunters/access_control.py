"""
avadhi/agents/hunters/access_control.py — Access Control Hunter.

Hunts for:
  - External/public functions with no access modifiers that write state
  - Functions that can be called by anyone to change critical parameters
  - Missing checks on msg.sender for privileged operations
  - Admin functions without timelocks or multi-sig requirements
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, WRITES, STATE_VAR
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in ACCESS CONTROL vulnerabilities.

You are given a filtered view of a SecurityGraph showing ONLY:
- External/public functions with NO access control modifiers (unrestricted entry points)
- State variables these functions can write to
- Any detected security patterns/flags on these functions

Your job is to find REAL access control vulnerabilities:
1. Functions that should be admin-only but aren't restricted
2. Functions that write to critical state (balances, addresses, configs) without authorization
3. Missing role checks that allow unauthorized state changes
4. Functions that can be called to manipulate protocol parameters

DO NOT flag:
- View/pure functions (they can't change state)
- Functions that are intentionally open (like buying tickets, depositing, etc.)
- Interface functions (they have no implementation)
- Functions that use EIP-712 signatures, ECDSA.recover, ecrecover, or _validateSignature to
  authenticate the caller — these have cryptographic access control even without a modifier
- Functions that perform internal ownership checks (e.g. _validateTicketOwnership,
  _checkOwner, require(msg.sender == owner)) without an explicit modifier

IMPORTANT: A missing modifier does NOT automatically mean missing access control.
Always check whether the function body contains require() checks, ownership validation,
signature verification, or similar guards before raising a finding.

For each finding, trace the FULL attack path: who calls what, what state changes, what's the impact."""


def run_access_control_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for access control vulnerabilities.

    Strategy:
      1. Find all unrestricted external/public functions
      2. Check which ones write to state variables
      3. Filter out views/pures and interfaces
      4. Ask LLM to analyze the dangerous ones
    """
    # Get unrestricted entry points
    unrestricted = sg.get_unrestricted_entry_points()

    # Filter to only functions that write state or have dangerous flags
    dangerous_fns = []
    for fn_id in unrestricted:
        node = sg.G.nodes.get(fn_id, {})

        # Skip views/pures
        if node.get("mutability") in ("view", "pure"):
            continue

        # Skip interface contracts
        contract_id = f"contract:{node.get('contract', '')}"
        contract_node = sg.G.nodes.get(contract_id, {})
        if contract_node.get("is_interface") or contract_node.get("is_library"):
            continue

        # Check for state writes
        has_writes = any(
            d.get("type") == WRITES
            for _, _, d in sg.G.out_edges(fn_id, data=True)
        )

        # Check for flags
        flags = sg.get_flags_for(fn_id)

        if has_writes or flags:
            dangerous_fns.append(fn_id)

    if not dangerous_fns:
        if verbose:
            print(f"  ℹ️  AccessControlHunter: No dangerous unrestricted functions found")
        return []

    if verbose:
        print(f"   AccessControlHunter: {len(dangerous_fns)} dangerous unrestricted functions")

    # Build focused context
    context_lines = ["# Unrestricted Functions That Modify State\n"]
    for fn_id in dangerous_fns:
        node = sg.G.nodes[fn_id]
        flags = sg.get_flags_for(fn_id)

        # Find what state vars this function writes
        writes = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                  if d.get("type") == WRITES]
        write_names = [sg.G.nodes.get(w, {}).get("name", w) for w in writes]

        context_lines.append(
            f"- {node['contract']}.{node['name']}() "
            f"[{node.get('visibility', '')}] "
            f"params=({node.get('params', '')})"
        )
        if write_names:
            context_lines.append(f"  WRITES: {', '.join(write_names)}")
        if flags:
            context_lines.append(f"  FLAGS: {', '.join(flags)}")

    # Add enrichment context if available
    trust_boundaries = sg.metadata.get("trust_boundaries", [])
    if trust_boundaries:
        context_lines.append("\n# Trust Boundaries (from enrichment)")
        for tb in trust_boundaries:
            if isinstance(tb, dict):
                context_lines.append(f"- {tb}")

    context = "\n".join(context_lines)
    source = get_source_for_functions(sg, dangerous_fns, max_chars=8000)

    return call_hunter(
        hunter_name="AccessControlHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
