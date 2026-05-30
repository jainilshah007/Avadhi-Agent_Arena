"""
avadhi/agents/hunters/external_call.py — External Call Hunter.

Hunts for:
  - Arbitrary external calls with user-controlled targets
  - User-controlled calldata reaching .call(), .delegatecall()
  - Missing validation on call targets
  - Reentrancy via external calls
  - Approval + call patterns that allow fund draining
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, TAINT_USER_INPUT
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in EXTERNAL CALL vulnerabilities.

You are given a focused view of a SecurityGraph showing:
- All external calls (.call, .delegatecall, .staticcall, .transfer, .send)
- Whether the call target is USER-CONTROLLED (tainted from function parameters)
- The calling function and its access control
- Token approval patterns near external calls

Your job is to find CRITICAL external call vulnerabilities:

1. **Arbitrary Call**: User controls BOTH the `to` address AND the `data` of a .call()
   - This is almost always Critical severity
   - Check if the calling contract holds tokens/NFTs/approvals that could be stolen
   - Check if the call can be used to impersonate the contract

2. **Reentrancy**: External call happens before state updates
   - Check if nonReentrant modifier is present
   - Check if CEI (Checks-Effects-Interactions) pattern is followed

3. **Unchecked Return Value**: Return value of .call() not checked
   - Especially dangerous for token transfers

4. **Approval + Call**: Contract approves tokens then makes an external call
   - Attacker could redirect the approved tokens via the call

For each finding, provide a CONCRETE exploit scenario with specific function calls."""


def run_external_call_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for external call vulnerabilities.

    Strategy:
      1. Get all external calls from the graph
      2. Prioritize user-controlled calls
      3. Include token flows near external calls
      4. Ask LLM with focused source code
    """
    ext_calls = sg.get_external_calls()
    if not ext_calls:
        if verbose:
            print(f"  ℹ️  ExternalCallHunter: No external calls found")
        return []

    user_controlled = sg.get_user_controlled_calls()
    token_flows = sg.get_token_flows()

    if verbose:
        print(f"  🎯 ExternalCallHunter: {len(ext_calls)} external calls "
              f"({len(user_controlled)} user-controlled)")

    # Build context
    context_lines = ["# External Calls Analysis\n"]

    if user_controlled:
        context_lines.append("## ⚠️ USER-CONTROLLED EXTERNAL CALLS (highest risk)")
        for u, v, d in user_controlled:
            src = sg.G.nodes.get(u, {})
            tgt = sg.G.nodes.get(v, {})
            flags = sg.get_flags_for(u)
            mods = src.get("modifiers", [])
            context_lines.append(
                f"- {src.get('contract','')}.{src.get('name','')}() "
                f"→ {tgt.get('target', v)} "
                f"[{d.get('call_type', '')}] "
                f"value_sent={d.get('value_sent', False)}"
            )
            context_lines.append(f"  Modifiers: {mods or 'NONE'}")
            context_lines.append(f"  Params: {src.get('params', '')}")
            if flags:
                context_lines.append(f"  Flags: {', '.join(flags)}")

    context_lines.append("\n## All External Calls")
    for u, v, d in ext_calls:
        src = sg.G.nodes.get(u, {})
        tgt = sg.G.nodes.get(v, {})
        taint = "⚠️USER_INPUT" if d.get("data_source") == TAINT_USER_INPUT else d.get("data_source", "")
        context_lines.append(
            f"- {src.get('contract','')}.{src.get('name','')}() "
            f"→ {tgt.get('target', v)} [{d.get('call_type', '')}] "
            f"taint={taint}"
        )

    if token_flows:
        context_lines.append("\n## Token Flows (near external calls)")
        for u, v, d in token_flows:
            src = sg.G.nodes.get(u, {})
            token = sg.G.nodes.get(v, {}).get("name", v)
            context_lines.append(
                f"- {src.get('contract','')}.{src.get('name','')}() "
                f"→ {d.get('flow_type', '')} {token}"
            )

    # Get source for functions that make external calls
    caller_fns = list(set(u for u, _, _ in ext_calls))
    context = "\n".join(context_lines)
    source = get_source_for_functions(sg, caller_fns, max_chars=10000)

    return call_hunter(
        hunter_name="ExternalCallHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
