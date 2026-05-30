"""
avadhi/agents/router.py — Intelligent agent routing.

Decides which hunters to activate based on:
  1. Pattern flags detected during recon (deterministic pre-filter)
  2. SecurityGraph complexity metrics (attack surface scoring)
  3. Protocol type from enrichment

Inspired by Plamen's BINDING MANIFEST — flags drive agent selection,
not a scatter-gather "run everything" approach.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from avadhi.core.graph import SecurityGraph, FUNCTION, WRITES, READS, EXTERNAL_CALL


# ---------------------------------------------------------------------------
# Hunt manifest — the router's output
# ---------------------------------------------------------------------------

@dataclass
class HuntManifest:
    """Which agents to run and what to focus on."""
    agents: list[str]                          # agent keys to activate
    hot_functions: list[str] = field(default_factory=list)   # high-priority fn IDs
    flags_detected: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)       # human-readable log


# ---------------------------------------------------------------------------
# Flag → agent mapping
# ---------------------------------------------------------------------------

# Agents that ALWAYS run — they cover universal attack surface
ALWAYS_RUN = {"reasoning", "structural", "vector_scan"}

# Pattern flags → which additional agents they trigger
FLAG_TRIGGERS: dict[str, set[str]] = {
    # Economic agent triggers
    "ORACLE":           {"economic"},
    "FLASH_LOAN":       {"economic"},
    "DEX_INTERACTION":  {"economic"},
    "LENDING":          {"economic"},
    "BALANCE_DEPENDENT": {"economic"},
    "STAKING":          {"economic"},
    "ERC4626":          {"economic"},
    "MIXED_DECIMALS":   {"economic"},
    "SHARE_ALLOCATION": {"economic"},
    # Execution trace agent triggers
    "PROXY_UPGRADEABLE": {"execution_trace"},
    "CROSS_CHAIN":       {"execution_trace"},
    "CALLBACK":          {"execution_trace"},
    "TEMPORAL":          {"execution_trace"},
    "HAS_SIGNATURES":    {"execution_trace"},
    "MIGRATION":         {"execution_trace"},
    "LOW_LEVEL_CALL":    {"execution_trace"},
    "MULTI_TOKEN":       {"execution_trace"},
    # Both economic + execution trace
    "GOVERNANCE":        {"economic", "execution_trace"},
    "LOTTERY":           {"economic"},
    "RANDOMNESS_WEAK":   {"economic"},
    "RANDOMNESS_VRF":    {"economic"},
    # Reentrancy guard presence doesn't skip analysis — it means
    # cross-function/cross-contract reentrancy is still possible
    "REENTRANCY_GUARD":  set(),
    "SEMI_TRUSTED_ROLE": set(),
}

# Protocol type → additional agents (from enrichment)
PROTOCOL_TRIGGERS: dict[str, set[str]] = {
    "lending":    {"economic"},
    "dex":        {"economic"},
    "amm":        {"economic"},
    "vault":      {"economic"},
    "bridge":     {"execution_trace", "economic"},
    "staking":    {"economic"},
    "governance": {"economic", "execution_trace"},
    "lottery":    {"economic"},
    "nft":        {"execution_trace"},
}

# Minimum contract count to activate periphery agent
PERIPHERY_MIN_CONTRACTS = 5


# ---------------------------------------------------------------------------
# Complexity scoring
# ---------------------------------------------------------------------------

def _score_function(sg: SecurityGraph, fn_id: str) -> float:
    """
    Score a function's attack-surface complexity.

    High scores = more interesting to audit:
      - External calls (especially user-controlled)  +3 each
      - State writes                                  +2 each
      - No access-control modifiers                   +2
      - Pattern flags on this function                +1 each
      - Token flows                                   +2 each
    """
    node = sg.G.nodes.get(fn_id, {})
    if not node or node.get("type") != FUNCTION:
        return 0.0

    # Skip views/pures and interfaces
    if node.get("mutability") in ("view", "pure"):
        return 0.0
    contract_id = f"contract:{node.get('contract', '')}"
    contract_node = sg.G.nodes.get(contract_id, {})
    if contract_node.get("is_interface") or contract_node.get("is_library"):
        return 0.0

    score = 0.0
    for _, _, d in sg.G.out_edges(fn_id, data=True):
        edge_type = d.get("type", "")
        if edge_type == EXTERNAL_CALL:
            score += 4.0 if d.get("data_source") == "user_input" else 3.0
        elif edge_type == WRITES:
            score += 2.0
        elif edge_type == "TOKEN_FLOW":
            score += 2.0

    mods = node.get("modifiers", [])
    if not mods:
        score += 2.0

    flags = sg.get_flags_for(fn_id)
    score += len(flags) * 1.0

    return score


def _rank_hot_functions(sg: SecurityGraph, top_n: int = 20) -> list[str]:
    """Return the top-N highest-complexity functions in the graph."""
    scored: list[tuple[str, float]] = []
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        s = _score_function(sg, fn_id)
        if s > 0:
            scored.append((fn_id, s))
    scored.sort(key=lambda x: x[1], reverse=True)
    return [fn_id for fn_id, _ in scored[:top_n]]


# ---------------------------------------------------------------------------
# Main router
# ---------------------------------------------------------------------------

def route(sg: SecurityGraph) -> HuntManifest:
    """
    Determine which agents to activate based on the SecurityGraph.

    Returns a HuntManifest with selected agents, hot functions, and rationale.
    """
    flags = set(sg.metadata.get("global_flags", []))
    protocol_type = (
        sg.metadata.get("enrichment_data", {}).get("protocol_type", "")
        or sg.metadata.get("protocol_type", "")
    ).lower().strip()

    agents: set[str] = set(ALWAYS_RUN)
    rationale: list[str] = [
        f"Always-on agents: {', '.join(sorted(ALWAYS_RUN))}",
    ]

    # Flag-based activation
    triggered_by_flags: set[str] = set()
    for flag in flags:
        new_agents = FLAG_TRIGGERS.get(flag, set())
        if new_agents:
            triggered_by_flags |= new_agents
            for a in new_agents:
                if a not in agents:
                    rationale.append(f"  + {a} (triggered by {flag} flag)")

    agents |= triggered_by_flags

    # Protocol-type activation
    if protocol_type:
        proto_agents = PROTOCOL_TRIGGERS.get(protocol_type, set())
        for a in proto_agents:
            if a not in agents:
                rationale.append(f"  + {a} (protocol type: {protocol_type})")
        agents |= proto_agents

    # Periphery agent: only if enough contracts
    contract_count = sum(
        1 for _, d in sg.G.nodes(data=True)
        if d.get("type") == "Contract"
        and not d.get("is_interface")
        and not d.get("is_library")
    )
    if contract_count >= PERIPHERY_MIN_CONTRACTS:
        agents.add("periphery")
        rationale.append(f"  + periphery ({contract_count} contracts >= {PERIPHERY_MIN_CONTRACTS})")

    # If no flags triggered economic or execution_trace, check if the graph
    # has external calls or token flows — those always warrant economic analysis
    ext_calls = sg.get_external_calls()
    token_flows = sg.get_token_flows()
    if ext_calls and "economic" not in agents:
        agents.add("economic")
        rationale.append(f"  + economic ({len(ext_calls)} external calls detected)")
    if token_flows and "economic" not in agents:
        agents.add("economic")
        rationale.append(f"  + economic ({len(token_flows)} token flows detected)")

    # Rank hot functions
    hot_fns = _rank_hot_functions(sg)

    rationale.append(f"Total agents selected: {len(agents)} / 6")
    rationale.append(f"Hot functions: {len(hot_fns)}")

    return HuntManifest(
        agents=sorted(agents),
        hot_functions=hot_fns,
        flags_detected=sorted(flags),
        rationale=rationale,
    )
