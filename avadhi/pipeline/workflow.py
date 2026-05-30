"""
avadhi/pipeline/workflow.py — The canonical LangGraph audit pipeline.

This is the SINGLE source of truth for the audit workflow.
All nodes deserialize SecurityGraph from graph_json (never raw objects).

Pipeline:
  START → enrichment → hunting → crossfeed → critic → review → END
"""
from __future__ import annotations

import traceback
from pathlib import Path
from typing import Any

from langgraph.graph import StateGraph, START, END

from avadhi.pipeline.state import AuditState
from avadhi.core.graph import SecurityGraph
from avadhi.utils.logging import AuditLogger


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_logger(state: AuditState) -> AuditLogger:
    """Create or retrieve a logger from state."""
    log_file = state.get("log_file", ".avadhi_output")
    log_dir = str(Path(log_file).parent) if Path(log_file).suffix else str(log_file)
    return AuditLogger(log_dir)


def _load_graph(state: AuditState) -> SecurityGraph | None:
    """Load SecurityGraph from the graph_json path in state."""
    graph_json = state.get("graph_json")
    if not graph_json:
        return None
    try:
        return SecurityGraph.from_json(graph_json)
    except Exception:
        return None


def _reload_source_files(sg: SecurityGraph, state: AuditState) -> None:
    """Reload source files into sg.metadata if not already loaded."""
    target_path = state.get("target_path", "")
    if target_path and not sg.metadata.get("source_files"):
        from avadhi.recon.parser import discover_sol_files
        sg.metadata["source_files"] = discover_sol_files(Path(target_path))


# ── Node: Enrichment ─────────────────────────────────────────────────────────

def enrichment_node(state: AuditState) -> dict[str, Any]:
    """Phase 1c: LLM enrichment of the SecurityGraph."""
    logger = _make_logger(state)
    sg = _load_graph(state)
    if sg is None:
        err = "Missing or invalid graph_json in state — cannot enrich"
        logger.log_phase("enrichment", "failed", error=err)
        return {"errors": state.get("errors", []) + [err]}

    try:
        logger.log_phase("enrichment", "start")
        from avadhi.recon.enrichment import run_enrichment
        enrichment_data = run_enrichment(sg, logger=logger, verbose=True)

        # Persist enrichment metadata back into the graph file
        sg.metadata.update({k: v for k, v in enrichment_data.items()
                            if k in ("protocol_type", "invariants", "trust_boundaries", "dangerous_flows")})
        sg.to_json(state["graph_json"])

        logger.log_phase("enrichment", "complete",
                         invariants=len(enrichment_data.get("invariants", [])))
        return {"enrichment_data": enrichment_data}

    except Exception as e:
        err = f"Enrichment failed: {e}"
        logger.log_phase("enrichment", "failed", error=err,
                         traceback=traceback.format_exc())
        return {"errors": state.get("errors", []) + [err]}


# ── Node: Hunting ────────────────────────────────────────────────────────────

def hunting_node(state: AuditState) -> dict[str, Any]:
    """Phase 2: Run all specialized hunters."""
    logger = _make_logger(state)
    sg = _load_graph(state)
    if sg is None:
        err = "Missing or invalid graph_json in state — cannot hunt"
        logger.log_phase("hunting", "failed", error=err)
        return {"errors": state.get("errors", []) + [err]}

    _reload_source_files(sg, state)

    from avadhi.agents.hunters.access_control import run_access_control_hunter
    from avadhi.agents.hunters.external_call import run_external_call_hunter
    from avadhi.agents.hunters.gas_dos import run_gas_dos_hunter
    from avadhi.agents.hunters.accounting import run_accounting_hunter
    from avadhi.agents.hunters.oracle import run_oracle_hunter
    from avadhi.agents.hunters.reentrancy import run_reentrancy_hunter
    from avadhi.agents.hunters.governance import run_governance_hunter

    hunters = [
        ("Access Control", run_access_control_hunter),
        ("External Call", run_external_call_hunter),
        ("Gas/DoS", run_gas_dos_hunter),
        ("Accounting", run_accounting_hunter),
        ("Oracle/Randomness", run_oracle_hunter),
        ("Reentrancy", run_reentrancy_hunter),
        ("Governance", run_governance_hunter),
    ]

    hypotheses: list = []
    errors: list[str] = []

    logger.log_phase("hunting", "start")
    for name, hunter_fn in hunters:
        try:
            results = hunter_fn(sg, logger=logger, verbose=True)
            hypotheses.extend(results)
        except Exception as e:
            err = f"{name} hunter failed: {e}"
            logger.log("hunting", name, "failed", error=err,
                       traceback=traceback.format_exc())
            errors.append(err)

    logger.log_phase("hunting", "complete", total_hypotheses=len(hypotheses))

    out: dict[str, Any] = {"hypotheses": hypotheses}
    if errors:
        out["errors"] = state.get("errors", []) + errors
    return out


# ── Node: Cross-Feed Hunting ─────────────────────────────────────────────────

def crossfeed_hunting_node(state: AuditState) -> dict[str, Any]:
    """Phase 2b: Re-run selected hunters with Pass 1 context."""
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        return {}

    logger = _make_logger(state)
    sg = _load_graph(state)
    if sg is None:
        return {}

    _reload_source_files(sg, state)

    from avadhi.agents.hunters.crossfeed import (
        summarize_for_crossfeed, select_hunters_for_pass2,
    )
    from avadhi.agents.hunters.access_control import run_access_control_hunter
    from avadhi.agents.hunters.external_call import run_external_call_hunter
    from avadhi.agents.hunters.gas_dos import run_gas_dos_hunter
    from avadhi.agents.hunters.accounting import run_accounting_hunter
    from avadhi.agents.hunters.oracle import run_oracle_hunter
    from avadhi.agents.hunters.reentrancy import run_reentrancy_hunter
    from avadhi.agents.hunters.governance import run_governance_hunter

    hunters = [
        ("Access Control", run_access_control_hunter),
        ("External Call", run_external_call_hunter),
        ("Gas/DoS", run_gas_dos_hunter),
        ("Accounting", run_accounting_hunter),
        ("Oracle/Randomness", run_oracle_hunter),
        ("Reentrancy", run_reentrancy_hunter),
        ("Governance", run_governance_hunter),
    ]

    try:
        cross_feed_summary = summarize_for_crossfeed(hypotheses)
        pass2_hunters = select_hunters_for_pass2(hypotheses, hunters)
    except Exception as e:
        logger.log("crossfeed", "orchestrator", "failed",
                   error=f"Cross-feed setup failed: {e}")
        return {}

    pass2_hypotheses = []
    for name, hunter_fn in pass2_hunters:
        try:
            results = hunter_fn(sg, logger=logger, verbose=True,
                                cross_feed_context=cross_feed_summary)
            for h in results:
                h.iteration = 2
                h.id = f"XF-{h.id}"
            pass2_hypotheses.extend(results)
        except Exception as e:
            logger.log("crossfeed", name, "failed", error=str(e))

    # Dedup
    existing = {(h.location, h.category) for h in hypotheses}
    novel = [h for h in pass2_hypotheses if (h.location, h.category) not in existing]

    logger.log_phase("crossfeed", "complete",
                     pass2_total=len(pass2_hypotheses), novel=len(novel))
    return {"hypotheses": hypotheses + novel}


# ── Node: Critic ─────────────────────────────────────────────────────────────

def critic_node(state: AuditState) -> dict[str, Any]:
    """Phase 3a: Challenge each hypothesis, drop refuted ones."""
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        return {"hypotheses": [], "critic_challenges": []}

    logger = _make_logger(state)
    sg = _load_graph(state)
    if sg is None:
        sg = SecurityGraph()

    _reload_source_files(sg, state)

    try:
        from avadhi.agents.critic import run_critic
        logger.log_phase("critic", "start")
        surviving, challenges = run_critic(hypotheses, sg, logger=logger, verbose=True)
        logger.log_phase("critic", "complete",
                         surviving=len(surviving),
                         refuted=len(hypotheses) - len(surviving))
        return {
            "hypotheses": surviving,
            "critic_challenges": [c.model_dump() for c in challenges],
        }
    except Exception as e:
        logger.log_phase("critic", "failed", error=str(e),
                         traceback=traceback.format_exc())
        # On critic failure, pass all hypotheses through unfiltered
        return {"hypotheses": hypotheses, "critic_challenges": []}


# ── Node: Review ─────────────────────────────────────────────────────────────

def review_node(state: AuditState) -> dict[str, Any]:
    """Phase 3b: Convert surviving hypotheses to VerifiedFindings."""
    hypotheses = state.get("hypotheses", [])
    challenges_raw = state.get("critic_challenges", [])

    from avadhi.core.schemas import VerifiedFinding

    challenge_map: dict[str, list[str]] = {}
    for c in challenges_raw:
        hid = c.get("hypothesis_id", "") if isinstance(c, dict) else getattr(c, "hypothesis_id", "")
        challenge = c.get("challenge", "") if isinstance(c, dict) else getattr(c, "challenge", "")
        verdict = c.get("verdict", "?") if isinstance(c, dict) else getattr(c, "verdict", "?")
        entry = f"Critic [{verdict}]: {challenge}"
        challenge_map.setdefault(hid, []).append(entry)

    findings = []
    for h in hypotheses:
        finding = VerifiedFinding(
            id=f"V-{h.id}",
            title=h.title,
            severity=h.severity,
            confidence=h.confidence,
            category=h.category,
            description=h.description,
            location=h.location,
            attack_scenario=h.attack_scenario,
            impact=h.impact,
            debate_log=challenge_map.get(h.id, []),
            source_hypotheses=[h.id],
        )
        findings.append(finding)

    return {"verified_findings": findings}


# ── Graph Builder ────────────────────────────────────────────────────────────

def create_audit_graph():
    """Build the canonical LangGraph workflow.

    Pipeline: START → enrichment → hunting → crossfeed → critic → review → END
    """
    workflow = StateGraph(AuditState)

    workflow.add_node("enrichment", enrichment_node)
    workflow.add_node("hunting", hunting_node)
    workflow.add_node("crossfeed", crossfeed_hunting_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("review", review_node)

    workflow.add_edge(START, "enrichment")
    workflow.add_edge("enrichment", "hunting")
    workflow.add_edge("hunting", "crossfeed")
    workflow.add_edge("crossfeed", "critic")
    workflow.add_edge("critic", "review")
    workflow.add_edge("review", END)

    return workflow.compile()
