"""
avadhi/pipeline/state.py — LangGraph state definition.

This TypedDict is the single object that flows through every node
in the LangGraph workflow. Each agent reads from it, does work,
and writes results back into it.

ALL fields must be JSON-serializable — no raw Python objects.
"""
from __future__ import annotations

from typing import Any
from typing_extensions import TypedDict

from avadhi.core.schemas import Hypothesis, VerifiedFinding, CriticChallenge


class AuditState(TypedDict, total=False):
    """
    The state object that travels through the LangGraph pipeline.

    Fields are additive — each node can read any field and write
    to any field. LangGraph handles merging automatically.

    IMPORTANT: Every value must be JSON-serializable.
    Do NOT store raw Python objects (SecurityGraph, asyncpg pools, etc.).
    """
    # ── Input ──────────────────────────────────────────────────────────
    target_path: str                        # Path to the contracts dir

    # ── Phase 1: Recon outputs ─────────────────────────────────────────
    graph_json: str                         # Path to serialized SecurityGraph JSON
    graph_context: str                      # Graph context string for LLM
    source_files: dict[str, str]            # {path: content} of .sol files
    pattern_results: dict[str, list[str]]   # {pattern: [locations]}
    enrichment_data: dict[str, Any]         # LLM enrichment output

    # ── Phase 2: Hunting outputs ───────────────────────────────────────
    hypotheses: list[Hypothesis]            # Raw findings from hunters

    # ── Phase 3: Debate outputs ────────────────────────────────────────
    critic_challenges: list[CriticChallenge]  # CriticChallenge records
    verified_findings: list[VerifiedFinding]

    # ── Metadata ───────────────────────────────────────────────────────
    errors: list[str]                       # Errors from any phase
    log_file: str                           # Path to JSONL log
