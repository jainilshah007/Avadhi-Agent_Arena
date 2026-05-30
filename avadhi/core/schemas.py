"""
avadhi/core/schemas.py — Shared data models used across all agents.

Pydantic models for type safety and serialization.
Every agent input/output is a schema, never a raw dict.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"     # Proven with evidence
    CONTESTED = "Contested"     # Mixed evidence, needs debate
    REFUTED = "Refuted"         # Proven false
    UNCERTAIN = "Uncertain"     # Insufficient evidence


class ContractInfo(BaseModel):
    """Info about a single contract in the target project."""
    name: str
    file_path: str
    sloc: int = 0
    is_interface: bool = False
    is_library: bool = False
    inheritance: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    """
    A potential vulnerability found by a hunter agent.
    This is the primary output of Phase 4 (hunting).
    """
    id: str                                     # e.g., "H-EXT-001"
    title: str
    severity: Severity
    confidence: Confidence = Confidence.UNCERTAIN
    category: str                               # e.g., "External Call", "Access Control"
    description: str
    location: str                               # e.g., "JackpotBridgeManager._bridgeFunds:L345"
    attack_scenario: str = ""                   # Step-by-step exploit
    preconditions: list[str] = Field(default_factory=list)
    impact: str = ""
    evidence: list[str] = Field(default_factory=list)  # Code snippets, line refs
    related_graph_nodes: list[str] = Field(default_factory=list)  # SecurityGraph node IDs
    hunter_agent: str = ""                      # Which agent found this
    iteration: int = 1                          # Which loop iteration
    discovery_path: str = ""                    # How found: "ReasoningAgent", "Cross-feed I2", etc.
    critic_challenges: list[str] = Field(default_factory=list)  # Added to track depth/debate challenges


class CriticChallenge(BaseModel):
    """A critic's challenge to a hypothesis."""
    hypothesis_id: str
    challenge: str                              # What the critic disputes
    counter_evidence: list[str] = Field(default_factory=list)
    verdict: Confidence = Confidence.UNCERTAIN
    reasoning: str = ""


class VerifiedFinding(BaseModel):
    """
    A finding that survived the debate loop.
    This is the final output that goes into the report.
    """
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    location: str
    attack_scenario: str = ""
    proof_of_concept: str = ""                  # Foundry test code
    impact: str = ""
    recommendation: str = ""
    evidence_chain: list[str] = Field(default_factory=list)  # Full evidence trail
    debate_log: list[str] = Field(default_factory=list)      # Strategist ↔ Critic
    source_hypotheses: list[str] = Field(default_factory=list)  # Original hypothesis IDs


class AuditResult(BaseModel):
    """Complete result of an audit run."""
    target_path: str
    protocol_type: str = ""
    contracts: list[ContractInfo] = Field(default_factory=list)
    findings: list[VerifiedFinding] = Field(default_factory=list)
    hypotheses_total: int = 0
    hypotheses_confirmed: int = 0
    hypotheses_refuted: int = 0
    patterns_detected: list[str] = Field(default_factory=list)
    graph_nodes: int = 0
    graph_edges: int = 0
