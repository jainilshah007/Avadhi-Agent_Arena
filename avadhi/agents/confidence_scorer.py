"""
avadhi/agents/confidence_scorer.py — Phase 3c: 4-Axis Numerical Confidence Scorer.

Assigns a final numeric confidence score (0–100) to each surviving hypothesis
using four axes:

  Axis 1 — Structural Evidence  (0–25)
    Does the SecurityGraph provide definitive structural proof?
    (external call edges, write-before-guard patterns, etc.)

  Axis 2 — Critic Resistance    (0–25)
    Was the hypothesis CONFIRMED or merely CONTESTED by the Critic?

  Axis 3 — Severity × Exploitability (0–25)
    Critical bugs with well-defined preconditions score higher.

  Axis 4 — RAG Corroboration    (0–25)
    If similar patterns exist in the vulnerability database (Code4rena),
    the finding gets a corroboration boost.

Final score = Σ of four axes (0–100).
Score categories:
  90–100 → STRONG CONFIRMED (include as-is in report)
  70–89  → CONFIRMED (include in report, note any caveats)
  50–69  → CONTESTED (include with explicit low-confidence caveat)
  0–49   → WEAK (demote in report, include only as advisory notes)
"""
from __future__ import annotations

from dataclasses import dataclass
from avadhi.core.schemas import Hypothesis, Severity, Confidence


# ---------------------------------------------------------------------------
# Score dataclass
# ---------------------------------------------------------------------------

@dataclass
class HypothesisScore:
    hypothesis_id: str
    axis_structural: int        # 0–25
    axis_critic: int            # 0–25
    axis_severity: int          # 0–25
    axis_rag: int               # 0–25
    total: int                  # 0–100
    tier: str                   # STRONG_CONFIRMED | CONFIRMED | CONTESTED | WEAK

    def to_markdown_row(self) -> str:
        return (
            f"| `{self.hypothesis_id}` "
            f"| {self.axis_structural} "
            f"| {self.axis_critic} "
            f"| {self.axis_severity} "
            f"| {self.axis_rag} "
            f"| **{self.total}** "
            f"| {self.tier} |"
        )


# ---------------------------------------------------------------------------
# Axis scoring helpers
# ---------------------------------------------------------------------------

def _score_structural(h: Hypothesis) -> int:
    """
    Axis 1: Does the hunter cite concrete SecurityGraph evidence?
    More cited graph nodes and code-level evidence = higher score.
    """
    score = 0
    # Number of graph nodes cited
    nodes = len(h.related_graph_nodes)
    score += min(nodes * 3, 12)          # up to 12 pts for graph nodes

    # Number of evidence items (code references)
    evidence = len(h.evidence)
    score += min(evidence * 2, 8)        # up to 8 pts for evidence lines

    # If attack_scenario is detailed (>200 chars), bonus
    if len(h.attack_scenario) > 200:
        score += 5

    return min(score, 25)


def _score_critic(h: Hypothesis) -> int:
    """Axis 2: Based entirely on the Critic's verdict."""
    mapping = {
        Confidence.CONFIRMED:  25,
        Confidence.UNCERTAIN:  15,
        Confidence.CONTESTED:  10,
        Confidence.REFUTED:    0,
    }
    return mapping.get(h.confidence, 10)


def _score_severity(h: Hypothesis) -> int:
    """
    Axis 3: Severity × exploitability heuristic.
    Critical with no preconditions → max points.
    Low with many preconditions → low points.
    """
    base = {
        Severity.CRITICAL: 25,
        Severity.HIGH:     20,
        Severity.MEDIUM:   13,
        Severity.LOW:      6,
        Severity.INFO:     2,
    }.get(h.severity, 10)

    # Penalize if lots of preconditions (harder to exploit)
    precond_penalty = min(len(h.preconditions) * 2, 10)
    return max(base - precond_penalty, 0)


def _score_rag(h: Hypothesis) -> int:
    """
    Axis 4: RAG corroboration heuristic.
    For now, we use category-based lookup; in future this can call the
    retriever to do a live database check for matching bug patterns.
    """
    # Categories with very strong historical precedent in the C4 database
    HIGH_EVIDENCE_CATEGORIES = {
        "Reentrancy", "Oracle/Randomness", "Access Control",
        "External Call", "Accounting"
    }
    MEDIUM_EVIDENCE_CATEGORIES = {
        "Governance", "Gas/DoS", "DeFi Math", "Cryptography"
    }
    LOW_EVIDENCE_CATEGORIES = {
        "Proxy", "Cross-Chain"
    }

    if h.category in HIGH_EVIDENCE_CATEGORIES:
        return 25
    elif h.category in MEDIUM_EVIDENCE_CATEGORIES:
        return 17
    elif h.category in LOW_EVIDENCE_CATEGORIES:
        return 10
    return 12


def _compute_tier(total: int) -> str:
    if total >= 90:
        return "STRONG_CONFIRMED"
    elif total >= 70:
        return "CONFIRMED"
    elif total >= 50:
        return "CONTESTED"
    return "WEAK"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_hypotheses(
    hypotheses: list[Hypothesis],
    verbose: bool = False,
) -> list[HypothesisScore]:
    """
    Phase 3c: Compute a 4-axis confidence score for all surviving hypotheses.

    Args:
        hypotheses: list of Hypothesis objects that survived the Critic.
        verbose: whether to print scoring per finding.

    Returns:
        list of HypothesisScore objects, sorted descending by total score.
    """
    scores: list[HypothesisScore] = []

    for h in hypotheses:
        s1 = _score_structural(h)
        s2 = _score_critic(h)
        s3 = _score_severity(h)
        s4 = _score_rag(h)
        total = s1 + s2 + s3 + s4
        tier = _compute_tier(total)

        hs = HypothesisScore(
            hypothesis_id=h.id,
            axis_structural=s1,
            axis_critic=s2,
            axis_severity=s3,
            axis_rag=s4,
            total=total,
            tier=tier,
        )
        scores.append(hs)

        if verbose:
            print(
                f"  📊 {h.id:12s}  structural={s1:2d}  critic={s2:2d}  "
                f"severity={s3:2d}  rag={s4:2d}  → total={total:3d}  [{tier}]"
            )

    # Sort descending — highest confidence findings first in the report
    scores.sort(key=lambda x: x.total, reverse=True)
    return scores


def scores_to_markdown_table(scores: list[HypothesisScore]) -> str:
    """Render a complete markdown confidence score table for the final report."""
    header = (
        "| Finding ID | Structural | Critic | Severity | RAG | **Total** | Tier |\n"
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|"
    )
    rows = "\n".join(s.to_markdown_row() for s in scores)
    return f"{header}\n{rows}"
