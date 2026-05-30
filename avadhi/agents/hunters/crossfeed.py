"""
avadhi/agents/hunters/crossfeed.py — Cross-Feed Hunting (Pass 2).

After all hunters run independently in Pass 1, this module:
  1. Summarizes all Pass 1 findings into a compact digest
  2. Selects which hunters to re-run based on domain interactions
  3. Provides the cross-feed context so hunters can find CHAINS,
     INTERACTIONS, and AMPLIFICATIONS across findings

Inspired by Nemesis iterative cross-feeding and Hound adaptive knowledge graphs.
"""
from __future__ import annotations

from typing import Callable

from avadhi.core.schemas import Hypothesis


# Which hunter domains interact with each other?
# If HunterA finds something, HunterB should re-run if B is in A's interaction set.
DOMAIN_INTERACTIONS: dict[str, set[str]] = {
    "ExternalCallHunter": {"ReentrancyHunter", "AccessControlHunter", "AccountingHunter"},
    "AccountingHunter": {"ExternalCallHunter", "GovernanceHunter", "OracleHunter", "GasDoSHunter"},
    "AccessControlHunter": {"GovernanceHunter", "ExternalCallHunter"},
    "ReentrancyHunter": {"ExternalCallHunter", "AccountingHunter"},
    "OracleHunter": {"AccountingHunter", "GovernanceHunter"},
    "GovernanceHunter": {"AccessControlHunter", "AccountingHunter", "OracleHunter"},
    "GasDoSHunter": {"AccountingHunter", "GovernanceHunter"},
}


def summarize_for_crossfeed(
    hypotheses: list[Hypothesis],
    max_chars: int = 2500,
) -> str:
    """
    Compress Pass 1 hypotheses into a compact one-line-per-finding digest.

    Format per finding:
      [HIGH] ACC-001: LP pool cap bypass in LotteryPool.settleDraw() — Description snippet.

    Sorted by severity (Critical first). Truncated at max_chars.
    """
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_h = sorted(
        hypotheses,
        key=lambda h: severity_order.get(
            h.severity.value if hasattr(h.severity, "value") else str(h.severity), 5
        ),
    )

    lines: list[str] = []
    total = 0

    for h in sorted_h:
        sev = h.severity.value if hasattr(h.severity, "value") else str(h.severity)
        # Truncate description to ~120 chars
        desc = h.description[:120].replace("\n", " ")
        if len(h.description) > 120:
            desc += "..."
        line = f"[{sev}] {h.id}: {h.title} @ {h.location} — {desc}"
        if total + len(line) > max_chars:
            lines.append(f"... and {len(sorted_h) - len(lines)} more findings (truncated)")
            break
        lines.append(line)
        total += len(line) + 1  # +1 for newline

    return "\n".join(lines)


def select_hunters_for_pass2(
    hypotheses: list[Hypothesis],
    all_hunters: list[tuple[str, Callable]],
) -> list[tuple[str, Callable]]:
    """
    Select which hunters should re-run in Pass 2 based on domain interactions.

    A hunter is selected if:
      (a) it produced findings in Pass 1, OR
      (b) another hunter that produced findings lists this hunter as interacting

    Returns a subset of all_hunters.
    """
    # Which hunters produced findings?
    active_hunters: set[str] = set()
    for h in hypotheses:
        agent = h.hunter_agent
        # Normalize: "GasDoSHunter" from hunter_agent field
        active_hunters.add(agent)

    # Which hunters should re-run due to domain interactions?
    rerun_hunters: set[str] = set(active_hunters)
    for active in active_hunters:
        interactions = DOMAIN_INTERACTIONS.get(active, set())
        rerun_hunters.update(interactions)

    # Match against the actual hunter list by checking if hunter name is a substring
    selected: list[tuple[str, Callable]] = []
    for label, fn in all_hunters:
        # label is like "🔓 AccessControl" or "🏛️ Governance"
        # hunter_agent is like "AccessControlHunter" or "GovernanceHunter"
        # Match by checking if any rerun hunter name contains the label's key word
        label_clean = label.strip()
        # Remove emoji prefix
        for ch in label_clean:
            if ch.isalpha():
                break
            label_clean = label_clean[1:]
        label_clean = label_clean.strip()

        for rerun in rerun_hunters:
            # Check if label keyword appears in the hunter name or vice versa
            if (label_clean.lower().replace("/", "").replace(" ", "")
                    in rerun.lower().replace("hunter", "")):
                selected.append((label, fn))
                break
            if (rerun.lower().replace("hunter", "")
                    in label_clean.lower().replace("/", "").replace(" ", "")):
                selected.append((label, fn))
                break

    return selected
