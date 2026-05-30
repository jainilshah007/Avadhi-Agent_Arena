"""
avadhi/agents/chain_analysis.py — Phase 3b: Compound Exploit Chain Detector.

Takes the surviving post-Critic hypotheses and looks for cases where two
independent findings can be combined into a higher-severity compound attack:

  Attack A creates the precondition for Attack B → Chain: A → B

Examples:
  - oracle_manipulation (price skew) + accounting_error (unbounded borrow)
    → drain protocol reserves in one flash loan
  - access_control (unprotected admin fn) + proxy_reinitialization
    → permanent logic contract takeover

Output: A list of CompoundExploit objects that are injected back into the
report with an elevated severity and a synthesized attack narrative.
"""
from __future__ import annotations

import json
import time
from typing import Any

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.schemas import Hypothesis, Severity, Confidence
from avadhi.utils.llm import get_llm
from avadhi.utils.logging import AuditLogger


# ---------------------------------------------------------------------------
# Schema for compound findings
# ---------------------------------------------------------------------------

class CompoundExploit:
    """Represents a discovered exploit chain between two individual findings."""

    def __init__(
        self,
        chain_id: str,
        title: str,
        hypothesis_a: Hypothesis,
        hypothesis_b: Hypothesis,
        chain_narrative: str,
        elevated_severity: Severity,
        impact_amplification: str,
    ):
        self.chain_id = chain_id
        self.title = title
        self.hypothesis_a = hypothesis_a
        self.hypothesis_b = hypothesis_b
        self.chain_narrative = chain_narrative
        self.elevated_severity = elevated_severity
        self.impact_amplification = impact_amplification

    def to_markdown(self) -> str:
        """Serialize as a markdown finding block."""
        lines = [
            f"## ⛓️  {self.chain_id}: {self.title}",
            "",
            f"**Severity:** {self.elevated_severity.value} *(elevated from component findings)*  ",
            f"**Chain:** `{self.hypothesis_a.id}` → `{self.hypothesis_b.id}`  ",
            "",
            "### Compound Attack Narrative",
            "",
            self.chain_narrative,
            "",
            "### Impact Amplification",
            "",
            self.impact_amplification,
            "",
            "### Component Findings",
            "",
            f"- **A:** [{self.hypothesis_a.severity.value}] {self.hypothesis_a.title} @ `{self.hypothesis_a.location}`",
            f"- **B:** [{self.hypothesis_b.severity.value}] {self.hypothesis_b.title} @ `{self.hypothesis_b.location}`",
            "",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

CHAIN_SYSTEM = """You are a world-class DeFi security researcher performing COMPOUND EXPLOIT analysis.

You are given two independently confirmed vulnerability hypotheses (A and B) from a unified security graph.

Your task is to determine whether an attacker can chain these two bugs together in a single transaction
or multi-step exploit to achieve a WORSE outcome than each bug can achieve alone.

Think like an adversarial researcher. Classic chains include:
- Flash loan → price oracle manipulation (A) → borrow against inflated collateral (B) → profit
- Governance takeover (A) → upgrade contract logic (B) → drain treasury
- Uninitialized proxy (A) → selfdestruct implementation (B) → brick protocol
- Missing access check (A) → front-run initialization (B) → steal ownership permanently

Return a JSON object with this exact structure:
{
  "chainable": true | false,
  "title": "Brief title for the compound exploit if chainable, else empty string",
  "elevated_severity": "Critical" | "High" | "Medium" | "Low",
  "chain_narrative": "Step-by-step attack walkthrough combining both bugs (3–6 steps)",
  "impact_amplification": "Why the compound attack is worse than each bug alone",
  "confidence": "High" | "Medium" | "Low"
}

If the bugs are completely independent and cannot amplify each other, set "chainable": false.
Do NOT force connections that don't logically exist.
"""


# ---------------------------------------------------------------------------
# Core analysis logic
# ---------------------------------------------------------------------------

def _is_candidate_pair(a: Hypothesis, b: Hypothesis) -> bool:
    """Fast pre-filter: only send promising pairs to the LLM."""
    if a.id == b.id:
        return False

    # Both must be at least Medium severity to be worth chaining
    sev_rank = {
        Severity.CRITICAL: 4, Severity.HIGH: 3,
        Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0
    }
    if sev_rank[a.severity] < 2 or sev_rank[b.severity] < 2:
        return False

    # Prefer cross-category pairs (intra-category pairs rarely chain interestingly)
    if a.category == b.category:
        return False

    # Heuristic: categories that commonly chain together
    CHAIN_MAP: dict[str, list[str]] = {
        "Oracle/Randomness":   ["Accounting", "Governance", "External Call"],
        "Access Control":      ["Proxy", "Governance", "Reentrancy"],
        "Proxy":               ["Access Control", "External Call"],
        "Accounting":          ["Oracle/Randomness", "Flash Loan"],
        "Reentrancy":          ["Accounting", "External Call"],
        "Governance":          ["Access Control", "Accounting"],
        "External Call":       ["Reentrancy", "Access Control"],
        "Cryptography":        ["Access Control", "Governance"],
        "DeFi Math":           ["Oracle/Randomness", "Accounting"],
    }
    a_partners = CHAIN_MAP.get(a.category, [])
    if b.category in a_partners:
        return True
    b_partners = CHAIN_MAP.get(b.category, [])
    if a.category in b_partners:
        return True

    return False


def _build_pair_prompt(a: Hypothesis, b: Hypothesis) -> str:
    return f"""## Finding A
ID: {a.id}
Title: {a.title}
Severity: {a.severity.value}
Category: {a.category}
Location: {a.location}

Attack Scenario:
{a.attack_scenario}

Impact: {a.impact}

---

## Finding B
ID: {b.id}
Title: {b.title}
Severity: {b.severity.value}
Category: {b.category}
Location: {b.location}

Attack Scenario:
{b.attack_scenario}

Impact: {b.impact}

---

Can an attacker chain Finding A and Finding B into a compound exploit?
Return the JSON object as specified."""


def _parse_chain_response(text: str) -> dict[str, Any]:
    for marker in ("```json", "```"):
        if marker in text:
            try:
                start = text.index(marker) + len(marker)
                end = text.index("```", start)
                return json.loads(text[start:end].strip())
            except Exception:
                pass
    for i, ch in enumerate(text):
        if ch == "{":
            depth = 0
            for j in range(i, len(text)):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[i : j + 1])
                    except Exception:
                        break
            break
    return {"chainable": False}


def run_chain_analysis(
    hypotheses: list[Hypothesis],
    logger: AuditLogger | None = None,
    verbose: bool = False,
) -> list[CompoundExploit]:
    """
    Phase 3b: Identify compound exploit chains between surviving findings.

    Iterates over all candidate pairs (filtered by heuristic), calls the LLM
    to check for chainability, and returns CompoundExploit objects for confirmed
    chains only.
    """
    if len(hypotheses) < 2:
        return []

    llm = get_llm()
    chains: list[CompoundExploit] = []
    chain_counter = 1
    checked_pairs: set[frozenset[str]] = set()

    for i, hyp_a in enumerate(hypotheses):
        for j, hyp_b in enumerate(hypotheses):
            if i >= j:
                continue
            pair_key = frozenset({hyp_a.id, hyp_b.id})
            if pair_key in checked_pairs:
                continue
            checked_pairs.add(pair_key)

            if not _is_candidate_pair(hyp_a, hyp_b):
                continue

            if verbose:
                print(f"  ⛓️  Testing chain: {hyp_a.id} → {hyp_b.id}")

            start = time.time()
            from avadhi.agents.hunters.base import _invoke_with_backoff
            try:
                response = _invoke_with_backoff(
                    llm,
                    [
                        SystemMessage(content=CHAIN_SYSTEM),
                        HumanMessage(content=_build_pair_prompt(hyp_a, hyp_b)),
                    ],
                    hunter_name=f"Chain:{hyp_a.id}-{hyp_b.id}",
                    max_retries=4
                )
                latency_ms = int((time.time() - start) * 1000)
                text = response.content if hasattr(response, "content") else str(response)

                if logger:
                    usage = getattr(response, "usage_metadata", {}) or {}
                    logger.log_llm_call(
                        agent="ChainAnalysis",
                        model=str(getattr(llm, "model", "unknown")),
                        phase="chain_analysis",
                        prompt_tokens=usage.get("input_tokens", 0),
                        completion_tokens=usage.get("output_tokens", 0),
                        latency_ms=latency_ms,
                    )

                parsed = _parse_chain_response(text)
                if not parsed.get("chainable", False):
                    continue

                # Determine elevated severity
                raw_sev = parsed.get("elevated_severity", "High")
                try:
                    elevated = Severity(raw_sev)
                except ValueError:
                    elevated = Severity.HIGH

                compound = CompoundExploit(
                    chain_id=f"CHAIN-{chain_counter:03d}",
                    title=parsed.get("title", f"Compound: {hyp_a.category} + {hyp_b.category}"),
                    hypothesis_a=hyp_a,
                    hypothesis_b=hyp_b,
                    chain_narrative=parsed.get("chain_narrative", ""),
                    elevated_severity=elevated,
                    impact_amplification=parsed.get("impact_amplification", ""),
                )
                chains.append(compound)
                chain_counter += 1

                if verbose:
                    print(f"    OK Chain confirmed: [{elevated.value}] {compound.title}")

            except Exception as e:
                if verbose:
                    print(f"    WARNING  Chain test failed: {e}")
                continue

    if verbose:
        print(f"\n  📊 Chain Analysis: {len(chains)} compound exploits found from {len(checked_pairs)} candidate pairs")

    return chains
