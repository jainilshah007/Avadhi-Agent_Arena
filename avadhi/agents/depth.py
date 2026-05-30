"""
avadhi/agents/depth.py — Depth Analysis Phase (Phase 2c).

Inspired by Plamen/BEAST Phase 5: after breadth hunting surfaces High/Critical
hypotheses, this phase spawns a targeted depth agent per finding that:

  1. Pulls the FULL source of every function involved in the hypothesis
  2. Re-queries RAG with the specific hypothesis text (not a generic query)
  3. Injects protocol invariants relevant to this finding
  4. Asks the LLM to:
     - Confirm or refute the finding with exact line evidence
     - Identify boundary values / concrete conditions
     - Find adjacent functions with the same bug pattern
     - Suggest the minimal fix

Findings that are confirmed get upgraded to Confidence.HIGH.
Findings that are refuted are dropped from the result set.
New adjacent findings are added as new hypotheses.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.graph import SecurityGraph, FUNCTION
from avadhi.core.schemas import Hypothesis, Severity, Confidence
from avadhi.agents.hunters.base import (
    get_source_for_functions,
    _invoke_with_backoff,
    _parse_hypotheses,
)
from avadhi.config import HUNTER_CONCURRENCY, DEPTH_CONCURRENCY

if TYPE_CHECKING:
    from avadhi.utils.logging import AuditLogger


DEPTH_SYSTEM_PROMPT = """You are an elite smart contract security auditor performing DEPTH ANALYSIS on a suspected vulnerability.

You are given:
1. A specific vulnerability hypothesis from the breadth scanning phase
2. The FULL source code of every function involved
3. Relevant RAG context (similar past bugs from the knowledge base)
4. Protocol invariants that must hold

Your job is to CONFIRM or REFUTE this finding with surgical precision:

## If CONFIRMING:
- Find the EXACT lines that create the bug
- State the PRECISE conditions under which it triggers
- Give the boundary values (exact amounts, timestamps, addresses)
- Show the exact sequence of calls that exploits it
- Check if the SAME bug pattern exists in adjacent/similar functions too

## If REFUTING:
- Explain exactly WHY the hypothesis is wrong
- Identify the protection mechanism that prevents exploitation
- If the root concern is real but the finding description is wrong, describe what the actual bug IS

## Output Format:
Return a JSON object:
```json
{
  "verdict": "CONFIRMED" | "REFUTED" | "PARTIALLY_CONFIRMED",
  "confidence_reason": "Why you are confident in this verdict",
  "confirmed_finding": {
    "id": "depth-refined id",
    "title": "Refined title if different",
    "severity": "Critical|High|Medium|Low|Info",
    "category": "Category",
    "description": "Precise description with exact line references",
    "location": "Contract.function:Lxxx-Lyyy",
    "attack_scenario": "Step-by-step with exact values",
    "preconditions": ["Exact conditions required"],
    "impact": "Quantified impact",
    "evidence": ["Exact code line references"]
  },
  "adjacent_findings": [
    {
      "title": "Same pattern found in adjacent function",
      "location": "Contract.otherFunction:Lxxx",
      "description": "How it manifests here",
      "severity": "High|Medium|Low"
    }
  ],
  "refutation_reason": "Only if REFUTED: exact reason why this is not exploitable"
}
```

Be precise. Be surgical. Every claim must be tied to specific lines of code."""


def run_depth_analysis(
    hypotheses: list[Hypothesis],
    sg: SecurityGraph,
    logger: "AuditLogger | None" = None,
    verbose: bool = False,
) -> list[Hypothesis]:
    """
    Phase 2c: Deep targeted analysis of High/Critical hypotheses.

    Args:
        hypotheses: All hypotheses from breadth + cross-feed phases
        sg: SecurityGraph with source files and metadata
        logger: Optional audit logger
        verbose: Print progress

    Returns:
        Refined list of hypotheses with:
        - Refuted findings removed
        - Confirmed findings upgraded to Confidence.HIGH
        - New adjacent findings added
    """
    # Only depth-analyze High and Critical — Medium/Low aren't worth the tokens
    high_value = [
        h for h in hypotheses
        if h.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    lower_value = [
        h for h in hypotheses
        if h.severity not in (Severity.CRITICAL, Severity.HIGH)
    ]

    if not high_value:
        if verbose:
            print("  ℹ️  DepthAnalyzer: No High/Critical hypotheses to analyze")
        return hypotheses

    if verbose:
        print(f"   DepthAnalyzer: deep-analyzing {len(high_value)} High/Critical findings...")

    # Get RAG pool if available
    _rag_pool = sg.metadata.get("rag_pool")
    invariants = sg.metadata.get("invariants", [])
    invariant_text = "\n".join(f"- {inv}" for inv in invariants[:8]) if invariants else "(none extracted)"

    def _analyze_one(hyp: Hypothesis) -> tuple[str, dict | None]:
        """Run depth analysis on a single hypothesis. Returns (hyp.id, result_dict|None)."""
        try:
            # ── Find relevant function IDs from the location ────────────────
            location_contract = hyp.location.split(".")[0] if hyp.location else ""
            location_fn = hyp.location.split(".")[1].split(":")[0] if "." in hyp.location else ""

            relevant_fn_ids = []
            for fn_id, data in sg.get_nodes_by_type(FUNCTION):
                fn_contract = data.get("contract", "")
                fn_name = data.get("name", "")
                # Primary: exact match
                if fn_contract == location_contract and fn_name == location_fn:
                    relevant_fn_ids.insert(0, fn_id)  # highest priority
                # Secondary: same contract
                elif fn_contract == location_contract:
                    relevant_fn_ids.append(fn_id)

            # Get FULL source for relevant functions (larger budget for depth)
            source = get_source_for_functions(sg, relevant_fn_ids[:12], max_chars=12_000)

            # ── Second-pass RAG: query with hypothesis text ─────────────────
            rag_section = ""
            if _rag_pool is not None:
                try:
                    from avadhi.rag.context import build_rag_context_sync
                    _hyp_query = f"{hyp.title} {hyp.description[:300]}"
                    rag_context = build_rag_context_sync(
                        _hyp_query,
                        _rag_pool,
                        top_k=4,
                        use_hyde=False,       # hypothesis IS specific — no expansion needed
                        use_reranker=True,    # rerank for precision
                        include_methodology=True,
                        include_protocol=False,
                        max_chars=2000,
                    )
                    if rag_context:
                        rag_section = f"\n\n## Similar Past Bugs (RAG)\n{rag_context}"
                except Exception:
                    pass

            # ── Build the depth prompt ──────────────────────────────────────
            prompt = f"""## Hypothesis Under Analysis

**ID:** {hyp.id}
**Title:** {hyp.title}
**Severity:** {hyp.severity.value}
**Category:** {hyp.category}
**Location:** {hyp.location}
**Description:** {hyp.description}
**Attack Scenario:** {hyp.attack_scenario}
**Evidence claimed:** {'; '.join(hyp.evidence[:4])}

## Protocol Invariants
{invariant_text}

## Full Source Code of Involved Functions
{source}
{rag_section}

---

Analyze this hypothesis and return your JSON verdict."""

            from avadhi.utils.llm import get_llm
            llm = get_llm()
            response = _invoke_with_backoff(
                llm,
                [SystemMessage(content=DEPTH_SYSTEM_PROMPT), HumanMessage(content=prompt)],
                hunter_name=f"Depth:{hyp.id}",
            )
            response_text = response.content if hasattr(response, "content") else str(response)

            # Parse the verdict JSON
            import json
            result = None
            try:
                # Extract JSON from markdown block
                text = response_text
                if "```json" in text:
                    s = text.index("```json") + 7
                    e = text.index("```", s) if "```" in text[s:] else len(text)
                    text = text[s:e].strip()
                elif "```" in text:
                    s = text.index("```") + 3
                    e = text.index("```", s) if "```" in text[s:] else len(text)
                    text = text[s:e].strip()
                result = json.loads(text)
            except (json.JSONDecodeError, ValueError, IndexError):
                pass

            return hyp.id, result

        except Exception as exc:
            if verbose:
                print(f"  WARNING  Depth:{hyp.id} failed: {exc}")
            return hyp.id, None

    # ── Run depth analysis in parallel (same concurrency as hunters) ─────────
    result_map: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=min(DEPTH_CONCURRENCY, len(high_value))) as pool:
        futs = {pool.submit(_analyze_one, h): h for h in high_value}
        for fut in as_completed(futs):
            hyp_id, result = fut.result()
            result_map[hyp_id] = result
            if verbose:
                verdict = result.get("verdict", "ERROR") if result else "ERROR"
                print(f"  {'OK' if verdict == 'CONFIRMED' else 'WARNING' if verdict == 'PARTIALLY_CONFIRMED' else 'FAILED'} "
                      f"Depth:{hyp_id} → {verdict}")

    # ── Process results ───────────────────────────────────────────────────────
    final_high: list[Hypothesis] = []
    adjacent_findings: list[Hypothesis] = []
    refuted_count = 0
    confirmed_count = 0

    for hyp in high_value:
        result = result_map.get(hyp.id)
        if result is None:
            # Analysis failed — keep the finding as-is (don't discard)
            final_high.append(hyp)
            continue

        verdict = result.get("verdict", "CONFIRMED")

        if verdict == "REFUTED":
            refuted_count += 1
            refutation_reason = result.get("refutation_reason", "")
            # Attach refutation as critic note and downgrade
            hyp.critic_challenges = [f"[DepthAnalyzer REFUTED]: {refutation_reason}"]
            # Drop from final list — will be excluded
            continue

        # CONFIRMED or PARTIALLY_CONFIRMED: upgrade confidence and refine details
        confirmed_count += 1
        confirmed = result.get("confirmed_finding", {})
        if confirmed:
            # Refine the hypothesis with depth-analysis details
            if confirmed.get("description"):
                hyp.description = confirmed["description"]
            if confirmed.get("attack_scenario"):
                hyp.attack_scenario = confirmed["attack_scenario"]
            if confirmed.get("evidence"):
                hyp.evidence = confirmed["evidence"]
            if confirmed.get("location"):
                hyp.location = confirmed["location"]

        hyp.confidence = Confidence.HIGH if verdict == "CONFIRMED" else Confidence.MEDIUM
        final_high.append(hyp)

        # Add adjacent findings as new hypotheses
        for adj in result.get("adjacent_findings", []):
            if not adj.get("title") or not adj.get("location"):
                continue
            try:
                adj_hyp = Hypothesis(
                    id=f"DEPTH-ADJ-{len(adjacent_findings)+1:03d}",
                    title=adj["title"],
                    severity=_parse_severity_str(adj.get("severity", "Medium")),
                    confidence=Confidence.UNCERTAIN,
                    category=hyp.category,
                    description=adj.get("description", ""),
                    location=adj["location"],
                    attack_scenario="Adjacent pattern — see parent finding for scenario",
                    preconditions=[],
                    impact="Same as parent finding",
                    evidence=[f"Identified as adjacent pattern to {hyp.id}"],
                    hunter_agent="DepthAnalyzer",
                )
                adjacent_findings.append(adj_hyp)
            except Exception:
                continue

    if verbose:
        print(f"    DepthAnalyzer: {confirmed_count} confirmed, "
              f"{refuted_count} refuted, "
              f"{len(adjacent_findings)} adjacent findings")

    if logger:
        logger.log_phase(
            "depth_analysis", "complete",
            confirmed=confirmed_count,
            refuted=refuted_count,
            adjacent=len(adjacent_findings),
        )

    return final_high + adjacent_findings + lower_value


def _parse_severity_str(s: str) -> Severity:
    s_lower = s.lower().strip()
    for sev in Severity:
        if sev.value.lower() == s_lower:
            return sev
    return Severity.MEDIUM
