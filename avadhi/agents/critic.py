"""
avadhi/agents/critic.py — Critic / Debate Agent (Phase 3).

For each Hypothesis produced by the hunters, the Critic LLM is given the
full source evidence and asked to steelman the DEFENCE: can any on-chain
condition, modifier, access check, or protocol invariant make the attack
impossible?

Outcomes per hypothesis:
  CONFIRMED  — Critic found no valid defence; finding stands.
  CONTESTED  — Some mitigating factor exists but does not fully block the
               attack; finding stands with a lower confidence note.
  REFUTED    — A clear on-chain guard prevents the attack; finding is
               dropped from the final report.

Only CONFIRMED and CONTESTED hypotheses pass through to VerifiedFindings.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.graph import SecurityGraph
from avadhi.core.schemas import Hypothesis, CriticChallenge, Confidence
from avadhi.agents.hunters.base import get_source_for_functions
from avadhi.utils.llm import get_llm
from avadhi.utils.logging import AuditLogger


CRITIC_SYSTEM = """You are a senior smart contract security CRITIC.

You will be shown a vulnerability hypothesis produced by a hunter agent,
along with the actual source code and security graph evidence.

Your ONLY job is to find reasons the hypothesis might be WRONG:
- Is the vulnerable code path actually reachable by an attacker?
- Does the function have a modifier, require-check, or access control that
  blocks the attack scenario described?
- Does the protocol architecture prevent the preconditions from being met?
- Is the described impact overstated or impossible given on-chain constraints?
- Does a reentrancy guard, time-lock, or other defence mitigate the finding?

Be SPECIFIC. Reference exact function names, modifier names, require() checks,
or state conditions that prevent the attack. Vague rebuttals do not count.

Return a JSON object with this exact structure:
{
  "verdict": "CONFIRMED" | "CONTESTED" | "REFUTED",
  "confidence_after": "Confirmed" | "Contested" | "Uncertain" | "Refuted",
  "challenge": "One-paragraph summary of your critique",
  "counter_evidence": ["specific code fact 1", "specific code fact 2"],
  "reasoning": "Detailed step-by-step analysis of why the attack works or doesn't"
}

Verdict guide:
  CONFIRMED  — You cannot find a valid on-chain defence. The attack is plausible.
  CONTESTED  — You found a partial mitigation but the attack may still work under
               specific conditions. Mention the conditions precisely.
  REFUTED    — You found a clear, unconditional guard that prevents the attack.
               State exactly which check/modifier blocks it."""


def run_critic(
    hypotheses: list[Hypothesis],
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
) -> tuple[list[Hypothesis], list[CriticChallenge]]:
    """
    Challenge every hypothesis with the Critic LLM in parallel.

    Returns:
        (surviving_hypotheses, challenges)
        surviving_hypotheses — hypotheses not REFUTED (confidence updated)
        challenges           — all CriticChallenge records for the debate log
    """
    if not hypotheses:
        return [], []

    from avadhi.config import CRITIC_CONCURRENCY

    # Run all critiques in parallel
    results: dict[str, tuple[CriticChallenge, Confidence]] = {}

    def _run_one(h: Hypothesis):
        if verbose:
            print(f"   Critic reviewing: [{h.severity.value}] {h.title}")
        challenge, confidence = _critique_hypothesis(h, sg, logger, verbose)
        return h.id, challenge, confidence

    with ThreadPoolExecutor(max_workers=CRITIC_CONCURRENCY) as pool:
        futures = {pool.submit(_run_one, h): h for h in hypotheses}
        for fut in as_completed(futures):
            hyp_id, challenge, confidence = fut.result()
            results[hyp_id] = (challenge, confidence)

    # Rebuild in original order
    surviving: list[Hypothesis] = []
    challenges: list[CriticChallenge] = []

    for h in hypotheses:
        challenge, new_confidence = results[h.id]
        challenges.append(challenge)
        h_updated = h.model_copy(update={"confidence": new_confidence})

        if new_confidence == Confidence.REFUTED:
            if verbose:
                print(f"  FAILED REFUTED: {challenge.challenge[:80]}...")
        else:
            if verbose:
                label = "OK CONFIRMED" if new_confidence == Confidence.CONFIRMED else "WARNING  CONTESTED"
                print(f"  {label}")
            surviving.append(h_updated)

    if verbose:
        refuted = len(hypotheses) - len(surviving)
        print(f"\n  Critic: {len(surviving)}/{len(hypotheses)} hypotheses survived "
              f"({refuted} refuted)")

    return surviving, challenges


def _critique_hypothesis(
    h: Hypothesis,
    sg: SecurityGraph,
    logger: AuditLogger | None,
    verbose: bool,
) -> tuple[CriticChallenge, Confidence]:
    """Run one LLM critique call for a single hypothesis."""

    # Build focused source context for this finding
    source = _get_finding_source(h, sg)

    prompt = f"""## Hypothesis to Critique

**ID:** {h.id}
**Title:** {h.title}
**Severity:** {h.severity.value}
**Category:** {h.category}
**Location:** {h.location}

**Description:**
{h.description}

**Attack Scenario:**
{h.attack_scenario}

**Evidence cited by hunter:**
{chr(10).join(f"- {e}" for e in h.evidence)}

**Preconditions claimed:**
{chr(10).join(f"- {p}" for p in h.preconditions)}

---

## Source Code at Location

{source}

---

Analyse the above. Can an attacker actually execute this attack, or does an
on-chain guard prevent it? Return your verdict as the JSON object specified."""

    llm = get_llm()
    start = time.time()

    from avadhi.agents.hunters.base import _invoke_with_backoff

    try:
        response = _invoke_with_backoff(
            llm,
            [SystemMessage(content=CRITIC_SYSTEM), HumanMessage(content=prompt)],
            hunter_name=f"Critic:{h.id}",
            max_retries=4
        )
        latency_ms = int((time.time() - start) * 1000)
        text = response.content if hasattr(response, "content") else str(response)

        if logger:
            usage = getattr(response, "usage_metadata", {}) or {}
            logger.log_llm_call(
                agent="Critic",
                model=str(getattr(llm, "model", "unknown")),
                phase="debate",
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                latency_ms=latency_ms,
            )

        parsed = _parse_critic_response(text)
        verdict_str = parsed.get("verdict", "CONFIRMED")
        confidence = _map_confidence(verdict_str)

        challenge = CriticChallenge(
            hypothesis_id=h.id,
            challenge=parsed.get("challenge", ""),
            counter_evidence=parsed.get("counter_evidence", []),
            verdict=confidence,
            reasoning=parsed.get("reasoning", ""),
        )
        return challenge, confidence

    except Exception as e:
        # On failure, conservatively keep the hypothesis as UNCERTAIN
        challenge = CriticChallenge(
            hypothesis_id=h.id,
            challenge=f"Critic call failed: {e}",
            verdict=Confidence.UNCERTAIN,
        )
        return challenge, Confidence.UNCERTAIN


def _get_finding_source(h: Hypothesis, sg: SecurityGraph) -> str:
    """Get source code most relevant to the finding location."""
    # Try to extract contract.function from location string
    location = h.location  # e.g. "JackpotBridgeManager._bridgeFunds"
    fn_ids: list[str] = []

    if "." in location:
        parts = location.split(":")[0].split(".")  # strip line refs
        if len(parts) >= 2:
            contract = parts[0].strip()
            fn_name = parts[1].strip()
            fn_id = f"fn:{contract}.{fn_name}"
            if sg.G.has_node(fn_id):
                fn_ids.append(fn_id)
                # Also include functions that this one calls (via CALLS edges)
                callees = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                           if d.get("type") == "CALLS" and sg.G.has_node(v)]
                fn_ids.extend(callees[:3])

    if fn_ids:
        return get_source_for_functions(sg, fn_ids, max_chars=6000)

    # Fallback: search source_files for any snippet mentioning the location
    source_files = sg.metadata.get("source_files", {})
    for content in source_files.values():
        if location.split(".")[0] in content:
            # Return first 3000 chars of the relevant file
            return content[:3000]

    return "(source not available)"


def _parse_critic_response(text: str) -> dict[str, Any]:
    """Extract JSON object from LLM response."""
    # Try code block
    for marker in ("```json", "```"):
        if marker in text:
            try:
                start = text.index(marker) + len(marker)
                end = text.index("```", start)
                return json.loads(text[start:end].strip())
            except Exception:
                pass

    # Try raw JSON object
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
                        return json.loads(text[i:j + 1])
                    except Exception:
                        break
            break

    return {"verdict": "CONFIRMED", "challenge": text[:200], "counter_evidence": [], "reasoning": text}


def _map_confidence(verdict: str) -> Confidence:
    v = verdict.upper().strip()
    if v == "REFUTED":
        return Confidence.REFUTED
    if v == "CONTESTED":
        return Confidence.CONTESTED
    return Confidence.CONFIRMED
