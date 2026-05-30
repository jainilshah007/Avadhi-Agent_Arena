"""
avadhi/agents/judge.py — 4-Gate Judging System (replaces naive critic).

Inspired by Pashov's sequential judging gates:
  Gate 1: REFUTATION  — construct the strongest counter-argument
  Gate 2: REACHABILITY — prove the vulnerable state is reachable in deployment
  Gate 3: TRIGGER      — prove an unprivileged actor can execute the attack
  Gate 4: IMPACT       — prove material harm to an identifiable victim

Confidence scoring: start at 100, deduct for weaknesses.
  >= 80 → CONFIRMED
  50-79 → CONTESTED
  < 50  → REFUTED (dropped)

This replaces the single-call critic with structured adversarial reasoning.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.graph import SecurityGraph
from avadhi.core.schemas import Hypothesis, CriticChallenge, Confidence
from avadhi.agents.hunters.base import get_source_for_functions, _invoke_with_backoff
from avadhi.utils.llm import get_llm
from avadhi.config import CRITIC_CONCURRENCY

if TYPE_CHECKING:
    from avadhi.utils.logging import AuditLogger


JUDGE_SYSTEM = """You are a senior smart contract security JUDGE applying a 4-gate validation framework.

For each vulnerability hypothesis, you must evaluate 4 sequential gates. Each gate has specific criteria. A finding must pass ALL gates to be confirmed.

## Gate 1: REFUTATION
Construct the STRONGEST possible counter-argument against this finding.
- Is there a require() check, modifier, or access control that blocks the attack?
- Is the code path actually reachable by an external caller?
- Does the protocol architecture prevent the preconditions?
- Is there a time-lock, reentrancy guard, or other defence?
If you find a CONCRETE, unconditional guard: the finding fails Gate 1.

## Gate 2: REACHABILITY
Prove the vulnerable state can exist in a live deployment.
- Can the preconditions actually be met on-chain?
- Does the contract need to be in a specific state? Can an attacker get it there?
- Are there initialization checks or deployment constraints that prevent the state?
If the vulnerable state is unreachable: the finding fails Gate 2.

## Gate 3: TRIGGER
Prove an unprivileged actor (not admin/owner) can execute the attack profitably.
- Does the attacker need a privileged role?
- Is the attack economically viable (gas costs vs. gain)?
- Can the attacker front-run or time the attack?
If only a trusted admin can trigger the issue, DOWNGRADE severity but don't reject.

## Gate 4: IMPACT
Prove material harm to an identifiable victim.
- What specific loss occurs? (funds, locked assets, DoS, griefing)
- Is the impact bounded or unbounded?
- Does the impact affect only the attacker (self-harm) or other users?
If impact is self-harm only or negligible: the finding fails Gate 4.

## Scoring
Start at 100 points. Deduct:
- Partial code path (not fully traced):     -20
- Bounded/limited impact:                   -15
- Requires specific unlikely state:         -10
- Only exploitable by semi-trusted role:    -10
- High gas cost relative to gain:           -10

Return a JSON object:
```json
{
  "gate_1_refutation": {
    "passed": true/false,
    "reasoning": "Specific counter-argument or why none exists",
    "counter_evidence": ["exact code references"]
  },
  "gate_2_reachability": {
    "passed": true/false,
    "reasoning": "How the vulnerable state is/isn't reachable"
  },
  "gate_3_trigger": {
    "passed": true/false,
    "reasoning": "Who can trigger and at what cost"
  },
  "gate_4_impact": {
    "passed": true/false,
    "reasoning": "What harm occurs and to whom"
  },
  "confidence_score": 0-100,
  "verdict": "CONFIRMED" | "CONTESTED" | "REFUTED",
  "summary": "One-paragraph final assessment"
}
```"""


def run_judge(
    hypotheses: list[Hypothesis],
    sg: SecurityGraph,
    logger: "AuditLogger | None" = None,
    verbose: bool = False,
) -> tuple[list[Hypothesis], list[CriticChallenge]]:
    """
    Run 4-gate judging on all hypotheses.

    Returns:
        (surviving_hypotheses, challenges)
    """
    if not hypotheses:
        return [], []

    results: dict[str, tuple[CriticChallenge, Confidence, int]] = {}

    def _judge_one(h: Hypothesis):
        if verbose:
            print(f"   Judge reviewing: [{h.severity.value}] {h.title}")
        challenge, confidence, score = _judge_hypothesis(h, sg, logger, verbose)
        return h.id, challenge, confidence, score

    with ThreadPoolExecutor(max_workers=CRITIC_CONCURRENCY) as pool:
        futures = {pool.submit(_judge_one, h): h for h in hypotheses}
        for fut in as_completed(futures):
            hyp_id, challenge, confidence, score = fut.result()
            results[hyp_id] = (challenge, confidence, score)

    surviving: list[Hypothesis] = []
    challenges: list[CriticChallenge] = []

    for h in hypotheses:
        challenge, new_confidence, score = results[h.id]
        challenges.append(challenge)
        h_updated = h.model_copy(update={"confidence": new_confidence})

        if new_confidence == Confidence.REFUTED:
            if verbose:
                print(f"  REFUTED (score={score}): {h.title[:60]}...")
        else:
            if verbose:
                label = "CONFIRMED" if new_confidence == Confidence.CONFIRMED else "CONTESTED"
                print(f"  {label} (score={score}): {h.title[:60]}...")
            surviving.append(h_updated)

    if verbose:
        refuted = len(hypotheses) - len(surviving)
        print(f"\n  Judge: {len(surviving)}/{len(hypotheses)} survived ({refuted} refuted)")

    return surviving, challenges


def _judge_hypothesis(
    h: Hypothesis,
    sg: SecurityGraph,
    logger: "AuditLogger | None",
    verbose: bool,
) -> tuple[CriticChallenge, Confidence, int]:
    """Run 4-gate judging on a single hypothesis."""

    source = _get_finding_source(h, sg)

    prompt = f"""## Hypothesis Under Judgment

**ID:** {h.id}
**Title:** {h.title}
**Severity:** {h.severity.value}
**Category:** {h.category}
**Location:** {h.location}
**Hunter:** {h.hunter_agent}

**Description:**
{h.description}

**Attack Scenario:**
{h.attack_scenario}

**Evidence:**
{chr(10).join(f"- {e}" for e in h.evidence)}

**Preconditions:**
{chr(10).join(f"- {p}" for p in h.preconditions)}

**Impact:**
{h.impact}

---

## Source Code

{source}

---

Apply the 4-gate framework. Return your JSON verdict."""

    llm = get_llm()
    start = time.time()

    try:
        response = _invoke_with_backoff(
            llm,
            [SystemMessage(content=JUDGE_SYSTEM), HumanMessage(content=prompt)],
            hunter_name=f"Judge:{h.id}",
            max_retries=4,
        )
        latency_ms = int((time.time() - start) * 1000)
        text = response.content if hasattr(response, "content") else str(response)

        if logger:
            usage = getattr(response, "usage_metadata", {}) or {}
            logger.log_llm_call(
                agent="Judge",
                model=str(getattr(llm, "model", "unknown")),
                phase="judging",
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                latency_ms=latency_ms,
            )

        parsed = _parse_judge_response(text)
        score = parsed.get("confidence_score", 70)
        verdict = parsed.get("verdict", "CONFIRMED").upper()

        # Map verdict to confidence
        if verdict == "REFUTED" or score < 50:
            confidence = Confidence.REFUTED
        elif verdict == "CONTESTED" or score < 80:
            confidence = Confidence.CONTESTED
        else:
            confidence = Confidence.CONFIRMED

        # Build summary from gates
        gate_summaries = []
        for gate_key in ["gate_1_refutation", "gate_2_reachability",
                         "gate_3_trigger", "gate_4_impact"]:
            gate = parsed.get(gate_key, {})
            if isinstance(gate, dict):
                passed = "PASS" if gate.get("passed") else "FAIL"
                reasoning = gate.get("reasoning", "")[:100]
                gate_summaries.append(f"{gate_key}: [{passed}] {reasoning}")

        challenge = CriticChallenge(
            hypothesis_id=h.id,
            challenge=parsed.get("summary", ""),
            counter_evidence=gate_summaries,
            verdict=confidence,
            reasoning="\n".join(gate_summaries),
        )
        return challenge, confidence, score

    except Exception as e:
        challenge = CriticChallenge(
            hypothesis_id=h.id,
            challenge=f"Judge call failed: {e}",
            verdict=Confidence.UNCERTAIN,
        )
        return challenge, Confidence.UNCERTAIN, 70


def _get_finding_source(h: Hypothesis, sg: SecurityGraph) -> str:
    """Get source code relevant to the finding location."""
    location = h.location
    fn_ids: list[str] = []

    if "." in location:
        parts = location.split(":")[0].split(".")
        if len(parts) >= 2:
            contract = parts[0].strip()
            fn_name = parts[1].strip()
            fn_id = f"fn:{contract}.{fn_name}"
            if sg.G.has_node(fn_id):
                fn_ids.append(fn_id)
                callees = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                           if d.get("type") == "CALLS" and sg.G.has_node(v)]
                fn_ids.extend(callees[:3])

    if fn_ids:
        return get_source_for_functions(sg, fn_ids, max_chars=6000)

    source_files = sg.metadata.get("source_files", {})
    for content in source_files.values():
        if location.split(".")[0] in content:
            return content[:3000]
    return "(source not available)"


def _parse_judge_response(text: str) -> dict:
    """Extract JSON object from judge LLM response."""
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
                        return json.loads(text[i:j + 1])
                    except Exception:
                        break
            break

    return {
        "verdict": "CONFIRMED",
        "confidence_score": 70,
        "summary": text[:300],
    }
