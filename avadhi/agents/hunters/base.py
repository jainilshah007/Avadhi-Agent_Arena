"""
avadhi/agents/hunters/base.py — Base utilities for hunter agents.

Every hunter follows the same pattern:
  1. Query the SecurityGraph for relevant nodes/edges
  2. Build a focused context string for the LLM
  3. Call the LLM with a hunter-specific system prompt
  4. Parse structured Hypothesis objects from the response
"""
from __future__ import annotations

import json
import time
from typing import Any

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.graph import SecurityGraph
from avadhi.core.schemas import Hypothesis, Severity, Confidence
from avadhi.utils.llm import get_llm
from avadhi.utils.logging import AuditLogger
from avadhi.config import MAX_CONTEXT_CHARS, MAX_SOURCE_CHARS, MAX_RAG_CHARS


def call_hunter(
    hunter_name: str,
    system_prompt: str,
    context: str,
    source_snippets: str,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
    rag_pool: Any | None = None,
    rag_query: str | None = None,
    vulnerability_type: str | None = None,
    sg: SecurityGraph | None = None,
    include_methodology: bool = False,
) -> list[Hypothesis]:
    """
    Generic hunter LLM call.

    Args:
        hunter_name:       Name of the hunter (for logging)
        system_prompt:     The system prompt with hunting instructions
        context:           Security-relevant graph context
        source_snippets:   Relevant source code
        logger:            Optional audit logger
        verbose:           Print progress
        cross_feed_context: Optional Pass 1 findings summary for cross-feed hunting
        rag_pool:          Optional asyncpg Pool — if provided, triggers RAG retrieval
        rag_query:         Natural-language query to search the RAG DB with
        vulnerability_type: Hint for HyDE (e.g. "reentrancy", "oracle")

    Returns:
        List of Hypothesis objects
    """
    # Build cross-feed section if provided
    cross_feed_section = ""
    if cross_feed_context:
        cross_feed_section = f"""

## Cross-Feed: Findings From Other Hunters (Pass 1)

{cross_feed_context}

## CROSS-FEED INSTRUCTIONS
The findings above were produced by ALL hunters in Pass 1 (including yourself).
Now look for:
- **INTERACTION**: Finding X from one domain + Finding Y from another = a worse combined attack
- **CHAIN**: A sequence of steps across multiple findings that creates a multi-step exploit path
- **AMPLIFICATION**: A finding that makes another finding's impact significantly worse
- **MISSED ANGLES**: Vulnerabilities in the same functions that Pass 1 overlooked

Do NOT re-report findings already listed above. Only report NEW composite vulnerabilities.
"""

    # ── Token Budget: Truncate each section to configured caps ──────────────
    context        = context[:MAX_CONTEXT_CHARS]
    source_snippets = source_snippets[:MAX_SOURCE_CHARS]

    # ── RAG Context Injection ──────────────────────────────────────────────
    rag_section = ""
    _rag_pool = rag_pool or (sg.metadata.get("rag_pool") if sg is not None else None)
    if _rag_pool is not None:
        try:
            from avadhi.rag.context import build_rag_context_sync

            # ── Graph-grounded query (much more precise than generic name) ──
            if rag_query:
                _rag_query = rag_query  # hunter provided its own targeted query
            elif sg is not None:
                # Build query from graph: top functions + protocol type
                _top_fns = sorted(
                    [n for n, d in sg.G.nodes(data=True) if d.get("type") == "Function"],
                    key=lambda n: sg.G.out_degree(n),
                    reverse=True,
                )[:5]
                _fn_names = [sg.G.nodes[n].get("name", "") for n in _top_fns]
                _protocol = sg.metadata.get("enrichment_data", {}).get("protocol_type", "DeFi")
                _rag_query = (
                    f"{hunter_name} vulnerability in {_protocol} smart contract. "
                    f"Key functions: {', '.join(fn for fn in _fn_names if fn)}."
                )
            else:
                _rag_query = f"{hunter_name} vulnerability in Solidity smart contract"

            # Adaptive: halve RAG budget if context+source is already large
            _combined_len = len(context) + len(source_snippets)
            _rag_chars = MAX_RAG_CHARS // 2 if _combined_len > 10_000 else MAX_RAG_CHARS

            if verbose:
                print(f"   {hunter_name}: fetching RAG context (hyde=True, methodology={include_methodology})...")

            rag_context = build_rag_context_sync(
                _rag_query,
                _rag_pool,
                vulnerability_type=vulnerability_type,
                top_k=6,
                include_methodology=include_methodology,
                include_protocol=False,
                use_hyde=True,        # Always on — adds <1s, dramatically improves retrieval
                use_reranker=True,    # Always on — essential for precision
                max_chars=_rag_chars,
            )
            if rag_context:
                rag_section = f"\n\n{rag_context}\n"
                if verbose:
                    print(f"   {hunter_name}: RAG injected ({len(rag_context)} chars)")
        except Exception as _rag_err:
            if verbose:
                print(f"  WARNING  {hunter_name}: RAG failed ({_rag_err}), continuing without")

    prompt = f"""## SecurityGraph Context

{context}

## Relevant Source Code

{source_snippets}
{rag_section}
{cross_feed_section}
---

Analyze the above and return your findings as a JSON array of hypotheses:

```json
[
  {{
    "id": "{hunter_name[:3].upper()}-001",
    "title": "Short descriptive title",
    "severity": "Critical|High|Medium|Low|Info",
    "category": "Category of vulnerability",
    "description": "Detailed description of the vulnerability",
    "location": "ContractName.functionName:Lxxx",
    "attack_scenario": "Step-by-step exploit scenario",
    "preconditions": ["What must be true for this to work"],
    "impact": "What happens if exploited",
    "evidence": ["Specific code references or graph facts that support this"]
  }}
]
```

RULES:
- Only report findings you have STRONG evidence for from the graph and source
- Include specific line references and function names
- Describe a concrete attack scenario, not just "this could be bad"
- If you find nothing, return an empty array: []
- Do NOT hallucinate findings that aren't supported by the code"""

    if verbose:
        print(f"   {hunter_name}: calling LLM ({len(prompt)} chars)...")

    llm = get_llm()
    start = time.time()
    response = _invoke_with_backoff(llm, [
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt),
    ], hunter_name=hunter_name)

    latency_ms = int((time.time() - start) * 1000)
    response_text = response.content if hasattr(response, "content") else str(response)

    if logger:
        usage = getattr(response, "usage_metadata", {}) or {}
        logger.log_llm_call(
            agent=hunter_name,
            model=str(getattr(llm, "model", "unknown")),
            phase="hunting",
            prompt_tokens=usage.get("input_tokens", 0),
            completion_tokens=usage.get("output_tokens", 0),
            latency_ms=latency_ms,
        )

    if verbose:
        print(f"  OK {hunter_name}: response {len(response_text)} chars ({latency_ms}ms)")

    # Parse hypotheses
    hypotheses = _parse_hypotheses(response_text, hunter_name)

    if verbose:
        print(f"   {hunter_name}: {len(hypotheses)} hypotheses generated")

    return hypotheses


def _invoke_with_backoff(llm, messages, hunter_name: str = "", max_retries: int = 4):
    """
    Invoke the LLM with:
      1. PROACTIVE rate limiting via the global sliding-window rate_limiter
         (sleeps before the call if any Tier-1 budget would be exceeded).
      2. REACTIVE exponential backoff on any 429 that still slips through
         (15 s → 30 s → 60 s → 120 s).

    Actual token usage from the response is recorded back to the rate limiter
    so future calls can budget accurately.
    """
    import logging as _logging
    _log = _logging.getLogger(__name__)

    from avadhi.utils.rate_limiter import rate_limiter

    # Estimate prompt size (chars / 4 ≈ tokens) for the pre-call reservation.
    est_input  = sum(len(getattr(m, "content", str(m))) for m in messages) // 4
    est_output = 1500  # conservative output estimate for hunter calls

    for attempt in range(1, max_retries + 1):
        # Proactively wait until all three budgets have room.
        rid = rate_limiter.acquire(
            estimated_input_tokens=est_input,
            estimated_output_tokens=est_output,
        )
        try:
            response = llm.invoke(messages)

            # Record actual usage so future calls budget correctly.
            usage = getattr(response, "usage_metadata", None) or {}
            actual_in  = usage.get("input_tokens",  est_input)
            actual_out = usage.get("output_tokens", est_output)
            rate_limiter.record_usage(rid, actual_in, actual_out)

            return response

        except Exception as exc:
            rate_limiter.cancel_reservation(rid)
            err_str = str(exc)
            is_rate_limit = (
                "429" in err_str
                or "rate_limit" in err_str.lower()
                or "rate limit" in err_str.lower()
            )
            if is_rate_limit and attempt < max_retries:
                # Reactive fallback: wait longer and flush the window.
                wait_secs = 15 * (2 ** (attempt - 1))  # 15 s, 30 s, 60 s, 120 s
                _log.warning(
                    "... %s: 429 on attempt %d/%d, sleeping %ds (rate_limiter status: %s)",
                    hunter_name or "hunter", attempt, max_retries, wait_secs,
                    rate_limiter.status(),
                )
                print(f"  ... {hunter_name}: 429 still hit — waiting {wait_secs}s...")
                time.sleep(wait_secs)
            else:
                raise
    raise RuntimeError(f"{hunter_name}: Max retries ({max_retries}) exceeded")


def _parse_hypotheses(text: str, hunter_name: str) -> list[Hypothesis]:
    """Parse LLM response into Hypothesis objects."""
    # Extract JSON array
    json_str = _extract_json_array(text)
    if not json_str:
        return []

    try:
        raw_list = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    hypotheses = []
    for i, raw in enumerate(raw_list):
        try:
            h = Hypothesis(
                id=raw.get("id", f"{hunter_name[:3].upper()}-{i+1:03d}"),
                title=raw.get("title", "Untitled"),
                severity=_parse_severity(raw.get("severity", "Medium")),
                confidence=Confidence.UNCERTAIN,
                category=raw.get("category", "Unknown"),
                description=raw.get("description", ""),
                location=raw.get("location", ""),
                attack_scenario=raw.get("attack_scenario", ""),
                preconditions=raw.get("preconditions", []),
                impact=raw.get("impact", ""),
                evidence=raw.get("evidence", []),
                hunter_agent=hunter_name,
            )
            hypotheses.append(h)
        except Exception:
            continue

    return hypotheses


def _extract_json_array(text: str) -> str | None:
    """Extract a JSON array from text, handling markdown code blocks."""
    # Try code block first
    if "```json" in text:
        start = text.index("```json") + 7
        if "```" in text[start:]:
            end = text.index("```", start)
            return text[start:end].strip()
        else:
            return text[start:].strip()
    if "```" in text:
        start = text.index("```") + 3
        if "```" in text[start:]:
            end = text.index("```", start)
            candidate = text[start:end].strip()
        else:
            candidate = text[start:].strip()
        if candidate.startswith("["):
            return candidate

    # Try raw JSON array
    for i, ch in enumerate(text):
        if ch == "[":
            depth = 0
            for j in range(i, len(text)):
                if text[j] == "[":
                    depth += 1
                elif text[j] == "]":
                    depth -= 1
                if depth == 0:
                    return text[i:j + 1]
            break
    return None


def _parse_severity(s: str) -> Severity:
    """Parse severity string to enum."""
    s_lower = s.lower().strip()
    for sev in Severity:
        if sev.value.lower() == s_lower:
            return sev
    return Severity.MEDIUM


def get_source_for_functions(sg: SecurityGraph, fn_ids: list[str],
                             max_chars: int | None = None) -> str:
    """Get source code snippets for specific functions.

    Functions are sorted by graph out-degree (most-connected first) so the
    LLM always sees the most architecturally central code when the budget runs
    out.
    """
    from avadhi.config import MAX_SOURCE_CHARS
    if max_chars is None:
        max_chars = MAX_SOURCE_CHARS

    source_files = sg.metadata.get("source_files", {})
    if not source_files:
        return "(no source available)"

    # Sort by out-degree (call-site centrality) descending — top 10 only
    fn_ids = sorted(fn_ids, key=lambda f: sg.G.out_degree(f), reverse=True)[:10]

    snippets = []
    total = 0

    for fn_id in fn_ids:
        node = sg.G.nodes.get(fn_id, {})
        contract = node.get("contract", "")
        fn_name = node.get("name", "")
        line_start = node.get("line_start", 0)
        line_end = node.get("line_end", 0)

        if not contract or not line_start:
            continue

        # Prefer exact file path stored by Slither; fall back to scanning all files.
        node_file = node.get("file", "")
        candidates = (
            [(node_file, source_files[node_file])]
            if node_file and node_file in source_files
            else [(fp, c) for fp, c in source_files.items() if contract in c]
        )

        for file_path, content in candidates:
            lines = content.split("\n")
            # Get surrounding context (5 lines before, full function body)
            start = max(0, line_start - 5)
            end = min(len(lines), line_end + 3) if line_end else min(len(lines), line_start + 60)
            snippet = "\n".join(lines[start:end])
            snippets.append(f"// {file_path} — {contract}.{fn_name}() (L{line_start}-{line_end})\n{snippet}")
            total += len(snippet)
            break

        if total >= max_chars:
            break

    return "\n\n".join(snippets) if snippets else "(source not found for specified functions)"
