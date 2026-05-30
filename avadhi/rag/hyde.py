"""
avadhi/rag/hyde.py
──────────────────────────────────────────────────────────────────────────────
HyDE — Hypothetical Document Embedding (Gao et al., 2022)

THE PROBLEM WITH STANDARD QUERIES
───────────────────────────────────
When a hunter asks "oracle manipulation through price skew", that query
is SHORT and ABSTRACT. The actual vulnerability descriptions in our DB are
LONG and SPECIFIC, filled with technical detail like function names, exploit
steps, and code snippets.

The semantic distance between a short query and a rich document is large —
the embedding vectors for them land in very different parts of the space even
when they're conceptually identical.

THE HyDE SOLUTION
─────────────────
Instead of embedding the raw query string, we:
  1. Ask an LLM to generate a HYPOTHETICAL vulnerability description that
     WOULD answer the query — a fake-but-plausible document snippet.
  2. Embed THAT synthetic document (instead of the query).
  3. Retrieve against the real database with this hypothetical embedding.

Because the synthetic document is long, technical, and domain-specific, it
lands close to real vulnerability descriptions in the embedding space —
dramatically improving retrieval precision.

DOMAIN-SPECIFIC GENERATION
────────────────────────────
We use a compact security-domain prompt so the LLM generates a doc that:
  • Uses Solidity/EVM terminology
  • Describes a specific exploit mechanism step-by-step
  • Contains function/variable names and code-like descriptions
  • Explicitly states the invariant that is violated

This is not a general HyDE — it is a Security-Audit-HyDE™.

PERFORMANCE
───────────
  Cold: ~0.5-1.5s for the LLM call (uses FAST_MODEL by default)
  Cached: 0ms (LRU cache keyed on query string)

USAGE
─────
    from avadhi.rag.hyde import expand_query_with_hyde

    hyde_query = await expand_query_with_hyde(
        "oracle price manipulation flash loan",
        vulnerability_type="oracle",
    )
    # hyde_query is now a 300-word synthetic exploit description
    # → embed this for retrieval instead of the raw 5-word query
"""

from __future__ import annotations

import asyncio
import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)

# Maps vulnerability categories to domain-specific generation hints
_CATEGORY_HINTS: dict[str, str] = {
    "reentrancy": (
        "Describe a specific reentrancy vulnerability where an external call is made before"
        " a state variable update (CEI violation). Include: which function is vulnerable,"
        " the callback mechanism exploited (fallback/ERC-721/ERC-777), state variable that"
        " is read stale, and the exact invariant that is violated."
    ),
    "oracle": (
        "Describe a specific oracle manipulation vulnerability involving price feed skew."
        " Include: which oracle is used (TWAP/Chainlink/Uniswap spot), how the attacker"
        " can manipulate it (flash loan, sandwich, large trade), the dependent function"
        " that uses the stale/skewed price, and the economic impact."
    ),
    "accounting": (
        "Describe a specific accounting invariant violation in a DeFi protocol."
        " Include: which state variables must remain in sync (totalAssets vs sum(balances)),"
        " which function breaks the invariant, whether it involves rounding errors or"
        " precision loss (fixed-point math), and the resulting drain vector."
    ),
    "access_control": (
        "Describe a specific missing access control vulnerability on a privileged function."
        " Include: which function lacks the onlyOwner/onlyAdmin modifier, what state it"
        " can modify, what an attacker could drain or manipulate, and which modifier or"
        " require() check is absent."
    ),
    "gas_dos": (
        "Describe a specific gas grief or DoS vulnerability involving an unbounded loop."
        " Include: which state variable grows unboundedly, which loop iterates over it,"
        " the gas cost at N iterations, and how an attacker can cause the function to"
        " always revert by growing the array past the block gas limit."
    ),
    "governance": (
        "Describe a specific governance vulnerability where an admin setter function"
        " can be called to alter critical protocol state mid-operation. Include: which"
        " setter function exists, what variable it modifies, which operational function"
        " reads that variable, and how a malicious owner can exploit this to drain funds"
        " or permanently lock the protocol."
    ),
    "external_call": (
        "Describe a specific arbitrary external call vulnerability where user-controlled"
        " data is passed to a low-level .call() without validation. Include: which function"
        " takes the target address/calldata from user input, what approvals or token flows"
        " the contract has that an attacker could redirect, and the exact steal path."
    ),
}

_DEFAULT_HINT = (
    "Describe a specific smart contract vulnerability with step-by-step exploit mechanics."
    " Include Solidity function names, state variable names, the broken invariant,"
    " and the exact impact (fund drain, denial of service, or privilege escalation)."
)

_HYDE_SYSTEM = """You are an expert smart contract security researcher.
Given a vulnerability type hint, write a CONCISE (150-250 words) but technically PRECISE
description of a hypothetical vulnerability of that type.

Requirements:
- Use real Solidity/EVM terminology (function names, state variable names, modifiers)
- Describe the exploit step-by-step (attacker does X → contract does Y → attacker gains Z)
- Name the invariant that is violated
- Include specific token amounts or percentages where relevant
- Do NOT provide generic descriptions — be specific and technical
- Write as if you are describing a REAL finding from an audit report
Output ONLY the vulnerability description text, no preamble."""


async def expand_query_with_hyde(
    query: str,
    *,
    vulnerability_type: str | None = None,
    model: str | None = None,
) -> str:
    """
    Expand a short retrieval query into a synthetic vulnerability description
    using a small LLM call (HyDE technique).

    Args:
        query:              The original short query (e.g., "oracle flash loan attack").
        vulnerability_type: Optional hint to improve generation quality.
                            One of: reentrancy, oracle, accounting, access_control,
                                    gas_dos, governance, external_call.
        model:              LLM model override (defaults to AVADHI_FAST_MODEL).

    Returns:
        A 150-250 word synthetic vulnerability description for embedding.
        Falls back to the original query if LLM call fails.
    """
    # Cache HyDE expansions — same query → same expansion
    cache_key = (query.strip().lower(), vulnerability_type)
    cached = _hyde_cache_get(cache_key)
    if cached:
        logger.debug("HyDE cache hit: %r", query[:40])
        return cached

    hint = _CATEGORY_HINTS.get(vulnerability_type or "", _DEFAULT_HINT)
    user_message = f"Vulnerability hint: {hint}\n\nQuery to expand: {query}"

    effective_model = model or os.getenv("AVADHI_FAST_MODEL", "gpt-4o-mini")

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, _generate_hyde_sync, user_message, effective_model
        )
        logger.debug("HyDE expanded %r → %d chars", query[:40], len(result))
        _hyde_cache_set(cache_key, result)
        return result
    except Exception as e:
        logger.warning("HyDE generation failed (%s: %s) — using raw query", type(e).__name__, e)
        return query


def _generate_hyde_sync(user_message: str, model: str) -> str:
    """Synchronous LLM call for HyDE generation."""
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _HYDE_SYSTEM},
            {"role": "user", "content": user_message},
        ],
        max_tokens=350,
        temperature=0.3,  # Low temp — we want plausible, not creative
    )
    return response.choices[0].message.content.strip()


# ── Simple in-process LRU cache (no Redis needed) ────────────────────────────
# Keyed on (query, vuln_type) tuple — handles repeated hunter calls within 1 run

_CACHE: dict[tuple, str] = {}
_CACHE_MAX = 128


def _hyde_cache_get(key: tuple) -> str | None:
    return _CACHE.get(key)


def _hyde_cache_set(key: tuple, value: str) -> None:
    if len(_CACHE) >= _CACHE_MAX:
        # Evict oldest entry (Python 3.7+ dicts preserve insertion order)
        oldest = next(iter(_CACHE))
        del _CACHE[oldest]
    _CACHE[key] = value
