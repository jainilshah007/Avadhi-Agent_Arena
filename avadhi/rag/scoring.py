"""
avadhi/rag/scoring.py
──────────────────────────────────────────────────────────────────────────────
Metadata-aware scoring and semantic deduplication.

Two jobs:

1. METADATA BOOSTING
   ─────────────────
   After RRF fusion, apply domain-specific boosts based on chunk metadata:

   Boost signals (multiplicative):
     +30%  chunk.has_code == True AND query appears code-related
     +20%  chunk.category == "bug_pattern" (most relevant for hunters)
     +15%  chunk has tags that semantically overlap with query keywords
     +10%  chunk is from "audit_methodology" (methodological grounding)
     -20%  chunk is from "web3_basics" category (less specific)
     -15%  chunk.chunk_tokens < 50 (very short — likely boilerplate)

   This is NOT a replacement for reranking — it is a lightweight heuristic
   pass that runs before the cross-encoder to ensure the reranker sees the
   highest-signal candidates.

2. SEMANTIC DEDUPLICATION
   ───────────────────────
   When HNSW retrieves top-40 candidates before reranking, many are nearly
   identical (same document chunked at offset ±100 chars). Flooding the
   reranker with 8 near-identical chunks wastes context window and dilutes
   the final result set.

   We deduplicate using a cosine-similarity threshold (default: 0.92) on the
   chunk text via a fast in-memory comparison. Chunks that are >92% similar
   to an already-accepted chunk are dropped.

   Bonus: also removes exact-duplicate chunk_ids (same UUID from different
   retrieval passes — RRF should handle this, but belt-and-suspenders).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avadhi.rag.retriever import RetrievedChunk

logger = logging.getLogger(__name__)

# ── Metadata Boosting ─────────────────────────────────────────────────────────

# Keywords that imply code-centric intent in the query
_CODE_INTENT_WORDS = frozenset({
    "function", "contract", "modifier", "mapping", "delegatecall",
    "assembly", "solidity", "reentrancy", "call(", "transfer(",
    "emit", "revert", "require", "uint", "address", "bytes",
})

# Ordered by priority — first match wins the tag boost
_VULN_TAG_MAP: dict[str, list[str]] = {
    "reentrancy":      ["reentrancy", "reentrant", "nonreentrant"],
    "oracle":          ["oracle", "price", "twap", "chainlink", "flash_loan"],
    "accounting":      ["accounting", "invariant", "balance", "share", "rounding"],
    "access_control":  ["access_control", "onlyowner", "admin", "permission"],
    "gas_dos":         ["gas", "dos", "loop", "unbounded"],
    "governance":      ["governance", "timelock", "owner", "admin"],
    "external_call":   ["external_call", "arbitrary_call", "delegatecall"],
}


def boost_scores(
    chunks: list["RetrievedChunk"],
    query: str,
    *,
    code_boost: float = 1.30,
    bug_pattern_boost: float = 1.20,
    tag_boost: float = 1.15,
    methodology_boost: float = 1.10,
    web3_basics_penalty: float = 0.80,
    tiny_chunk_penalty: float = 0.85,
    tiny_chunk_threshold: int = 50,
) -> list["RetrievedChunk"]:
    """
    Apply multiplicative metadata boosts to RRF scores.

    Modifies chunk.rrf_score in-place and re-sorts the list.

    Args:
        chunks:                 List of chunks after RRF fusion.
        query:                  The original query string (used for signal detection).
        code_boost:             Multiplier applied when chunk has code and query is code-related.
        bug_pattern_boost:      Multiplier for bug_pattern chunks.
        tag_boost:              Multiplier when chunk tags overlap with inferred vuln type.
        methodology_boost:      Multiplier for audit_methodology chunks.
        web3_basics_penalty:    Penalty for generic web3_basics chunks.
        tiny_chunk_penalty:     Penalty for very short chunks.
        tiny_chunk_threshold:   Token count below which the tiny penalty applies.

    Returns:
        Re-sorted list with boosted scores.
    """
    query_lower = query.lower()
    query_words = set(re.findall(r"\b\w+\b", query_lower))

    # Detect code intent (set once for the whole query)
    is_code_query = bool(query_words & _CODE_INTENT_WORDS)

    # Detect which vulnerability type the query is about
    inferred_vuln_tags: set[str] = set()
    for vuln_type, tag_keywords in _VULN_TAG_MAP.items():
        if any(kw in query_lower for kw in tag_keywords):
            inferred_vuln_tags.update(tag_keywords)

    for chunk in chunks:
        score = chunk.rrf_score
        reasons: list[str] = []

        # Code boost
        if chunk.has_code and is_code_query:
            score *= code_boost
            reasons.append(f"code_boost×{code_boost}")

        # Category boosts/penalties
        if chunk.category == "bug_pattern":
            score *= bug_pattern_boost
            reasons.append(f"bug_pattern×{bug_pattern_boost}")
        elif chunk.category == "audit_methodology":
            score *= methodology_boost
            reasons.append(f"methodology×{methodology_boost}")
        elif chunk.category == "web3_basics":
            score *= web3_basics_penalty
            reasons.append(f"web3_basics×{web3_basics_penalty}")

        # Tag overlap boost
        chunk_tag_set = set(t.lower() for t in chunk.tags)
        if inferred_vuln_tags and chunk_tag_set & inferred_vuln_tags:
            score *= tag_boost
            reasons.append(f"tag_overlap×{tag_boost}")

        # Tiny chunk penalty
        if chunk.chunk_tokens is not None and chunk.chunk_tokens < tiny_chunk_threshold:
            score *= tiny_chunk_penalty
            reasons.append(f"tiny×{tiny_chunk_penalty}")

        chunk.rrf_score = score
        chunk._debug["boosts"] = reasons

    # Re-sort after boosting
    chunks.sort(key=lambda c: c.rrf_score, reverse=True)
    return chunks


# ── Semantic Deduplication ────────────────────────────────────────────────────


def deduplicate_chunks(
    chunks: list["RetrievedChunk"],
    *,
    similarity_threshold: float = 0.92,
) -> list["RetrievedChunk"]:
    """
    Remove near-duplicate chunks using shingling-based Jaccard similarity.

    We use word-level 3-shingle Jaccard similarity (fast, no embeddings needed)
    rather than cosine distance on vectors — shingles capture text overlap
    precisely what we care about (same content, slightly different windows).

    Args:
        chunks:               Ranked list of retrieved chunks.
        similarity_threshold: Chunks with Jaccard sim > this are dropped.
                              0.92 = must share >92% of 3-word shingles.

    Returns:
        Deduplicated list preserving original order (highest-ranked kept).
    """
    if len(chunks) <= 1:
        return chunks

    kept: list["RetrievedChunk"] = []
    kept_shingles: list[frozenset] = []
    seen_ids: set[str] = set()

    for chunk in chunks:
        # 1. Exact-ID dedup (shouldn't happen post-RRF but belt-and-suspenders)
        if chunk.chunk_id in seen_ids:
            chunk._debug["deduped_by"] = "exact_id"
            continue
        seen_ids.add(chunk.chunk_id)

        # 2. Near-duplicate shingle check
        shingles = _compute_shingles(chunk.chunk_text)
        is_dup = False
        for kept_sh in kept_shingles:
            jaccard = _jaccard(shingles, kept_sh)
            if jaccard >= similarity_threshold:
                chunk._debug["deduped_by"] = f"jaccard={jaccard:.3f}"
                is_dup = True
                break

        if not is_dup:
            kept.append(chunk)
            kept_shingles.append(shingles)

    removed = len(chunks) - len(kept)
    if removed > 0:
        logger.debug("Deduplication: removed %d/%d near-duplicate chunks", removed, len(chunks))

    return kept


def _compute_shingles(text: str, k: int = 3) -> frozenset[str]:
    """Compute k-word shingle set from text."""
    words = re.findall(r"\b\w+\b", text.lower())
    if len(words) < k:
        return frozenset(words)
    return frozenset(" ".join(words[i : i + k]) for i in range(len(words) - k + 1))


def _jaccard(a: frozenset, b: frozenset) -> float:
    """Compute Jaccard similarity between two sets."""
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0
