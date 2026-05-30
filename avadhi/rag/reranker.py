"""
avadhi/rag/reranker.py
──────────────────────────────────────────────────────────────────────────────
Cross-encoder reranking layer — the most impactful single upgrade to retrieval
quality.

WHY RERANKING MATTERS
─────────────────────
Bi-encoder retrieval (what HNSW does) compresses a document into a single
fixed-size vector. It is extremely fast but loses fine-grained token-level
alignment between query and document.

A cross-encoder sees the FULL (query, document) pair together and computes a
precise relevance score. It is 10-100× slower than bi-encoding, but far more
accurate on the top candidates.

The industry-standard pattern is:
  Stage 1: Fast bi-encoder retrieval (top 40-80 candidates) ← what we do
  Stage 2: Slow cross-encoder reranking (top 40 → top 10)   ← this module

MODELS AVAILABLE
────────────────
  voyage-rerank-2     — Voyage AI's reranker, explicitly trained for code + technical text.
                        Best option for Solidity/audit-domain queries.
                        API: client.rerank(query, documents, model="rerank-2", top_k=N)

  rerank-english-v3.0 — Cohere's cross-encoder. Strong on English prose.
                        Fallback when Voyage reranker quota is hit.

CONFIGURATION
─────────────
  AVADHI_RERANKER=voyage      (default)
  AVADHI_RERANKER=cohere
  AVADHI_RERANKER=none        (disable — useful for latency-sensitive paths)
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avadhi.rag.retriever import RetrievedChunk

logger = logging.getLogger(__name__)

RERANKER_BACKEND = os.getenv("AVADHI_RERANKER", "voyage").lower()


async def rerank(
    query: str,
    chunks: list["RetrievedChunk"],
    *,
    top_k: int,
    backend: str | None = None,
) -> list["RetrievedChunk"]:
    """
    Cross-encoder rerank a list of retrieval candidates.

    Runs in a thread-executor since Voyage/Cohere SDKs are synchronous.

    Args:
        query:   The original retrieval query.
        chunks:  Candidate chunks from bi-encoder retrieval (pre-RRF or post-RRF).
        top_k:   Number of top results to return after reranking.
        backend: Override AVADHI_RERANKER env var for this call.

    Returns:
        Reranked, truncated list of RetrievedChunk with `rerank_score` populated.
    """
    effective_backend = (backend or RERANKER_BACKEND).lower()

    if not chunks or effective_backend == "none":
        return chunks[:top_k]

    import asyncio

    try:
        if effective_backend == "voyage":
            return await asyncio.get_event_loop().run_in_executor(
                None, _rerank_voyage_sync, query, chunks, top_k
            )
        elif effective_backend == "cohere":
            return await asyncio.get_event_loop().run_in_executor(
                None, _rerank_cohere_sync, query, chunks, top_k
            )
        else:
            logger.warning("Unknown reranker backend %r — skipping rerank", effective_backend)
            return chunks[:top_k]
    except Exception as e:
        logger.warning("Reranker failed (%s: %s) — falling back to RRF order", type(e).__name__, e)
        return chunks[:top_k]


# ── Voyage Reranker ──────────────────────────────────────────────────────────

def _rerank_voyage_sync(
    query: str,
    chunks: list["RetrievedChunk"],
    top_k: int,
) -> list["RetrievedChunk"]:
    """
    voyage-rerank-2: Cross-encoder explicitly trained for code + technical text.
    Sends (query, doc) pairs in a single batch call.
    """
    import voyageai  # type: ignore

    client = voyageai.Client(api_key=os.environ["VOYAGE_API_KEY"])
    documents = [c.chunk_text for c in chunks]

    result = client.rerank(
        query=query,
        documents=documents,
        model="rerank-2",
        top_k=min(top_k, len(chunks)),
    )

    # result.results is a list of RerankingObject with .index and .relevance_score
    reranked: list["RetrievedChunk"] = []
    for item in result.results:
        chunk = chunks[item.index]
        chunk.rerank_score = float(item.relevance_score)
        chunk._debug["reranker"] = "voyage-rerank-2"
        reranked.append(chunk)

    logger.debug("Voyage rerank: %d → %d chunks", len(chunks), len(reranked))
    return reranked


# ── Cohere Reranker (fallback) ───────────────────────────────────────────────

def _rerank_cohere_sync(
    query: str,
    chunks: list["RetrievedChunk"],
    top_k: int,
) -> list["RetrievedChunk"]:
    """
    Cohere rerank-english-v3.0: strong at prose, good fallback for text chunks.
    """
    import cohere  # type: ignore

    api_key = os.environ.get("COHERE_API_KEY", "")
    if not api_key:
        raise RuntimeError("COHERE_API_KEY not set")

    client = cohere.Client(api_key)
    documents = [c.chunk_text for c in chunks]

    result = client.rerank(
        query=query,
        documents=documents,
        model="rerank-english-v3.0",
        top_n=min(top_k, len(chunks)),
    )

    reranked: list["RetrievedChunk"] = []
    for item in result.results:
        chunk = chunks[item.index]
        chunk.rerank_score = float(item.relevance_score)
        chunk._debug["reranker"] = "cohere-rerank-english-v3.0"
        reranked.append(chunk)

    logger.debug("Cohere rerank: %d → %d chunks", len(chunks), len(reranked))
    return reranked
