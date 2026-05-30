"""
avadhi/rag/retriever.py
──────────────────────────────────────────────────────────────────────────────
Core hybrid retrieval logic against the pgvector PostgreSQL database.

Retrieval Strategy
──────────────────
The database stores TWO parallel embedding columns per chunk:

   embedding_code  vector(1024)  — voyage-code-3   (code-heavy content)
   embedding_text  vector(1536)  — text-embedding-3-small (prose content)

Plus a full-text GIN index on the TSVector `search_vector` column for BM25-
style keyword matching.

The HybridRetriever executes all three independently and fuses them using
Reciprocal Rank Fusion (RRF), which is provably more robust than score-
normalisation when result sets are heterogeneous.

RRF Formula: score(d) = Σ 1 / (k + rank_in_list_i)  where k = 60 (constant)

Pre-filters (applied BEFORE vector search, hitting metadata indexes):
  - category        TEXT   — web3_basics | protocol | bug_pattern | audit_methodology
  - tags            TEXT[] — reentrancy | flash_loan | oracle | access_control …
  - has_code        BOOL   — True if the chunk contains Solidity code
  - subcategory     TEXT   — fine-grained grouping within category
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import asyncpg
import numpy as np

from avadhi.rag.embedder import QueryEmbedder

logger = logging.getLogger(__name__)

# RRF constant — empirically optimal value from the original paper.
_RRF_K = 60


@dataclass
class RetrievedChunk:
    """A single document chunk returned from the retrieval layer."""
    chunk_id: str
    source_doc_id: str
    chunk_text: str
    chunk_tokens: int | None
    category: str
    subcategory: str | None
    tags: list[str]
    has_code: bool
    code_language: str | None
    embed_model: str
    # Scores — populated as the chunk moves through the pipeline stages
    vector_score: float = 0.0         # Stage 1: cosine similarity from HNSW
    fts_score: float = 0.0            # Stage 1: BM25 rank from TSVector
    rrf_score: float = 0.0            # Stage 1: fused RRF score
    rerank_score: float = 0.0         # Stage 4: cross-encoder relevance score
    # Debug / traceability metadata
    _debug: dict = field(default_factory=dict, repr=False)


class HybridRetriever:
    """
    Performs Hybrid retrieval: Vector (HNSW) + Full-Text (BM25) fused via RRF.

    Parameters
    ──────────
    pool        asyncpg.Pool    — shared DB connection pool (required)
    embedder    QueryEmbedder   — embedding wrapper (auto-created if None)
    top_k       int             — number of final results to return (default 10)
    ef_search   int             — HNSW ef_search scan width (default 100)
                                  Higher = more accurate, slower. Good range: 64-200.
    rrf_k       int             — RRF smoothing constant (default 60)

    Basic Usage
    ────────────
        retriever = HybridRetriever(pool=pool, top_k=8)

        chunks = await retriever.retrieve(
            query="reentrancy through ERC-721 onERC721Received callback",
            category="bug_pattern",
        )

    Advanced Usage (pre-filters)
    ─────────────────────────────
        chunks = await retriever.retrieve(
            query="price oracle twap single source manipulation",
            category="bug_pattern",
            tags=["oracle", "flash_loan"],
            has_code=True,
            top_k=12,
        )
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        embedder: QueryEmbedder | None = None,
        top_k: int = 10,
        ef_search: int = 100,
        rrf_k: int = _RRF_K,
    ) -> None:
        self._pool = pool
        self._embedder = embedder or QueryEmbedder()
        self._top_k = top_k
        self._ef_search = ef_search
        self._rrf_k = rrf_k

    async def retrieve(
        self,
        query: str,
        *,
        category: str | None = None,
        tags: list[str] | None = None,
        has_code: bool | None = None,
        subcategory: str | None = None,
        top_k: int | None = None,
        is_code: bool | None = None,
    ) -> list[RetrievedChunk]:
        """
        Execute hybrid retrieval and return fused, ranked chunks.

        Args:
            query:       Natural language or code query.
            category:    Optional pre-filter on the `category` column.
            tags:        Optional GIN pre-filter — chunks must contain ALL listed tags.
            has_code:    Optional boolean pre-filter on `has_code`.
            subcategory: Optional pre-filter on the `subcategory` column.
            top_k:       Override the instance-level top_k for this call.
            is_code:     Override auto-detection of embedding model.

        Returns:
            List of RetrievedChunk sorted by descending RRF score.
        """
        k = top_k or self._top_k
        fetch_k = k * 4  # over-fetch so RRF has enough candidates for fusion

        # 1. Embed the query (both models in parallel for full hybrid search)
        code_vec, text_vec = self._embedder.embed_both(query)

        # 2. Execute all retrieval passes concurrently
        code_results, text_results, fts_results = await asyncio.gather(
            self._vector_search(code_vec, "embedding_code", fetch_k, category, tags, has_code, subcategory),
            self._vector_search(text_vec, "embedding_text", fetch_k, category, tags, has_code, subcategory),
            self._fts_search(query, fetch_k, category, tags, has_code, subcategory),
        )

        # 3. Fuse via RRF
        fused = self._rrf_fuse(code_results, text_results, fts_results, k=k)

        logger.debug(
            "RAG retrieve: query=%r code_hits=%d text_hits=%d fts_hits=%d fused=%d",
            query[:60],
            len(code_results),
            len(text_results),
            len(fts_results),
            len(fused),
        )
        return fused

    async def retrieve_code_only(
        self,
        query: str,
        *,
        category: str | None = None,
        tags: list[str] | None = None,
        top_k: int | None = None,
    ) -> list[RetrievedChunk]:
        """
        Pure vector search using voyage-code-3 only.
        Fastest path for code-similarity queries.
        """
        k = top_k or self._top_k
        code_vec, _ = self._embedder.embed_both(query)
        return await self._vector_search(code_vec, "embedding_code", k, category, tags, None, None)

    async def retrieve_fts_only(
        self,
        query: str,
        *,
        category: str | None = None,
        top_k: int | None = None,
    ) -> list[RetrievedChunk]:
        """
        Pure full-text search (BM25-style) — no embeddings needed.
        Fast and useful when the query contains exact function/variable names.
        """
        k = top_k or self._top_k
        return await self._fts_search(query, k, category, None, None, None)

    # ── Private retrieval backends ───────────────────────────────────────────

    async def _vector_search(
        self,
        vector: np.ndarray,
        column: str,
        limit: int,
        category: str | None,
        tags: list[str] | None,
        has_code: bool | None,
        subcategory: str | None,
    ) -> list[RetrievedChunk]:
        """
        HNSW cosine similarity search on a given vector column.
        Sets ef_search session variable for quality control.
        """
        # Build WHERE clause from optional pre-filters
        filters, params = _build_filters(
            category=category,
            tags=tags,
            has_code=has_code,
            subcategory=subcategory,
            start_param_idx=2,  # $1 is the query vector
        )
        where_clause = f"WHERE {column} IS NOT NULL" + (f" AND {filters}" if filters else "")

        sql = f"""
            SELECT
                id::text AS chunk_id,
                source_doc_id::text,
                chunk_text,
                chunk_tokens,
                category,
                subcategory,
                tags,
                has_code,
                code_language,
                embed_model,
                1 - ({column} <=> $1::vector) AS vector_score
            FROM document_embeddings
            {where_clause}
            ORDER BY {column} <=> $1::vector
            LIMIT {limit}
        """

        async with self._pool.acquire() as conn:
            # SET LOCAL must be its own execute — asyncpg does not allow multi-statement queries
            await conn.execute(f"SET LOCAL hnsw.ef_search = {self._ef_search}")
            rows = await conn.fetch(sql, vector, *params)

        return [_row_to_chunk(r, vector_score=float(r["vector_score"])) for r in rows]

    async def _fts_search(
        self,
        query: str,
        limit: int,
        category: str | None,
        tags: list[str] | None,
        has_code: bool | None,
        subcategory: str | None,
    ) -> list[RetrievedChunk]:
        """
        Full-text search using PostgreSQL TSVector + GIN index.
        Uses plainto_tsquery for safe query parsing (no user-controlled operators).
        """
        filters, params = _build_filters(
            category=category,
            tags=tags,
            has_code=has_code,
            subcategory=subcategory,
            start_param_idx=2,  # $1 is the tsquery string
        )
        where_clause = "WHERE search_vector @@ plainto_tsquery('english', $1)" + (
            f" AND {filters}" if filters else ""
        )

        sql = f"""
            SELECT
                id::text AS chunk_id,
                source_doc_id::text,
                chunk_text,
                chunk_tokens,
                category,
                subcategory,
                tags,
                has_code,
                code_language,
                embed_model,
                ts_rank_cd(search_vector, plainto_tsquery('english', $1)) AS fts_score
            FROM document_embeddings
            {where_clause}
            ORDER BY fts_score DESC
            LIMIT {limit}
        """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, query, *params)

        return [_row_to_chunk(r, fts_score=float(r["fts_score"])) for r in rows]

    # ── RRF Fusion ───────────────────────────────────────────────────────────

    def _rrf_fuse(
        self,
        code_results: list[RetrievedChunk],
        text_results: list[RetrievedChunk],
        fts_results: list[RetrievedChunk],
        k: int,
    ) -> list[RetrievedChunk]:
        """
        Reciprocal Rank Fusion across 3 ranked lists.
        
        RRF score = Σ  1 / (K + rank_i)
        where K=60 — strongly down-weights items that rank poorly in any list.
        """
        rrf_scores: dict[str, float] = {}
        all_chunks: dict[str, RetrievedChunk] = {}

        for ranked_list in (code_results, text_results, fts_results):
            for rank, chunk in enumerate(ranked_list, start=1):
                cid = chunk.chunk_id
                rrf_scores[cid] = rrf_scores.get(cid, 0.0) + 1.0 / (self._rrf_k + rank)
                # Keep the chunk dict deduped — prefer the one with a vector score
                if cid not in all_chunks or chunk.vector_score > all_chunks[cid].vector_score:
                    all_chunks[cid] = chunk

        # Attach the final RRF score and sort
        reranked: list[RetrievedChunk] = []
        for cid, score in sorted(rrf_scores.items(), key=lambda x: -x[1]):
            chunk = all_chunks[cid]
            chunk.rrf_score = score
            reranked.append(chunk)

        return reranked[:k]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _build_filters(
    *,
    category: str | None,
    tags: list[str] | None,
    has_code: bool | None,
    subcategory: str | None,
    start_param_idx: int,
) -> tuple[str, list[Any]]:
    """Build parametrized WHERE fragments and positional params list."""
    clauses: list[str] = []
    params: list[Any] = []
    idx = start_param_idx

    if category is not None:
        clauses.append(f"category = ${idx}")
        params.append(category)
        idx += 1

    if subcategory is not None:
        clauses.append(f"subcategory = ${idx}")
        params.append(subcategory)
        idx += 1

    if has_code is not None:
        clauses.append(f"has_code = ${idx}")
        params.append(has_code)
        idx += 1

    if tags:
        # GIN index: chunk must contain ALL specified tags
        clauses.append(f"tags @> ${idx}::text[]")
        params.append(tags)
        idx += 1

    return " AND ".join(clauses), params


def _row_to_chunk(
    row: asyncpg.Record,
    *,
    vector_score: float = 0.0,
    fts_score: float = 0.0,
) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=row["chunk_id"],
        source_doc_id=row["source_doc_id"],
        chunk_text=row["chunk_text"],
        chunk_tokens=row["chunk_tokens"],
        category=row["category"],
        subcategory=row["subcategory"],
        tags=list(row["tags"] or []),
        has_code=row["has_code"],
        code_language=row["code_language"],
        embed_model=row["embed_model"],
        vector_score=vector_score,
        fts_score=fts_score,
    )
