"""
avadhi/rag/context.py
──────────────────────────────────────────────────────────────────────────────
High-level context builder — the main interface between the RAG layer and
the LLM hunter/critic orchestration.

FULL ADVANCED RAG PIPELINE
────────────────────────────

  Query
    │
    ├─► [A] HyDE Expansion (optional, ~0.5s)
    │       LLM generates a hypothetical vulnerability doc
    │       → embed THAT for better semantic alignment
    │
    ├─► [B] Multi-Query Decomposition (for complex queries)
    │       Split "flash loan + oracle + reentrancy" into 3 sub-queries
    │       → retrieve for each, merge candidate pools
    │
    ▼
  [Stage 1] Hybrid Bi-Encoder Retrieval  (fast, broad)
    ├── voyage-code-3 HNSW search    → top 40 code candidates
    ├── text-embedding-3-small HNSW  → top 40 text candidates
    └── TSVector BM25 FTS            → top 40 keyword candidates
    └── Reciprocal Rank Fusion → merged top 80 candidates
    │
    ▼
  [Stage 2] Metadata Scoring (no API, <1ms)
    ├── Boost:   has_code + code-query, bug_pattern, tag overlap, methodology
    └── Penalty: web3_basics, tiny chunks
    │
    ▼
  [Stage 3] Semantic Deduplication (no API, <5ms)
    └── Jaccard shingle similarity → remove near-duplicates
    │
    ▼
  [Stage 4] Cross-Encoder Reranking  (voyage-rerank-2, ~0.5s)
    └── Precise token-level relevance scoring on top 40 candidates
    │
    ▼
  Final top-K chunks → formatted context string
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import asyncpg

from avadhi.rag.retriever import HybridRetriever, RetrievedChunk
from avadhi.rag.reranker import rerank
from avadhi.rag.scoring import boost_scores, deduplicate_chunks
from avadhi.rag.hyde import expand_query_with_hyde

if TYPE_CHECKING:
    from avadhi.core.graph import SecurityGraph

logger = logging.getLogger(__name__)


# ── Main Pipeline ─────────────────────────────────────────────────────────────


async def build_rag_context(
    query: str,
    pool: asyncpg.Pool,
    *,
    sg: "SecurityGraph | None" = None,
    top_k: int = 8,
    include_methodology: bool = True,
    include_protocol: bool = True,
    max_chars: int = 12_000,
    use_hyde: bool = True,
    use_reranker: bool = True,
    vulnerability_type: str | None = None,
) -> str:
    """
    Build a complete, formatted RAG context string for LLM injection.

    Runs the full advanced RAG pipeline:
    HyDE → Hybrid Retrieval → Metadata Boost → Dedup → Rerank → Format

    Args:
        query:              The vulnerability or analysis query.
        pool:               Shared asyncpg connection pool.
        sg:                 Optional SecurityGraph for protocol-aware retrieval.
        top_k:              Final number of chunks per category to include.
        include_methodology: Include audit methodology context.
        include_protocol:   Include protocol-specific context.
        max_chars:          Hard cap on context string length.
        use_hyde:           Whether to use HyDE query expansion (default True).
        use_reranker:       Whether to run cross-encoder reranking (default True).
        vulnerability_type: Category hint for HyDE ("reentrancy", "oracle", etc.)

    Returns:
        Formatted multi-section context string ready for LLM system prompt.
    """
    # ── Step 0: Determine protocol context ────────────────────────────────────
    protocol_type = "defi"
    if sg is not None:
        enrichment = sg.metadata.get("enrichment_data", {})
        protocol_type = enrichment.get("protocol_type", "defi")

    # ── Step 1: HyDE — generate a hypothetical vulnerability doc ──────────────
    effective_query = query
    hyde_doc: str | None = None
    if use_hyde:
        hyde_doc = await expand_query_with_hyde(
            query,
            vulnerability_type=vulnerability_type,
        )
        if hyde_doc and hyde_doc != query:
            effective_query = hyde_doc
            logger.debug("HyDE active: using expanded query (%d chars)", len(hyde_doc))

    # ── Step 2: Parallel retrieval across all categories ─────────────────────
    # Over-fetch generously so reranker has enough candidates for precision
    fetch_k = max(top_k * 6, 40)

    retriever = HybridRetriever(pool=pool, top_k=fetch_k, ef_search=120)

    tasks = [
        # Bug patterns: use HyDE-expanded query for maximum recall
        retriever.retrieve(effective_query, category="bug_pattern"),
    ]
    if include_methodology:
        # Methodology: raw query works better (it's about process, not exploit mechanics)
        tasks.append(retriever.retrieve(query, category="audit_methodology", top_k=fetch_k // 2))
    if include_protocol:
        # Protocol: combine protocol type with query
        tasks.append(retriever.retrieve(
            f"{protocol_type} {query}",
            category="protocol",
            top_k=fetch_k // 2,
        ))

    results = await asyncio.gather(*tasks)

    pattern_chunks: list[RetrievedChunk] = results[0]
    methodology_chunks: list[RetrievedChunk] = results[1] if include_methodology else []
    protocol_chunks: list[RetrievedChunk] = results[2] if include_protocol else []

    # ── Step 3: Metadata boost + dedup per category ───────────────────────────
    pattern_chunks = boost_scores(pattern_chunks, query)
    pattern_chunks = deduplicate_chunks(pattern_chunks)

    methodology_chunks = boost_scores(methodology_chunks, query)
    methodology_chunks = deduplicate_chunks(methodology_chunks)

    protocol_chunks = boost_scores(protocol_chunks, query)
    protocol_chunks = deduplicate_chunks(protocol_chunks)

    # ── Step 4: Cross-encoder reranking ──────────────────────────────────────
    # Rerank each category separately so the reranker judges within-category relevance
    if use_reranker:
        rerank_top = top_k * 2  # rerank more than final top_k for headroom
        pattern_chunks, methodology_chunks, protocol_chunks = await asyncio.gather(
            rerank(query, pattern_chunks,     top_k=rerank_top),
            rerank(query, methodology_chunks, top_k=min(rerank_top, top_k + 2)),
            rerank(query, protocol_chunks,    top_k=min(rerank_top, top_k + 2)),
        )

    # ── Step 5: Final truncation to top_k ─────────────────────────────────────
    pattern_chunks    = _use_rerank_or_rrf(pattern_chunks,    top_k,          use_reranker)
    methodology_chunks = _use_rerank_or_rrf(methodology_chunks, min(top_k, 4), use_reranker)
    protocol_chunks   = _use_rerank_or_rrf(protocol_chunks,   min(top_k, 4), use_reranker)

    # ── Step 6: Format into context string ───────────────────────────────────
    sections: list[str] = []
    running_chars = 0
    # NOTE: HyDE doc is used for retrieval only — NOT injected into the context
    # string. Injecting it cost ~400 chars of token budget with zero LLM value.

    def _format_section(title: str, chunks: list[RetrievedChunk]) -> str:
        nonlocal running_chars
        if not chunks:
            return ""
        lines = [f"\n## {title}"]
        for i, chunk in enumerate(chunks, start=1):
            tag_str = f"({', '.join(chunk.tags[:4])})" if chunk.tags else ""
            cat_str = chunk.subcategory or chunk.category
            rerank_info = f" rerank={chunk.rerank_score:.3f}" if hasattr(chunk, "rerank_score") and chunk.rerank_score else ""
            header = f"[{i}] {tag_str} [{cat_str}]{rerank_info}"
            text = chunk.chunk_text[:900].replace("\n", " ").strip()
            entry = f"{header}\n{text}"
            if running_chars + len(entry) > max_chars:
                break
            lines.append(entry)
            running_chars += len(entry)
        return "\n".join(lines)

    sections.append(_format_section("RAG Context: Vulnerability Patterns", pattern_chunks))
    sections.append(_format_section("RAG Context: Audit Methodology", methodology_chunks))
    sections.append(_format_section("RAG Context: Protocol Context", protocol_chunks))

    return "\n".join(s for s in sections if s).strip()


# ── Focused Retrieval Helpers (called directly by individual hunters) ─────────


async def retrieve_similar_patterns(
    query: str,
    pool: asyncpg.Pool,
    *,
    top_k: int = 8,
    vulnerability_type: str | None = None,
    use_hyde: bool = True,
    use_reranker: bool = True,
) -> list[RetrievedChunk]:
    """
    Retrieve vulnerability pattern chunks with the full 4-stage pipeline.

    This is the primary function hunters call for bug-pattern retrieval.

    Args:
        query:              Vulnerability description or hypothesis.
        pool:               Shared asyncpg connection pool.
        top_k:              Final number of chunks to return.
        vulnerability_type: Category hint for HyDE.
        use_hyde:           Enable HyDE expansion (default True).
        use_reranker:       Enable cross-encoder reranking (default True).
    """
    fetch_k = max(top_k * 6, 40)

    # Step 1: HyDE expansion
    effective_query = query
    if use_hyde:
        expanded = await expand_query_with_hyde(query, vulnerability_type=vulnerability_type)
        if expanded and expanded != query:
            effective_query = expanded

    # Step 2: Hybrid retrieval
    retriever = HybridRetriever(pool=pool, top_k=fetch_k, ef_search=140)
    candidates = await retriever.retrieve(effective_query, category="bug_pattern")

    # Step 3: Boost + Dedup
    candidates = boost_scores(candidates, query)
    candidates = deduplicate_chunks(candidates)

    # Step 4: Rerank
    if use_reranker:
        candidates = await rerank(query, candidates, top_k=top_k * 2)

    return _use_rerank_or_rrf(candidates, top_k, use_reranker)


async def retrieve_methodology_context(
    query: str,
    pool: asyncpg.Pool,
    *,
    top_k: int = 5,
) -> list[RetrievedChunk]:
    """
    Retrieve audit methodology chunks without HyDE (raw query works better here).
    Still applies dedup but skips reranking for speed.
    """
    retriever = HybridRetriever(pool=pool, top_k=top_k * 3, ef_search=80)
    candidates = await retriever.retrieve(query, category="audit_methodology")
    candidates = deduplicate_chunks(candidates)
    return candidates[:top_k]


async def retrieve_protocol_context(
    query: str,
    pool: asyncpg.Pool,
    *,
    top_k: int = 5,
    tags: list[str] | None = None,
) -> list[RetrievedChunk]:
    """
    Retrieve protocol-specific context chunks with dedup but no HyDE.
    """
    retriever = HybridRetriever(pool=pool, top_k=top_k * 3, ef_search=80)
    candidates = await retriever.retrieve(query, category="protocol", tags=tags)
    candidates = boost_scores(candidates, query)
    candidates = deduplicate_chunks(candidates)
    return candidates[:top_k]


async def retrieve_code_similar(
    code_snippet: str,
    pool: asyncpg.Pool,
    *,
    top_k: int = 6,
) -> list[RetrievedChunk]:
    """
    Pure code-similarity search using voyage-code-3.
    Used by the PoC generator to find real-world exploit code examples.
    No HyDE (the code IS the document — no expansion needed).
    """
    retriever = HybridRetriever(pool=pool, top_k=top_k * 3, ef_search=150)
    candidates = await retriever.retrieve_code_only(
        code_snippet,
        category="bug_pattern",
        has_code=True,
    )
    candidates = deduplicate_chunks(candidates, similarity_threshold=0.88)
    return candidates[:top_k]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _use_rerank_or_rrf(
    chunks: list[RetrievedChunk],
    top_k: int,
    use_reranker: bool,
) -> list[RetrievedChunk]:
    """Sort by rerank_score if available, else by rrf_score."""
    if use_reranker and chunks and hasattr(chunks[0], "rerank_score") and chunks[0].rerank_score:
        chunks.sort(key=lambda c: getattr(c, "rerank_score", 0.0), reverse=True)
    else:
        chunks.sort(key=lambda c: c.rrf_score, reverse=True)
    return chunks[:top_k]


# ── Synchronous wrapper ───────────────────────────────────────────────────────


def build_rag_context_sync(
    query: str,
    pool: asyncpg.Pool,
    **kwargs,
) -> str:
    """
    Sync wrapper around build_rag_context for non-async callers.

    If the provided pool is already usable (e.g., passed from CLI), uses it
    directly. Otherwise creates a temporary pool with pgvector codec registered.
    """
    import asyncio

    async def _run_with_pool():
        return await build_rag_context(query, pool, **kwargs)

    async def _run_with_temp_pool():
        import os
        from pgvector.asyncpg import register_vector

        database_url = os.environ.get("DATABASE_URL", "")
        if not database_url:
            return ""

        async def _init_conn(conn):
            await register_vector(conn)

        temp_pool = await asyncpg.create_pool(
            database_url,
            min_size=1,
            max_size=1,
            init=_init_conn,
        )
        try:
            return await build_rag_context(query, temp_pool, **kwargs)
        finally:
            await temp_pool.close()

    loop = asyncio.new_event_loop()
    try:
        # Try using the provided pool first; fall back to a temp pool
        # if the provided pool isn't compatible with this event loop.
        try:
            return loop.run_until_complete(_run_with_pool())
        except Exception:
            return loop.run_until_complete(_run_with_temp_pool())
    finally:
        loop.close()
