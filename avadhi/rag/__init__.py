"""
avadhi/rag/ — Advanced RAG Pipeline
──────────────────────────────────────────────────────────────────────────────
A 4-stage production-grade retrieval system for security-domain queries.

Pipeline
────────
  [A]  HyDE Expansion    hyde.py       → Short query  → synthetic vuln doc
  [B]  Hybrid Retrieval  retriever.py  → HNSW × 2 + BM25 FTS → RRF fusion
  [C]  Scoring+Dedup     scoring.py    → Metadata boosts + Jaccard dedup
  [D]  Cross-Encoder     reranker.py   → voyage-rerank-2 precision scoring
  [E]  Context Format    context.py    → Structured context string for LLMs

Modules
────────
  embedder.py   — voyage-code-3 (1024d) + text-embedding-3-small (1536d) wrappers
  retriever.py  — HybridRetriever: 3-way HNSW/FTS + RRF fusion + pre-filters
  hyde.py       — Hypothetical Document Embedding (security-domain prompts)
  reranker.py   — voyage-rerank-2 cross-encoder (Cohere fallback)
  scoring.py    — Metadata-aware score boosts + Jaccard near-dedup
  context.py    — High-level build_rag_context() orchestrator
  pool.py       — Singleton asyncpg pool for retrieval path
"""

from avadhi.rag.context import (
    build_rag_context,
    build_rag_context_sync,
    retrieve_similar_patterns,
    retrieve_methodology_context,
    retrieve_protocol_context,
    retrieve_code_similar,
)
from avadhi.rag.retriever import HybridRetriever, RetrievedChunk
from avadhi.rag.embedder import QueryEmbedder
from avadhi.rag.hyde import expand_query_with_hyde
from avadhi.rag.reranker import rerank
from avadhi.rag.scoring import boost_scores, deduplicate_chunks
from avadhi.rag.pool import get_rag_pool, close_rag_pool

__all__ = [
    # Context builders (main interface for hunters)
    "build_rag_context",
    "build_rag_context_sync",
    "retrieve_similar_patterns",
    "retrieve_methodology_context",
    "retrieve_protocol_context",
    "retrieve_code_similar",
    # Core classes
    "HybridRetriever",
    "RetrievedChunk",
    "QueryEmbedder",
    # Advanced pipeline stages
    "expand_query_with_hyde",
    "rerank",
    "boost_scores",
    "deduplicate_chunks",
    # Pool
    "get_rag_pool",
    "close_rag_pool",
]

