"""
ingestion/embedder.py
────────────────────────────────────────────────────────────────────────────
HYBRID embedding strategy:
  • Code chunks  → voyage-code-3  @ 2048d (Matryoshka max) → embedding_code column
  • Text chunks  → text-embedding-3-small @ 1536d           → embedding_text column

Rate limits assumed (Voyage Tier 1, payment method added):
  voyage-code-3  → 2000 RPM / 3M TPM   (no artificial throttle needed)
  OpenAI         → 3000 RPM / 1M TPM   (no artificial throttle needed)

Built on top of langchain-voyageai + langchain-openai.
Handles:
  • Batching (Voyage max 128 per request — we default to 128 from config)
  • Async concurrency (multiple batches in-flight simultaneously)
  • Retry with random exponential backoff on rate-limit / transient errors
  • Proper routing so vectors land in the correct DB column
"""
from __future__ import annotations

import asyncio
import logging

from langchain_openai import OpenAIEmbeddings
from langchain_voyageai import VoyageAIEmbeddings
from tenacity import (
    after_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from ingestion.config import (
    CODE_EMBED_DIMS,
    CODE_EMBED_MODEL,
    EMBED_BATCH_SIZE,
    EMBED_CONCURRENCY,
    OPENAI_API_KEY,
    TEXT_EMBED_MODEL,
    VOYAGE_API_KEY,
)
from ingestion.chunkers import Chunk

logger = logging.getLogger(__name__)

# ── LangChain embedding clients ──────────────────────────────────────────────

# Code → Voyage AI (voyage-code-3, Matryoshka 1024d)
# output_dimension controls which Matryoshka truncation is returned.
# 1024 = HNSW-compatible sweet spot (2048 requires IVFFlat, not HNSW).
_code_embedder = VoyageAIEmbeddings(
    voyage_api_key=VOYAGE_API_KEY,
    model=CODE_EMBED_MODEL,
    output_dimension=CODE_EMBED_DIMS,   # 1024 — Matryoshka, HNSW max=2000d
)

# Text → OpenAI (text-embedding-3-small, 1536d)
_text_embedder = OpenAIEmbeddings(
    openai_api_key=OPENAI_API_KEY,
    model=TEXT_EMBED_MODEL,
)


# ── Retry decorator ───────────────────────────────────────────────────────────
# Random exponential backoff handles transient 429s gracefully.
# Voyage Tier 1 = 2000 RPM — 429s should be rare with proper batching.

embed_retry = retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_random_exponential(multiplier=1, max=60),
    stop=stop_after_attempt(6),
    after=after_log(logger, logging.WARNING),
    reraise=True,
)


# ── Core embed call (sync, wrapped for async) ────────────────────────────────

@embed_retry
def _embed_batch_sync(texts: list[str], is_code: bool) -> list[list[float]]:
    """
    Call the appropriate embedding API synchronously for one batch.
    - is_code=True  → Voyage AI voyage-code-3 (2048d)
    - is_code=False → OpenAI text-embedding-3-small (1536d)
    Returns list of float vectors.
    """
    client = _code_embedder if is_code else _text_embedder
    return client.embed_documents(texts)


async def _embed_batch_async(texts: list[str], is_code: bool) -> list[list[float]]:
    """Run the blocking embedding call in a thread pool so async callers don't block."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _embed_batch_sync, texts, is_code)


# ── Public API ────────────────────────────────────────────────────────────────

async def embed_chunks(chunks: list[Chunk]) -> list[dict]:
    """
    Embed a list of Chunk objects using the HYBRID strategy.

    Routing:
      • has_code=True  → voyage-code-3  → vector stored in embedding_code (2048d)
      • has_code=False → text-embedding-3-small → vector stored in embedding_text (1536d)

    Returns a list of dicts ready to pass to db.batch_insert_embeddings:
        {
          chunk_index, chunk_text, chunk_tokens,
          embedding_code: [...] | None,    ← populated for code chunks  (2048d)
          embedding_text: [...] | None,    ← populated for text chunks  (1536d)
          has_code, code_language, embed_model, tags, subcategory
        }
    """
    if not chunks:
        return []

    # Separate code and text chunks
    code_chunks = [c for c in chunks if c.has_code]
    text_chunks = [c for c in chunks if not c.has_code]

    logger.info(
        "Embedding %d chunks: %d code (voyage-code-3 @2048d) + %d text (text-embedding-3-small @1536d)",
        len(chunks), len(code_chunks), len(text_chunks),
    )

    # Build batches and embed concurrently.
    # Voyage Tier 1 allows 2000 RPM so we can run multiple batches in parallel.
    semaphore = asyncio.Semaphore(EMBED_CONCURRENCY)
    results: dict[int, tuple[list[float], bool]] = {}  # chunk_index → (vector, is_code)

    async def embed_group(group: list[Chunk], is_code: bool) -> None:
        batch_size = EMBED_BATCH_SIZE  # 128 for Voyage (API max), same for OpenAI
        for batch_start in range(0, len(group), batch_size):
            batch = group[batch_start : batch_start + batch_size]
            texts = [c.text for c in batch]
            async with semaphore:
                try:
                    vectors = await _embed_batch_async(texts, is_code)
                    for chunk, vec in zip(batch, vectors):
                        results[chunk.chunk_index] = (vec, is_code)
                except Exception as e:
                    logger.error(
                        "Embedding batch failed (is_code=%s, model=%s, size=%d): %s",
                        is_code,
                        CODE_EMBED_MODEL if is_code else TEXT_EMBED_MODEL,
                        len(batch),
                        e,
                    )
                    raise

    # Code and text batches run concurrently — different APIs, independent rate limits
    await asyncio.gather(
        embed_group(code_chunks, is_code=True),
        embed_group(text_chunks, is_code=False),
    )

    # Assemble output rows — vectors routed to the correct DB column
    output: list[dict] = []
    for chunk in chunks:
        result = results.get(chunk.chunk_index)
        if result is None:
            logger.warning("No vector for chunk_index=%d — skipping", chunk.chunk_index)
            continue

        vec, was_code = result

        output.append({
            "chunk_index":    chunk.chunk_index,
            "chunk_text":     chunk.text,
            "chunk_tokens":   chunk.token_estimate,
            "embedding_code": vec if was_code else None,      # voyage-code-3 (2048d)
            "embedding_text": vec if not was_code else None,   # text-embedding-3-small (1536d)
            "has_code":       chunk.has_code,
            "code_language":  chunk.code_language,
            "tags":           chunk.tags,
            "subcategory":    chunk.subcategory,
            "embed_model":    CODE_EMBED_MODEL if was_code else TEXT_EMBED_MODEL,
        })

    return output
