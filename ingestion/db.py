"""
ingestion/db.py
────────────────────────────────────────────────────────────────────────────
Database connection pool + all write helpers.
All functions accept a pool (or connection) so they can participate in
the caller's transaction when needed.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg
from pgvector.asyncpg import register_vector

from ingestion.config import DATABASE_URL, DB_POOL_MAX, DB_POOL_MIN


# ── Pool lifecycle ───────────────────────────────────────────────────────────

async def create_pool(*, register_pgvector: bool = True) -> asyncpg.Pool:
    """Create and return the shared connection pool.

    Args:
        register_pgvector: If True (default), register the pgvector codec on
            each connection.  Set to False when creating a pool for schema
            bootstrapping (before the ``vector`` extension exists).
    """
    init_fn = _init_connection if register_pgvector else None
    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=DB_POOL_MIN,
        max_size=DB_POOL_MAX,
        init=init_fn,
    )
    return pool


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Called for each new connection — registers the pgvector codec."""
    await register_vector(conn)


# ── data_sources helpers ─────────────────────────────────────────────────────

async def upsert_data_source(
    pool: asyncpg.Pool,
    *,
    name: str,
    category: str,
    source_type: str,
    url: str | None = None,
    scrape_method: str | None = None,
    scraped_at: datetime | None = None,
    raw_size_bytes: int | None = None,
    metadata: dict | None = None,
) -> str:
    """
    Insert a data source or return existing one's ID.
    Unique key: url (if provided) or name.
    Returns the UUID string of the row.
    """
    meta = json.dumps(metadata or {})
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO data_sources
                (name, category, source_type, url, scrape_method,
                 scraped_at, raw_size_bytes, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
            ON CONFLICT (url) DO UPDATE SET
                name             = EXCLUDED.name,
                category         = EXCLUDED.category,
                source_type      = EXCLUDED.source_type,
                scrape_method    = EXCLUDED.scrape_method,
                scraped_at       = EXCLUDED.scraped_at,
                raw_size_bytes   = EXCLUDED.raw_size_bytes,
                metadata         = EXCLUDED.metadata
            RETURNING id
            """,
            name, category, source_type, url, scrape_method,
            scraped_at or datetime.now(timezone.utc),
            raw_size_bytes, meta,
        )
        return str(row["id"])


async def get_source_by_name(pool: asyncpg.Pool, name: str) -> dict | None:
    """Fetch a source row by name (for sources without a URL)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name, url, scraped_at FROM data_sources WHERE name = $1",
            name,
        )
        return dict(row) if row else None


# ── raw_documents helpers ────────────────────────────────────────────────────

async def upsert_raw_document(
    pool: asyncpg.Pool,
    *,
    source_id: str,
    file_path: str,
    title: str | None,
    content_raw: str,
    content_clean: str,
    doc_type: str,
    word_count: int | None = None,
    char_count: int | None = None,
    metadata: dict | None = None,
) -> str:
    """
    Insert a document or update it if (source_id, file_path) already exists.
    Returns the UUID string of the row.
    """
    meta = json.dumps(metadata or {})
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO raw_documents
                (source_id, file_path, title, content_raw, content_clean,
                 doc_type, word_count, char_count, metadata)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
            ON CONFLICT (source_id, file_path) DO UPDATE SET
                title         = EXCLUDED.title,
                content_raw   = EXCLUDED.content_raw,
                content_clean = EXCLUDED.content_clean,
                doc_type      = EXCLUDED.doc_type,
                word_count    = EXCLUDED.word_count,
                char_count    = EXCLUDED.char_count,
                metadata      = EXCLUDED.metadata
            RETURNING id
            """,
            source_id, file_path, title, content_raw, content_clean,
            doc_type, word_count, char_count, meta,
        )
        return str(row["id"])


async def is_document_embedded(pool: asyncpg.Pool, doc_id: str) -> bool:
    """Return True if this document already has at least one embedding chunk."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM document_embeddings WHERE source_doc_id = $1::uuid LIMIT 1",
            doc_id,
        )
        return row is not None


async def delete_document_embeddings(pool: asyncpg.Pool, doc_id: str) -> None:
    """Delete all embedding chunks for a document (used when re-embedding)."""
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM document_embeddings WHERE source_doc_id = $1::uuid",
            doc_id,
        )


# ── document_embeddings helpers ──────────────────────────────────────────────

async def batch_insert_embeddings(
    pool: asyncpg.Pool,
    rows: list[dict],
) -> int:
    """
    Bulk-insert embedding chunks.
    Each dict in `rows` must have:
        source_doc_id, chunk_index, chunk_text, chunk_tokens,
        embedding_code (list[float] | None), embedding_text (list[float] | None),
        category, subcategory, tags, has_code, code_language, embed_model
    Skips duplicates (ON CONFLICT DO NOTHING).
    Returns number of rows inserted.
    """
    if not rows:
        return 0

    import numpy as np

    records = []
    for r in rows:
        # Convert Python list → numpy array for pgvector codec
        emb_code = np.array(r["embedding_code"], dtype=np.float32) if r.get("embedding_code") else None
        emb_text = np.array(r["embedding_text"], dtype=np.float32) if r.get("embedding_text") else None

        records.append((
            r["source_doc_id"],
            r.get("vuln_pattern_id"),
            r.get("methodology_id"),
            r.get("protocol_id"),
            r.get("web3_ref_id"),
            r["chunk_index"],
            r["chunk_text"],
            r.get("chunk_tokens"),
            emb_code,
            emb_text,
            r["category"],
            r.get("subcategory"),
            r.get("tags") or [],
            r.get("has_code", False),
            r.get("code_language"),
            r.get("embed_model", "voyage-code-3"),
        ))

    async with pool.acquire() as conn:
        result = await conn.executemany(
            """
            INSERT INTO document_embeddings
                (source_doc_id, vuln_pattern_id, methodology_id, protocol_id, web3_ref_id,
                 chunk_index, chunk_text, chunk_tokens,
                 embedding_code, embedding_text,
                 category, subcategory, tags, has_code, code_language, embed_model)
            VALUES
                ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,
                 $6, $7, $8,
                 $9, $10,
                 $11, $12, $13, $14, $15, $16)
            ON CONFLICT (source_doc_id, chunk_index) DO NOTHING
            """,
            records,
        )
    return len(records)


# ── Existence-check helpers ──────────────────────────────────────────────────

async def search_sources(pool: asyncpg.Pool, query: str) -> list[dict]:
    """
    Plain-English search over data_sources (uses tsvector GIN index).
    Example: search_sources(pool, "uniswap v3 whitepaper")
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT name, category, source_type, url, scraped_at,
                   ts_rank(search_vector, plainto_tsquery('english', $1)) AS rank
            FROM data_sources
            WHERE search_vector @@ plainto_tsquery('english', $1)
            ORDER BY rank DESC
            LIMIT 20
            """,
            query,
        )
        return [dict(r) for r in rows]


async def search_documents(pool: asyncpg.Pool, query: str) -> list[dict]:
    """
    Plain-English search over raw_documents titles and file paths.
    Example: search_documents(pool, "sm4rty audit methodology")
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT rd.title, rd.file_path, rd.doc_type, ds.name AS source_name,
                   ts_rank(rd.search_vector, plainto_tsquery('english', $1)) AS rank
            FROM raw_documents rd
            JOIN data_sources ds ON ds.id = rd.source_id
            WHERE rd.search_vector @@ plainto_tsquery('english', $1)
            ORDER BY rank DESC
            LIMIT 20
            """,
            query,
        )
        return [dict(r) for r in rows]


# ── Stats ────────────────────────────────────────────────────────────────────

async def get_ingestion_stats(pool: asyncpg.Pool) -> dict[str, Any]:
    """Return a summary of what's currently in the DB."""
    async with pool.acquire() as conn:
        sources    = await conn.fetchval("SELECT COUNT(*) FROM data_sources")
        docs       = await conn.fetchval("SELECT COUNT(*) FROM raw_documents")
        chunks     = await conn.fetchval("SELECT COUNT(*) FROM document_embeddings")
        embedded   = await conn.fetchval(
            "SELECT COUNT(DISTINCT source_doc_id) FROM document_embeddings"
        )
        by_category = await conn.fetch(
            """
            SELECT category, COUNT(*) as chunks
            FROM document_embeddings
            GROUP BY category
            ORDER BY chunks DESC
            """
        )
        return {
            "data_sources": sources,
            "raw_documents": docs,
            "total_chunks": chunks,
            "embedded_documents": embedded,
            "chunks_by_category": {r["category"]: r["chunks"] for r in by_category},
        }
