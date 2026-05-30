"""
avadhi/rag/pool.py
──────────────────────────────────────────────────────────────────────────────
Singleton asyncpg connection pool for the RAG retrieval layer.

The ingestion/ module has its own pool lifecycle (managed by run.py).
This module creates a SEPARATE cached pool specifically for the retrieval
path used by the hunter agents at audit-time.

Usage
─────
    from avadhi.rag.pool import get_rag_pool

    pool = await get_rag_pool()
    chunks = await retriever.retrieve("reentrancy ...", pool=pool)
"""

from __future__ import annotations

import asyncio
import logging
import os

import asyncpg
from pgvector.asyncpg import register_vector

logger = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None
_pool_lock = asyncio.Lock()


async def get_rag_pool(
    *,
    min_size: int = 1,
    max_size: int = 5,
) -> asyncpg.Pool:
    """
    Return the shared asyncpg pool, creating it lazily on first call.
    The pool is a process-level singleton — safe for concurrent hunters.

    Args:
        min_size:  Minimum number of connections to maintain.
        max_size:  Maximum number of simultaneous connections.
    """
    global _pool

    if _pool is not None:
        return _pool

    async with _pool_lock:
        # Double-check after acquiring the lock
        if _pool is not None:
            return _pool

        database_url = os.environ.get("DATABASE_URL", "")
        if not database_url:
            raise RuntimeError(
                "DATABASE_URL environment variable is not set. "
                "Check your .env file."
            )

        logger.info("Creating RAG connection pool → %s", _mask_url(database_url))

        _pool = await asyncpg.create_pool(
            database_url,
            min_size=min_size,
            max_size=max_size,
            init=_init_connection,
        )
        logger.info("✓ RAG pool ready (min=%d, max=%d)", min_size, max_size)
        return _pool


async def close_rag_pool() -> None:
    """Gracefully close the shared pool. Call on process shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("RAG pool closed.")


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Register the pgvector codec on every new connection."""
    await register_vector(conn)


def _mask_url(url: str) -> str:
    """Replace the password in the URL for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        masked = parsed._replace(netloc=parsed.netloc.replace(
            parsed.password or "", "****"
        ))
        return urlunparse(masked)
    except Exception:
        return "***"
