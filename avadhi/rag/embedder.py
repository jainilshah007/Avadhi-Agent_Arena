"""
avadhi/rag/embedder.py
──────────────────────────────────────────────────────────────────────────────
Thin, synchronous-safe embedding wrappers for the retrieval layer.

Two models are in play — mirroring exactly what was used during ingestion:

  • voyage-code-3  @ 1024d (Matryoshka)  → embedding_code column
  • text-embedding-3-small @ 1536d        → embedding_text column

The QueryEmbedder.embed() method decides which model to use based on the
`is_code` flag (default: auto-detect from content heuristics).
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from typing import List

import numpy as np

logger = logging.getLogger(__name__)

# ── Dimension constants — must match ingestion/config.py ────────────────────
CODE_EMBED_DIMS = 1024
TEXT_EMBED_DIMS = 1536
CODE_MODEL = "voyage-code-3"
TEXT_MODEL = "text-embedding-3-small"

# Heuristics: if the query contains any of these keywords, treat it as code.
_CODE_SIGNALS = re.compile(
    r"\b(function|contract|mapping|address|uint|int\d*|bytes\d*|"
    r"revert|require|emit|delegatecall|assembly|solidity|modifier|"
    r"receive\(\)|fallback\(\)|abi\.encode|msg\.sender|tx\.origin)\b",
    re.IGNORECASE,
)


def _looks_like_code(text: str) -> bool:
    """Return True if the query text contains Solidity / EVM keywords."""
    return bool(_CODE_SIGNALS.search(text))


@lru_cache(maxsize=1)
def _get_voyage_client():
    """Lazily initialize the Voyage AI client (cached singleton)."""
    try:
        import voyageai  # type: ignore
        api_key = os.environ.get("VOYAGE_API_KEY", "")
        if not api_key:
            raise RuntimeError("VOYAGE_API_KEY not set")
        return voyageai.Client(api_key=api_key)
    except ImportError as e:
        raise ImportError("voyageai package not installed. Run: pip install voyageai") from e


@lru_cache(maxsize=1)
def _get_openai_client():
    """Lazily initialize the OpenAI client (cached singleton)."""
    try:
        from openai import OpenAI  # type: ignore
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        return OpenAI(api_key=api_key)
    except ImportError as e:
        raise ImportError("openai package not installed. Run: pip install openai") from e


class QueryEmbedder:
    """
    Converts query strings into numpy vectors for HNSW similarity search.

    Usage
    ─────
        embedder = QueryEmbedder()

        # Auto-detect model based on content:
        vec, model = embedder.embed("delegatecall pattern in ERC-2535")

        # Force a specific model:
        vec, model = embedder.embed("...", is_code=True)   # voyage-code-3
        vec, model = embedder.embed("...", is_code=False)  # text-embedding-3-small
    """

    def embed(
        self,
        query: str,
        *,
        is_code: bool | None = None,
    ) -> tuple[np.ndarray, str]:
        """
        Embed a single query string.

        Args:
            query:   The text to embed.
            is_code: If None, auto-detects from content heuristics.
                     If True, uses voyage-code-3 (1024d).
                     If False, uses text-embedding-3-small (1536d).

        Returns:
            (vector: np.ndarray, model_name: str)
        """
        if is_code is None:
            is_code = _looks_like_code(query)

        if is_code:
            return self._embed_voyage(query), CODE_MODEL
        else:
            return self._embed_openai(query), TEXT_MODEL

    def embed_both(self, query: str) -> tuple[np.ndarray, np.ndarray]:
        """
        Embed the query with BOTH models.
        Useful for hybrid retrieval where we want to search both columns
        simultaneously.

        Returns:
            (code_vector: np.ndarray[1024], text_vector: np.ndarray[1536])
        """
        code_vec = self._embed_voyage(query)
        text_vec = self._embed_openai(query)
        return code_vec, text_vec

    # ── Private helpers ──────────────────────────────────────────────────────

    def _embed_voyage(self, query: str) -> np.ndarray:
        """Call voyage-code-3, return 1024d numpy vector."""
        client = _get_voyage_client()
        result = client.embed(
            [query],
            model=CODE_MODEL,
            input_type="query",
            output_dimension=CODE_EMBED_DIMS,
        )
        vec = np.array(result.embeddings[0], dtype=np.float32)
        logger.debug("Voyage embed: %d dims, model=%s", len(vec), CODE_MODEL)
        return vec

    def _embed_openai(self, query: str) -> np.ndarray:
        """Call text-embedding-3-small, return 1536d numpy vector."""
        client = _get_openai_client()
        response = client.embeddings.create(
            input=[query],
            model=TEXT_MODEL,
        )
        vec = np.array(response.data[0].embedding, dtype=np.float32)
        logger.debug("OpenAI embed: %d dims, model=%s", len(vec), TEXT_MODEL)
        return vec
