"""
ingestion/config.py
────────────────────────────────────────────────────────────────────────────
Central configuration — all paths, constants, and env-var loading live here.
Import this module everywhere; never hard-code paths or keys in other files.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ── Project root ────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent  # /Avadhi/
DATA = ROOT / "data"


# ── Data source map ─────────────────────────────────────────────────────────
# Maps every data directory to (db_category, db_source_type)
# category  → column value in data_sources / document_embeddings
# source_type → how the data was acquired
SOURCE_MAP: dict[Path, dict] = {
    # ── Web3 Basics ──────────────────────────────────────────────────────────
    DATA / "web3_basics" / "git_repos": {
        "category": "web3_basics",
        "source_type": "github_repo",
    },
    DATA / "web3_basics" / "static_pages": {
        "category": "web3_basics",
        "source_type": "docs_site",
    },
    DATA / "web3_basics" / "articles": {
        "category": "web3_basics",
        "source_type": "blog",
    },
    DATA / "web3_basics" / "pdfs": {
        "category": "web3_basics",
        "source_type": "pdf",
    },
    DATA / "web3_basics" / "substack": {
        "category": "web3_basics",
        "source_type": "substack",
    },
    # ── Bug Patterns ─────────────────────────────────────────────────────────
    DATA / "bug_patterns" / "git_repos": {
        "category": "bug_pattern",
        "source_type": "github_repo",
    },
    DATA / "bug_patterns" / "static_pages": {
        "category": "bug_pattern",
        "source_type": "docs_site",
    },
    DATA / "bug_patterns" / "articles": {
        "category": "bug_pattern",
        "source_type": "blog",
    },
    DATA / "bug_patterns" / "pdfs": {
        "category": "bug_pattern",
        "source_type": "pdf",
    },
    DATA / "bug_patterns" / "substack": {
        "category": "bug_pattern",
        "source_type": "substack",
    },
    # ── Audit Methodology ────────────────────────────────────────────────────
    DATA / "audit_methodology" / "static_pages": {
        "category": "audit_methodology",
        "source_type": "docs_site",
    },
    DATA / "audit_methodology" / "articles": {
        "category": "audit_methodology",
        "source_type": "blog",
    },
    DATA / "audit_methodology" / "substack": {
        "category": "audit_methodology",
        "source_type": "substack",
    },
    # Manual paste (methodology articles that Medium blocked)
    DATA / "manual_paste" / "audit_methodology": {
        "category": "audit_methodology",
        "source_type": "blog",
    },
    # ── Protocols ────────────────────────────────────────────────────────────
    DATA / "protocols" / "git_repos": {
        "category": "protocol",
        "source_type": "github_repo",
    },
    DATA / "protocols" / "static_pages": {
        "category": "protocol",
        "source_type": "docs_site",
    },
    DATA / "protocols" / "articles": {
        "category": "protocol",
        "source_type": "blog",
    },
    DATA / "protocols" / "pdfs": {
        "category": "protocol",
        "source_type": "pdf",
    },
    DATA / "protocols" / "llms_txt": {
        "category": "protocol",
        "source_type": "llms_txt",
    },
    DATA / "protocols" / "substack": {
        "category": "protocol",
        "source_type": "substack",
    },
    # Manual paste (Medium protocol articles)
    DATA / "manual_paste" / "protocols": {
        "category": "protocol",
        "source_type": "blog",
    },
    # Root-level scraped pages (samczsun interview, dacian yul, eigenlayer)
    DATA: {
        "category": "audit_methodology",  # overridden per-file if needed
        "source_type": "blog",
    },
}

# ── File extension → document type ──────────────────────────────────────────
EXT_TO_DOCTYPE: dict[str, str] = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".yul": "yul",
    ".md": "markdown",
    ".rst": "rst",
    ".txt": "plain_text",
    ".html": "html",
    ".pdf": "pdf",
    ".json": "json",
}

# Extensions to process (everything else is skipped)
PROCESSABLE_EXTENSIONS = set(EXT_TO_DOCTYPE.keys())

# Files / directories to always skip
SKIP_PATTERNS = {
    ".git", "__pycache__", "node_modules", ".pytest_cache",
    "artifacts", "cache", "typechain-types", "typechain",
    "coverage", ".nyc_output", "dist", "build",
    # Skip test fixtures and mocks (too noisy, low signal)
    "test", "tests", "mock", "mocks", "fixture", "fixtures",
}

# Minimum file size to process (bytes) — skip empty/tiny files
MIN_FILE_BYTES = 100

# ── Chunking parameters ──────────────────────────────────────────────────────
CHUNK_SIZES = {
    "solidity": {"size": 1500, "overlap": 150},   # ~function-level
    "vyper": {"size": 1500, "overlap": 150},
    "yul": {"size": 1000, "overlap": 100},
    "markdown": {"size": 1200, "overlap": 200},
    "rst": {"size": 1200, "overlap": 200},
    "plain_text": {"size": 1000, "overlap": 150},
    "html": {"size": 1000, "overlap": 150},
    "pdf": {"size": 1000, "overlap": 200},
    "json": {"size": 800, "overlap": 80},
}

# ── Embedding ────────────────────────────────────────────────────────────────
VOYAGE_API_KEY = os.environ["VOYAGE_API_KEY"]
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

# ── HYBRID EMBEDDING STRATEGY ─────────────────────────────────────────────────
#
# Code chunks  → voyage-code-3 @ 1024d (Matryoshka default, HNSW-compatible) → embedding_code
# Text chunks  → text-embedding-3-small @ 1536d                              → embedding_text
#
# NOTE: pgvector HNSW supports max 2000 dimensions, so 1024d is the
# sweet spot for voyage-code-3 (full 2048d requires IVFFlat).
#
# WHY voyage-code-3?
#   • Purpose-built for code retrieval (Solidity, Yul, Vyper, Markdown w/ code)
#   • Outperforms all general-purpose models on code-to-code / text-to-code tasks
#   • Matryoshka dims: 256 | 512 | 1024 (default) | 2048 (max)
#   • We use 1024d for maximum retrieval quality at the cost of ~2x storage
#   • Rate limits (Tier 1, payment added): 2000 RPM, 3M TPM — no throttle needed
#
# WHY text-embedding-3-small for text?
#   • Fast, cheap, very good at prose (methodology articles, audit reports)
#   • 1536d, 8191 token context

CODE_EMBED_MODEL = "voyage-code-3"   # purpose-built for code retrieval
CODE_EMBED_DIMS = 1024               # Matryoshka 1024d — HNSW supports max 2000d
                                     # (2048d would require IVFFlat, 1024d = best HNSW tradeoff)

TEXT_EMBED_MODEL = "text-embedding-3-small"   # prose chunks
TEXT_EMBED_DIMS = 1536

# Voyage Tier 1 limits: 2000 RPM / 3M TPM.  While 128 is the API max items, 
# Voyage enforces a strict 120,000 token limit per batch. 
# Solidity chunks contain intense syntax and generate unusually high token counts. 
# Batches of 50-60 chunks are STILL mathematically crossing 180k tokens in Voyage!
EMBED_BATCH_SIZE = int(os.getenv("EMBED_BATCH_SIZE", "10"))    # Bulletproof token cap
EMBED_CONCURRENCY = int(os.getenv("EMBED_CONCURRENCY", "8"))   # parallel batches

# ── Database ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "2"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "10"))
