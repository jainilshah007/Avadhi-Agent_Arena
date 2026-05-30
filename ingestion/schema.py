"""
ingestion/schema.py
────────────────────────────────────────────────────────────────────────────
All CREATE TABLE / CREATE INDEX DDL statements.
Run apply_schema(pool) once at startup — every statement uses IF NOT EXISTS
so it is fully idempotent (safe to run on every startup).
"""
from __future__ import annotations

import asyncpg

# ── Ordered list of DDL statements ──────────────────────────────────────────
# Order matters: referenced tables must exist before foreign-key tables.
DDL_STATEMENTS: list[str] = [

    # ── pgvector extension ────────────────────────────────────────────────────
    "CREATE EXTENSION IF NOT EXISTS vector",

    # ── TIER 1: Raw data sources ──────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS data_sources (
        id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name             TEXT NOT NULL,
        category         TEXT NOT NULL,        -- bug_pattern | audit_methodology | protocol | web3_basics
        source_type      TEXT NOT NULL,        -- github_repo | blog | pdf | docs_site | substack | llms_txt
        url              TEXT UNIQUE,
        scrape_method    TEXT,                 -- git_clone | requests | playwright | pdf_parse | manual
        license          TEXT,
        scraped_at       TIMESTAMPTZ,
        raw_size_bytes   BIGINT,
        clean_size_bytes BIGINT,
        search_vector    TSVECTOR GENERATED ALWAYS AS (
                             to_tsvector('english',
                                 coalesce(name, '') || ' ' || coalesce(url, ''))
                         ) STORED,
        metadata         JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sources_search ON data_sources USING GIN(search_vector)",
    "CREATE INDEX IF NOT EXISTS idx_sources_category ON data_sources(category)",

    # ── TIER 1: Raw documents (one row per file) ──────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS raw_documents (
        id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_id      UUID NOT NULL REFERENCES data_sources(id) ON DELETE CASCADE,
        file_path      TEXT NOT NULL,          -- relative path within source root
        title          TEXT,
        content_raw    TEXT,                   -- original content (may be large)
        content_clean  TEXT,                   -- cleaned / stripped content
        doc_type       TEXT NOT NULL,          -- solidity | markdown | pdf | html | plain_text | …
        language       TEXT NOT NULL DEFAULT 'en',
        word_count     INT,
        char_count     INT,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        search_vector  TSVECTOR GENERATED ALWAYS AS (
                           to_tsvector('english',
                               coalesce(title, '') || ' ' || coalesce(file_path, ''))
                       ) STORED,
        metadata       JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_docs_source_path ON raw_documents(source_id, file_path)",
    "CREATE INDEX IF NOT EXISTS idx_docs_search ON raw_documents USING GIN(search_vector)",
    "CREATE INDEX IF NOT EXISTS idx_docs_source ON raw_documents(source_id)",
    "CREATE INDEX IF NOT EXISTS idx_docs_type ON raw_documents(doc_type)",

    # ── TIER 2: Vulnerability patterns ───────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS vulnerability_patterns (
        id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_id               UUID REFERENCES data_sources(id),
        name                    TEXT NOT NULL,
        vulnerability_class     TEXT NOT NULL,   -- reentrancy | access_control | oracle_manipulation …
        severity                TEXT,            -- critical | high | medium | low | informational
        swc_id                  TEXT,            -- SWC-107
        owasp_id                TEXT,
        dasp_id                 TEXT,
        description             TEXT NOT NULL,
        detection_heuristic     TEXT,
        fix_pattern             TEXT,
        code_example_vulnerable TEXT,
        code_example_fixed      TEXT,
        applies_to              TEXT[],          -- ['erc20', 'lending', 'amm']
        tags                    TEXT[],
        metadata                JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_class ON vulnerability_patterns(vulnerability_class)",
    "CREATE INDEX IF NOT EXISTS idx_vuln_tags ON vulnerability_patterns USING GIN(tags)",
    "CREATE INDEX IF NOT EXISTS idx_vuln_applies ON vulnerability_patterns USING GIN(applies_to)",

    # ── TIER 2: Audit methodologies ──────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS audit_methodologies (
        id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_id         UUID REFERENCES data_sources(id),
        author            TEXT,
        methodology_name  TEXT,
        audit_phase       TEXT,             -- setup | recon | analysis | reporting
        thinking_framework TEXT,            -- sink_source | state_machine | invariant
        description       TEXT NOT NULL,
        steps             JSONB,            -- ordered steps as JSON array
        tools_referenced  TEXT[],
        applies_to        TEXT[],
        metadata          JSONB NOT NULL DEFAULT '{}'
    )
    """,

    # ── TIER 2: Protocols ─────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS protocols (
        id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name                  TEXT NOT NULL UNIQUE,
        category              TEXT NOT NULL,  -- amm | lending | bridge | oracle | lsd | perp | stablecoin
        github_urls           TEXT[],
        docs_url              TEXT,
        whitepaper_url        TEXT,
        llms_txt_url          TEXT,
        contract_language     TEXT NOT NULL DEFAULT 'solidity',
        has_upgradeable_proxy BOOLEAN NOT NULL DEFAULT false,
        has_flash_loans       BOOLEAN NOT NULL DEFAULT false,
        uses_oracle           BOOLEAN NOT NULL DEFAULT false,
        oracle_type           TEXT,          -- chainlink | twap | custom
        key_mechanisms        TEXT[],
        metadata              JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_protocols_category ON protocols(category)",
    "CREATE INDEX IF NOT EXISTS idx_protocols_mechanisms ON protocols USING GIN(key_mechanisms)",

    # ── TIER 2: Audit reports ─────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS audit_reports (
        id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        protocol_id      UUID REFERENCES protocols(id),
        source_id        UUID REFERENCES data_sources(id),
        auditor          TEXT NOT NULL,
        audit_date       DATE,
        report_url       TEXT,
        report_type      TEXT,              -- full_audit | competition | incremental | formal_verification
        findings_summary JSONB,            -- {critical: 2, high: 5, medium: 12, low: 8}
        content_text     TEXT,
        version_audited  TEXT,
        metadata         JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_reports_protocol ON audit_reports(protocol_id)",
    "CREATE INDEX IF NOT EXISTS idx_reports_auditor ON audit_reports(auditor)",

    # ── TIER 2: Protocol contracts ────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS protocol_contracts (
        id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        protocol_id         UUID REFERENCES protocols(id),
        source_doc_id       UUID REFERENCES raw_documents(id) ON DELETE CASCADE,
        file_path           TEXT NOT NULL,   -- contracts/core/Pool.sol
        contract_name       TEXT,
        contract_type       TEXT,            -- core | periphery | library | interface
        solidity_version    TEXT,
        code_content        TEXT NOT NULL,
        loc                 INT,
        has_external_calls  BOOLEAN NOT NULL DEFAULT false,
        uses_assembly       BOOLEAN NOT NULL DEFAULT false,
        uses_delegatecall   BOOLEAN NOT NULL DEFAULT false,
        imports             TEXT[],
        metadata            JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_contracts_protocol ON protocol_contracts(protocol_id)",
    "CREATE INDEX IF NOT EXISTS idx_contracts_type ON protocol_contracts(contract_type)",

    # ── TIER 2: Web3 references ───────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS web3_references (
        id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_id             UUID REFERENCES data_sources(id),
        ref_type              TEXT NOT NULL,  -- eip | erc | opcode | solidity_feature | compiler_bug
        ref_id                TEXT,           -- EIP-1559 | ERC-4626 | SSTORE
        title                 TEXT,
        status                TEXT,           -- final | draft | stagnant
        description           TEXT NOT NULL,
        security_implications TEXT,
        code_example          TEXT,
        tags                  TEXT[],
        metadata              JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_web3ref_type ON web3_references(ref_type)",
    "CREATE INDEX IF NOT EXISTS idx_web3ref_tags ON web3_references USING GIN(tags)",

    # ── TIER 2: Compiler bugs ─────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS compiler_bugs (
        id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        bug_name          TEXT NOT NULL UNIQUE,
        severity          TEXT,
        affected_versions TEXT[],
        fixed_in          TEXT,
        description       TEXT,
        detection_pattern TEXT,
        metadata          JSONB NOT NULL DEFAULT '{}'
    )
    """,

    # ── TIER 3: Embeddings ────────────────────────────────────────────────────
    # voyage-code-3 @ 2048d (Matryoshka max) → embedding_code
    # text-embedding-3-small @ 1536d         → embedding_text
    """
    CREATE TABLE IF NOT EXISTS document_embeddings (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_doc_id   UUID NOT NULL REFERENCES raw_documents(id) ON DELETE CASCADE,

        -- Domain entity backlinks (at most one non-NULL per row)
        vuln_pattern_id UUID REFERENCES vulnerability_patterns(id),
        methodology_id  UUID REFERENCES audit_methodologies(id),
        protocol_id     UUID REFERENCES protocols(id),
        web3_ref_id     UUID REFERENCES web3_references(id),

        chunk_index     INT NOT NULL,
        chunk_text      TEXT NOT NULL,
        chunk_tokens    INT,

        -- DUAL EMBEDDING COLUMNS
        -- Code chunks  → voyage-code-3 @ 1024d (Matryoshka, HNSW max=2000d) → embedding_code
        -- Text chunks  → text-embedding-3-small @ 1536d                       → embedding_text
        embedding_code  vector(1024),   -- voyage-code-3 (1024d Matryoshka)
        embedding_text  vector(1536),   -- text-embedding-3-small (OpenAI)

        -- BM25 column for keyword-based hybrid retrieval
        search_vector   TSVECTOR GENERATED ALWAYS AS (
                            to_tsvector('english', chunk_text)
                        ) STORED,

        -- Metadata used as pre-filters before vector search
        category        TEXT NOT NULL,
        subcategory     TEXT,
        tags            TEXT[],
        has_code        BOOLEAN NOT NULL DEFAULT false,
        code_language   TEXT,           -- solidity | vyper | yul
        embed_model     TEXT NOT NULL,  -- which model populated the vectors
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (source_doc_id, chunk_index)
    )
    """,
    # Partial HNSW indexes — each only covers rows where that column is non-NULL.
    """
    CREATE INDEX IF NOT EXISTS idx_embed_code ON document_embeddings
        USING hnsw (embedding_code vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
        WHERE embedding_code IS NOT NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_embed_text ON document_embeddings
        USING hnsw (embedding_text vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
        WHERE embedding_text IS NOT NULL
    """,
    "CREATE INDEX IF NOT EXISTS idx_embed_fts ON document_embeddings USING GIN(search_vector)",
    "CREATE INDEX IF NOT EXISTS idx_embed_category ON document_embeddings(category)",
    "CREATE INDEX IF NOT EXISTS idx_embed_subcategory ON document_embeddings(subcategory)",
    "CREATE INDEX IF NOT EXISTS idx_embed_tags ON document_embeddings USING GIN(tags)",
    "CREATE INDEX IF NOT EXISTS idx_embed_has_code ON document_embeddings(has_code)",
    "CREATE INDEX IF NOT EXISTS idx_embed_source_doc ON document_embeddings(source_doc_id)",

    # ── TIER 4: Knowledge graph ───────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS knowledge_edges (
        id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        source_node_id   UUID NOT NULL,
        source_node_type TEXT NOT NULL,    -- vulnerability_pattern | protocol | methodology
        target_node_id   UUID NOT NULL,
        target_node_type TEXT NOT NULL,
        relationship     TEXT NOT NULL,    -- exploits | mitigates | applies_to | detected_by | similar_to
        weight           FLOAT NOT NULL DEFAULT 1.0,
        evidence         TEXT,
        metadata         JSONB NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_edges_source ON knowledge_edges(source_node_id, source_node_type)",
    "CREATE INDEX IF NOT EXISTS idx_edges_target ON knowledge_edges(target_node_id, target_node_type)",
    "CREATE INDEX IF NOT EXISTS idx_edges_relationship ON knowledge_edges(relationship)",
]


async def apply_schema(pool: asyncpg.Pool) -> None:
    """
    Run all DDL statements. Safe to call on every startup — all statements
    use IF NOT EXISTS so they are fully idempotent.
    """
    async with pool.acquire() as conn:
        for stmt in DDL_STATEMENTS:
            stmt = stmt.strip()
            if stmt:
                await conn.execute(stmt)
