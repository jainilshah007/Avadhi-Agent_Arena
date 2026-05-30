"""
ingestion/pipeline.py
────────────────────────────────────────────────────────────────────────────
Main ingestion orchestrator.

Flow per file:
  1. Discover all processable files in data/
  2. For each file → upsert data_source + raw_document
  3. Skip if already embedded (resume support)
  4. Load + clean content (processors.py)
  5. Chunk content (chunkers.py)
  6. Embed chunks in batches (embedder.py)
  7. Store embedding rows in DB (db.py)
  8. Log progress
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

import asyncpg
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ingestion import config
from ingestion.chunkers import chunk_document
from ingestion.config import (
    EXT_TO_DOCTYPE,
    MIN_FILE_BYTES,
    PROCESSABLE_EXTENSIONS,
    SKIP_PATTERNS,
    SOURCE_MAP,
)
from ingestion.db import (
    batch_insert_embeddings,
    create_pool,
    delete_document_embeddings,
    get_ingestion_stats,
    is_document_embedded,
    upsert_data_source,
    upsert_raw_document,
)
from ingestion.embedder import embed_chunks
from ingestion.processors import process_file
from ingestion.schema import apply_schema

logger = logging.getLogger(__name__)
console = Console()


# ── File discovery ────────────────────────────────────────────────────────────

@dataclass
class FileRecord:
    path: Path
    source_root: Path
    category: str
    source_type: str
    doc_type: str
    rel_path: str = field(init=False)

    def __post_init__(self) -> None:
        self.rel_path = str(self.path.relative_to(self.source_root))


def _should_skip(path: Path) -> bool:
    """Return True if this path should be excluded."""
    for part in path.parts:
        if part.lower() in SKIP_PATTERNS:
            return True
    return False


def discover_files(
    category_filter: str | None = None,
    source_type_filter: str | None = None,
    limit: int | None = None,
) -> list[FileRecord]:
    """
    Walk every directory in SOURCE_MAP and collect all processable files.
    Applies optional filters. Returns a flat list of FileRecord objects.
    """
    records: list[FileRecord] = []

    for source_dir, attrs in SOURCE_MAP.items():
        if not source_dir.exists():
            continue

        cat = attrs["category"]
        stype = attrs["source_type"]

        if category_filter and cat != category_filter:
            continue
        if source_type_filter and stype != source_type_filter:
            continue

        for file_path in source_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if _should_skip(file_path):
                continue
            if file_path.suffix.lower() not in PROCESSABLE_EXTENSIONS:
                continue
            if file_path.stat().st_size < MIN_FILE_BYTES:
                continue
            # Skip error files (*.error from our scraper)
            if file_path.name.endswith(".error"):
                continue

            doc_type = EXT_TO_DOCTYPE.get(file_path.suffix.lower(), "plain_text")

            # Determine the true source root (first-level subdir of source_dir
            # for git repos, or source_dir itself for flat directories)
            if stype == "github_repo":
                # e.g., data/protocols/git_repos/uniswap-v3-core/...
                # source root = data/protocols/git_repos/uniswap-v3-core/
                parts = file_path.relative_to(source_dir).parts
                if parts:
                    true_root = source_dir / parts[0]
                else:
                    true_root = source_dir
            else:
                true_root = source_dir

            records.append(FileRecord(
                path=file_path,
                source_root=true_root,
                category=cat,
                source_type=stype,
                doc_type=doc_type,
            ))

    if limit:
        records = records[:limit]

    return records


# ── Source name extraction ────────────────────────────────────────────────────

def _source_name(record: FileRecord) -> str:
    """Human-readable name for the data_source row."""
    if record.source_type == "github_repo":
        return record.source_root.name  # e.g., "uniswap-v3-core"
    return record.source_root.name


def _source_url(record: FileRecord) -> str | None:
    """Best-effort URL for the source."""
    name = _source_name(record)
    # For known GitHub repos we can reconstruct the URL
    github_map = {
        "uniswap-v3-core": "https://github.com/Uniswap/v3-core",
        "uniswap-v4-core": "https://github.com/Uniswap/v4-core",
        "aave-v3-core":    "https://github.com/aave/aave-v3-core",
        "morpho-blue":     "https://github.com/morpho-org/morpho-blue",
        # … add more as needed. The pipeline works fine without URLs.
    }
    return github_map.get(name)


# ── Per-file ingestion ────────────────────────────────────────────────────────

async def ingest_file(
    file_rec: FileRecord,
    pool: asyncpg.Pool,
    source_id_cache: dict[str, str],
    force_reembed: bool = False,
) -> dict:
    """
    Process a single file end-to-end.
    Returns a status dict: {status: 'embedded'|'skipped'|'error', chunks: int}
    """
    source_name = _source_name(file_rec)

    # 1. Upsert data_source (cached to avoid repeated DB calls for same source)
    if source_name not in source_id_cache:
        source_id = await upsert_data_source(
            pool,
            name=source_name,
            category=file_rec.category,
            source_type=file_rec.source_type,
            url=_source_url(file_rec),
            scrape_method="git_clone" if file_rec.source_type == "github_repo" else "manual",
        )
        source_id_cache[source_name] = source_id
    source_id = source_id_cache[source_name]

    # 2. Process file content
    content_raw, content_clean, title, file_meta = process_file(
        file_rec.path, file_rec.doc_type
    )

    if not content_clean or len(content_clean.strip()) < 50:
        return {"status": "skipped", "reason": "empty_content", "chunks": 0}

    # 3. Upsert raw_document
    doc_id = await upsert_raw_document(
        pool,
        source_id=source_id,
        file_path=file_rec.rel_path,
        title=title,
        content_raw=content_raw,
        content_clean=content_clean,
        doc_type=file_rec.doc_type,
        word_count=len(content_clean.split()),
        char_count=len(content_clean),
        metadata=file_meta,
    )

    # 4. Skip if already embedded (unless force_reembed)
    if not force_reembed and await is_document_embedded(pool, doc_id):
        return {"status": "skipped", "reason": "already_embedded", "chunks": 0}

    if force_reembed:
        await delete_document_embeddings(pool, doc_id)

    # 5. Chunk
    chunks = chunk_document(content_clean, file_rec.doc_type, file_rec.rel_path)
    if not chunks:
        return {"status": "skipped", "reason": "no_chunks", "chunks": 0}

    # 6. Embed
    try:
        embedded_rows = await embed_chunks(chunks)
    except Exception as e:
        logger.error("Embedding failed for %s: %s", file_rec.path, e)
        return {"status": "error", "reason": str(e), "chunks": 0}

    # 7. Attach metadata and store
    for row in embedded_rows:
        row["source_doc_id"] = doc_id
        row["category"] = file_rec.category

    inserted = await batch_insert_embeddings(pool, embedded_rows)

    return {"status": "embedded", "chunks": inserted}


# ── Main pipeline ─────────────────────────────────────────────────────────────

class IngestionPipeline:
    def __init__(self) -> None:
        self.pool: asyncpg.Pool | None = None

    async def setup(self) -> None:
        """Connect to DB and apply schema."""
        console.print("[bold cyan]Connecting to Neon DB...[/bold cyan]")
        self.pool = await create_pool()
        console.print("[bold cyan]Applying schema (idempotent)...[/bold cyan]")
        await apply_schema(self.pool)
        console.print("[bold green]✓ Schema ready[/bold green]")

    async def teardown(self) -> None:
        if self.pool:
            await self.pool.close()

    async def run(
        self,
        category: str | None = None,
        source_type: str | None = None,
        limit: int | None = None,
        force_reembed: bool = False,
        dry_run: bool = False,
    ) -> None:
        """Run the full ingestion pipeline."""
        console.print(f"\n[bold]Discovering files[/bold] (category={category or 'all'})...")
        files = discover_files(
            category_filter=category,
            source_type_filter=source_type,
            limit=limit,
        )
        console.print(f"Found [bold cyan]{len(files)}[/bold cyan] files to process")

        if dry_run:
            console.print("[yellow]DRY RUN — no DB writes[/yellow]")
            for f in files[:20]:
                console.print(f"  {f.category}/{f.doc_type}  {f.rel_path}")
            if len(files) > 20:
                console.print(f"  ... and {len(files) - 20} more")
            return

        source_id_cache: dict[str, str] = {}
        stats = {"embedded": 0, "skipped": 0, "errors": 0, "total_chunks": 0}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Ingesting...", total=len(files))

            for file_rec in files:
                progress.update(
                    task,
                    description=f"[cyan]{file_rec.category}[/cyan] {file_rec.path.name[:40]}",
                )
                result = await ingest_file(
                    file_rec, self.pool, source_id_cache, force_reembed
                )
                status = result["status"]
                stats[status if status in stats else "errors"] += 1
                stats["total_chunks"] += result.get("chunks", 0)
                progress.advance(task)

        # Final summary
        console.print("\n[bold green]✓ Ingestion complete[/bold green]")
        console.print(f"  Embedded:     {stats['embedded']}")
        console.print(f"  Skipped:      {stats['skipped']}")
        console.print(f"  Errors:       {stats['errors']}")
        console.print(f"  Total chunks: {stats['total_chunks']}")

        # DB stats
        db_stats = await get_ingestion_stats(self.pool)
        console.print("\n[bold]Current DB state:[/bold]")
        console.print(f"  Data sources:  {db_stats['data_sources']}")
        console.print(f"  Documents:     {db_stats['raw_documents']}")
        console.print(f"  Total chunks:  {db_stats['total_chunks']}")
        console.print(f"  By category:   {db_stats['chunks_by_category']}")
