"""
ingestion/run.py
────────────────────────────────────────────────────────────────────────────
CLI entry point.

Usage examples:
  # Dry run — see what would be processed
  python -m ingestion.run --dry-run

  # Ingest everything
  python -m ingestion.run

  # Only protocol Solidity code
  python -m ingestion.run --category protocol --source-type github_repo

  # Only audit methodology articles
  python -m ingestion.run --category audit_methodology

  # Re-embed everything (useful when you change chunking strategy)
  python -m ingestion.run --force-reembed

  # Quick test with first 50 files
  python -m ingestion.run --limit 50 --dry-run

  # Check what's already in the DB
  python -m ingestion.run --stats

  # Search if a specific document was ingested
  python -m ingestion.run --search "uniswap v3 whitepaper"
"""
from __future__ import annotations

import asyncio
import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from ingestion.db import create_pool, get_ingestion_stats, search_documents, search_sources
from ingestion.pipeline import IngestionPipeline
from ingestion.schema import apply_schema

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Immunefi AI Bug Scanner — Ingestion Pipeline"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--category", default=None,
              type=click.Choice(["bug_pattern", "audit_methodology", "protocol", "web3_basics"]),
              help="Only ingest this category")
@click.option("--source-type", default=None,
              type=click.Choice(["github_repo", "blog", "pdf", "docs_site", "substack", "llms_txt"]),
              help="Only ingest this source type")
@click.option("--limit", default=None, type=int,
              help="Process at most N files (useful for testing)")
@click.option("--force-reembed", is_flag=True, default=False,
              help="Re-embed files that are already in the DB")
@click.option("--dry-run", is_flag=True, default=False,
              help="Discover files but do not write to DB")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable debug logging")
def ingest(
    category: str | None,
    source_type: str | None,
    limit: int | None,
    force_reembed: bool,
    dry_run: bool,
    verbose: bool,
) -> None:
    """Run the ingestion pipeline."""
    _setup_logging(verbose)

    async def _run() -> None:
        pipeline = IngestionPipeline()
        try:
            await pipeline.setup()
            await pipeline.run(
                category=category,
                source_type=source_type,
                limit=limit,
                force_reembed=force_reembed,
                dry_run=dry_run,
            )
        finally:
            await pipeline.teardown()

    asyncio.run(_run())


@cli.command()
def stats() -> None:
    """Show current DB ingestion statistics."""
    async def _run() -> None:
        pool = await create_pool()
        try:
            data = await get_ingestion_stats(pool)
        finally:
            await pool.close()

        table = Table(title="Ingestion Stats", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_row("Data sources", str(data["data_sources"]))
        table.add_row("Raw documents", str(data["raw_documents"]))
        table.add_row("Total chunks", str(data["total_chunks"]))
        table.add_row("Embedded documents", str(data["embedded_documents"]))
        
        # Calculate completion against our known ~26,769 file corpus
        TOTAL_FILES = 26769
        embedded = data["embedded_documents"]
        pending = max(0, TOTAL_FILES - embedded)
        completion = (embedded / TOTAL_FILES) * 100
        
        table.add_row("Pending documents", f"{pending:,}")
        table.add_row("Completion", f"{completion:.1f}%")
        console.print(table)

        if data["chunks_by_category"]:
            cat_table = Table(title="Chunks by Category", header_style="bold magenta")
            cat_table.add_column("Category")
            cat_table.add_column("Chunks", justify="right")
            for cat, count in data["chunks_by_category"].items():
                cat_table.add_row(cat, str(count))
            console.print(cat_table)

    asyncio.run(_run())


@cli.command()
@click.argument("query")
def search(query: str) -> None:
    """Check if a document or source is in the DB using plain English.

    Examples:
      python -m ingestion.run search "uniswap v3 whitepaper"
      python -m ingestion.run search "sm4rty audit methodology"
      python -m ingestion.run search "eigenlayer contracts"
    """
    async def _run() -> None:
        pool = await create_pool()
        try:
            sources = await search_sources(pool, query)
            docs = await search_documents(pool, query)
        finally:
            await pool.close()

        if sources:
            t = Table(title=f"Matching Sources for: '{query}'", header_style="bold cyan")
            t.add_column("Name")
            t.add_column("Category")
            t.add_column("Type")
            t.add_column("Ingested At")
            t.add_column("Rank", justify="right")
            for s in sources:
                t.add_row(
                    s["name"], s["category"], s["source_type"],
                    str(s.get("scraped_at", "—"))[:19],
                    f"{s['rank']:.3f}",
                )
            console.print(t)
        else:
            console.print(f"[yellow]No sources found matching: {query}[/yellow]")

        if docs:
            t = Table(title=f"Matching Documents for: '{query}'", header_style="bold green")
            t.add_column("Title")
            t.add_column("File Path")
            t.add_column("Type")
            t.add_column("Source")
            t.add_column("Rank", justify="right")
            for d in docs:
                t.add_row(
                    (d.get("title") or "")[:50],
                    d["file_path"][:60],
                    d["doc_type"],
                    d["source_name"],
                    f"{d['rank']:.3f}",
                )
            console.print(t)
        else:
            console.print(f"[yellow]No documents found matching: {query}[/yellow]")

    asyncio.run(_run())


@cli.command()
def init_schema() -> None:
    """Apply the DB schema without running ingestion (useful for first-time setup)."""
    async def _run() -> None:
        pool = await create_pool(register_pgvector=False)
        try:
            console.print("[bold cyan]Applying schema...[/bold cyan]")
            await apply_schema(pool)
            console.print("[bold green]✓ Schema applied successfully[/bold green]")
        finally:
            await pool.close()

    asyncio.run(_run())


if __name__ == "__main__":
    cli()
