"""
avadhi/cli.py — CLI entry point.

Usage:
    python -m avadhi scan ./path/to/contracts
    python -m avadhi scan ./contracts --enrich        # Add LLM enrichment
    python -m avadhi scan ./contracts --viz            # Open graph in browser
    python -m avadhi scan ./contracts --output out/    # Custom output dir
    python -m avadhi inspect graph.json               # Load & inspect saved graph
"""
from __future__ import annotations

import time
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from avadhi.recon.runner import run_recon
from avadhi.viz.export import export_graph_html
from avadhi.utils.logging import AuditLogger

app = typer.Typer(
    name="avadhi",
    help="🔒 Avadhi — Multi-Agent Smart Contract Security Auditor",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to Solidity contracts directory"),
    output: str = typer.Option(".avadhi_output", "--output", "-o",
                               help="Output directory"),
    scope: str = typer.Option("", help="Comma-separated file names to scope"),
    enrich: bool = typer.Option(False, "--enrich", "-e",
                                help="Run LLM enrichment (Phase 1c)"),
    viz: bool = typer.Option(False, "--viz", help="Open graph visualization in browser"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    Run security scan on a Solidity project.

    Phase 1a: Structural analysis → SecurityGraph
    Phase 1b: Pattern detection → flags
    Phase 1c: LLM enrichment → invariants, trust model (with --enrich)
    """
    console.print("\n[bold cyan]🔒 Avadhi Security Auditor[/bold cyan]")
    console.print(f"[dim]   Target: {target}[/dim]")
    console.print(f"[dim]   Output: {output}[/dim]")
    if enrich:
        from avadhi.config import MODEL
        console.print(f"[dim]   Model:  {MODEL}[/dim]")
    console.print()

    start = time.time()
    scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope else None

    # Initialize logger
    logger = AuditLogger(output)
    logger.log_phase("recon", "start", target=target)

    # ── Phase 1a + 1b: Recon ─────────────────────────────────────────────
    sg, patterns = run_recon(target, scope=scope_list, verbose=verbose)

    logger.log_phase("recon", "complete",
                     nodes=sg.G.number_of_nodes(),
                     edges=sg.G.number_of_edges(),
                     patterns=list(patterns.keys()))

    # ── Phase 1c: LLM Enrichment ─────────────────────────────────────────
    enrichment_data = {}
    if enrich:
        from avadhi.recon.enrichment import run_enrichment
        logger.log_phase("enrichment", "start")
        enrichment_data = run_enrichment(sg, logger=logger, verbose=verbose)
        logger.log_phase("enrichment", "complete",
                         invariants=len(enrichment_data.get("invariants", [])))

    elapsed = time.time() - start

    # ── Display ──────────────────────────────────────────────────────────
    _show_summary(sg)
    _show_attack_surface(sg)
    _show_external_calls(sg)
    _show_token_flows(sg)
    _show_patterns(patterns)

    if enrichment_data:
        _show_enrichment(enrichment_data)

    # ── Save outputs ─────────────────────────────────────────────────────
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    graph_path = out_dir / "security_graph.json"
    sg.to_json(graph_path)
    console.print(f"\n  📁 Graph: [dim]{graph_path}[/dim]")

    viz_path = out_dir / "graph.html"
    export_graph_html(sg, viz_path)
    console.print(f"  🌐 Viz:   [dim]{viz_path}[/dim]")

    log_summary = logger.get_summary()
    console.print(f"  📋 Log:   [dim]{log_summary['log_file']}[/dim]")

    if log_summary.get("llm_calls", 0) > 0:
        console.print(f"  💰 LLM:   {log_summary['llm_calls']} calls, "
                      f"{log_summary['total_tokens']} tokens")

    if viz:
        webbrowser.open(f"file://{viz_path.absolute()}")
        console.print(f"  🌐 Opening graph in browser...")

    console.print(f"\n[bold green]  ✅ Scan complete in {elapsed:.1f}s[/bold green]\n")


@app.command()
def hunt(
    target: str = typer.Argument(..., help="Path to Solidity contracts directory"),
    output: str = typer.Option(".avadhi_output", "--output", "-o", help="Output directory"),
    scope: str = typer.Option("", help="Comma-separated file names to scope"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    Run the full multi-agent hunting pipeline on a Solidity project.

    Phase 1a+b: Recon → SecurityGraph
    Phase 1c:   LLM Enrichment
    Phase 2:    Hunter Agents (AccessControlHunter, ExternalCallHunter)

    Output: .avadhi_output/hunt_results.md
    """
    from avadhi.config import MODEL
    console.print("\n[bold cyan]Avadhi -- Multi-Agent Hunt[/bold cyan]")
    console.print(f"[dim]   Target: {target}[/dim]")
    console.print(f"[dim]   Output: {output}[/dim]")
    console.print(f"[dim]   Model:  {MODEL}[/dim]")
    console.print()

    start = time.time()
    scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope else None

    # Auto-detect scope.txt from target directory if no explicit --scope provided
    if not scope_list:
        target_path = Path(target)
        for candidate in [target_path / "scope.txt", target_path.parent / "scope.txt"]:
            if candidate.exists():
                raw_scope = candidate.read_text().splitlines()
                scope_list = [s.strip().lstrip("./") for s in raw_scope if s.strip() and not s.startswith("#")]
                if scope_list:
                    console.print(f"  [dim]Scope: {len(scope_list)} in-scope files loaded from {candidate.name}[/dim]")
                    break

    import datetime as _dt
    import re as _re

    # ── Timestamped run folder: output/<protocol>_<YYYYMMDD_HHMMSS>/ ──
    protocol_slug = Path(target).parent.name or Path(target).name
    protocol_slug = _re.sub(r"[^\w-]", "_", protocol_slug).strip("_") or "audit"
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_name = f"{protocol_slug}_{timestamp}"

    out_root = Path(output)
    out_dir = out_root / run_name
    out_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"  [dim]Run folder: {out_dir}[/dim]")

    # ── Phase 1a + 1b: Recon ─────────────────────────────────────────────
    logger = AuditLogger(str(out_dir))
    console.print("[bold]Phase 1a+b[/bold]  Structural recon...")
    logger.log_phase("recon", "start", target=target)
    sg, patterns = run_recon(target, scope=scope_list, verbose=verbose)
    logger.log_phase("recon", "complete",
                     nodes=sg.G.number_of_nodes(),
                     edges=sg.G.number_of_edges())

    console.print(f"  Graph: {sg.G.number_of_nodes()} nodes, {sg.G.number_of_edges()} edges")

    # ── Phase 1c: LLM Enrichment ─────────────────────────────────────────
    console.print("[bold]Phase 1c[/bold]   LLM enrichment...")
    from avadhi.recon.enrichment import run_enrichment as _run_enrichment
    logger.log_phase("enrichment", "start")
    enrichment_data = _run_enrichment(sg, logger=logger, verbose=verbose)
    logger.log_phase("enrichment", "complete",
                     invariants=len(enrichment_data.get("invariants", [])))
    console.print(f"  Protocol: {enrichment_data.get('protocol_type', 'unknown')}")
    console.print(f"  Invariants: {len(enrichment_data.get('invariants', []))}")

    # ── RAG Pool Init ─────────────────────────────────────────────────────
    _rag_loop = None
    try:
        import asyncio as _asyncio
        import os as _os
        if _os.environ.get("DATABASE_URL"):
            from avadhi.rag.pool import get_rag_pool as _get_rag_pool
            _rag_loop = _asyncio.new_event_loop()
            _rag_pool = _rag_loop.run_until_complete(_get_rag_pool())
            sg.metadata["rag_pool"] = _rag_pool
            console.print("  RAG pool connected (pgvector knowledge base)")
        else:
            console.print("  RAG disabled (DATABASE_URL not set)")
    except Exception as _rag_init_err:
        console.print(f"  RAG pool init failed: {_rag_init_err}")

    # ── Phase 1d: Protocol Invariant Extraction ───────────────────────────
    console.print("[bold]Phase 1d[/bold]   Protocol invariant extraction...")
    try:
        from avadhi.agents.invariant import extract_invariants
        _inv_list = extract_invariants(sg, logger=logger, verbose=verbose)
        console.print(f"  Invariants extracted: {len(_inv_list)}")
    except Exception as _inv_err:
        console.print(f"  Invariant extraction failed: {_inv_err}")
    # ── Phase 2: Routing ──────────────────────────────────────────────────
    console.print("[bold]Phase 2[/bold]    Intelligent routing...")

    # Reload source files for hunters (to_json excludes them)
    from avadhi.recon.parser import discover_sol_files
    sg.metadata["source_files"] = discover_sol_files(Path(target))

    from avadhi.agents.router import route
    manifest = route(sg)

    console.print(f"  Agents selected: [cyan]{', '.join(manifest.agents)}[/cyan] "
                  f"({len(manifest.agents)}/6)")
    console.print(f"  Flags detected:  {', '.join(manifest.flags_detected) or 'none'}")
    console.print(f"  Hot functions:   {len(manifest.hot_functions)}")
    if verbose:
        for line in manifest.rationale:
            console.print(f"  [dim]{line}[/dim]")

    logger.log_phase("routing", "complete",
                     agents=manifest.agents,
                     flags=manifest.flags_detected)

    # ── Phase 2b: Convergence Loop (Hunt + Cross-Feed) ──────────────────
    console.print("[bold]Phase 2b[/bold]   Convergence loop (iterative hunting)...")

    from avadhi.agents.hunters import AGENT_REGISTRY
    from avadhi.agents.convergence import run_convergence_loop

    logger.log_phase("hunting", "start")
    all_hypotheses = run_convergence_loop(
        sg=sg,
        manifest=manifest,
        agent_registry=AGENT_REGISTRY,
        logger=logger,
        verbose=verbose,
    )
    logger.log_phase("hunting", "complete",
                     total_hypotheses=len(all_hypotheses))
    console.print(f"  Convergence complete: {len(all_hypotheses)} hypotheses")

    # ── Phase 2c: Depth Analysis ─────────────────────────────────────────────
    if all_hypotheses:
        console.print("[bold]Phase 2c[/bold]   Depth analysis (High/Critical findings)...")
        try:
            from avadhi.agents.depth import run_depth_analysis
            logger.log_phase("depth_analysis", "start")
            all_hypotheses = run_depth_analysis(
                all_hypotheses, sg, logger=logger, verbose=verbose
            )
            console.print(f"  Depth complete: {len(all_hypotheses)} findings remain")
        except Exception as _depth_err:
            console.print(f"  Depth analysis failed: {_depth_err}")

    # ── Phase 3: 4-Gate Judge ────────────────────────────────────────────
    console.print("[bold]Phase 3[/bold]    4-Gate Judge (Refutation/Reachability/Trigger/Impact)...")
    from avadhi.agents.judge import run_judge
    logger.log_phase("judging", "start")
    raw_count = len(all_hypotheses)
    surviving, challenges = run_judge(all_hypotheses, sg, logger=logger, verbose=verbose)
    refuted_count = raw_count - len(surviving)
    all_hypotheses = surviving
    logger.log_phase("judging", "complete",
                     surviving=len(surviving), refuted=refuted_count)

    # ── Phase 3b: Chain Analysis ───────────────────────────────────────
    console.print("[bold]Phase 3b[/bold]   Chain analysis...")
    from avadhi.agents.chain_analysis import run_chain_analysis
    logger.log_phase("chain_analysis", "start")
    compound_exploits = run_chain_analysis(all_hypotheses, logger=logger, verbose=verbose)
    logger.log_phase("chain_analysis", "complete", chains_found=len(compound_exploits))
    console.print(f"  {len(compound_exploits)} compound exploit chains detected")

    # ── Phase 3c: Confidence Scoring ──────────────────────────────────
    console.print("[bold]Phase 3c[/bold]   Confidence scoring...")
    from avadhi.agents.confidence_scorer import score_hypotheses, scores_to_markdown_table
    confidence_scores = score_hypotheses(all_hypotheses, verbose=verbose)
    console.print(f"  {len(confidence_scores)} findings scored")

    # ── Phase 4: PoC Generation (High/Critical only) ──────────────────
    console.print("[bold]Phase 4[/bold]    PoC generation (High/Critical)...")
    from avadhi.agents.poc_gen import generate_pocs
    from avadhi.core.schemas import Severity as _Sev
    logger.log_phase("poc_gen", "start")
    pocs = generate_pocs(all_hypotheses, sg, logger=logger, verbose=verbose,
                         severity_threshold=_Sev.HIGH)
    logger.log_phase("poc_gen", "complete", pocs_generated=len(pocs))
    console.print(f"  {len(pocs)} PoCs generated")

    # Write PoC files under pocs/
    poc_dir = out_dir / "pocs"
    if pocs:
        poc_dir.mkdir(exist_ok=True)
        for poc_id, poc_code in pocs.items():
            safe_id = poc_id.replace("/", "_").replace(":", "_")
            poc_file = poc_dir / f"{safe_id}_test.sol"
            poc_file.write_text(poc_code)
            if verbose:
                console.print(f"    {poc_file}")

    elapsed = time.time() - start

    # ── Cleanup RAG pool ──────────────────────────────────────────────────
    if _rag_loop is not None:
        try:
            _rag_loop.close()
        except Exception:
            pass

    # ── Visualization ─────────────────────────────────────────────────────
    from avadhi.viz.export import export_graph_html as _export
    graph_dir = out_dir / "graph"
    graph_dir.mkdir(exist_ok=True)
    viz_path = graph_dir / "security_graph.html"
    _export(sg, viz_path, hypotheses=all_hypotheses)
    # Also save the raw graph JSON
    sg.to_json(graph_dir / "security_graph.json")

    # ── Write Code4rena-style Markdown Report ─────────────────────────────
    from avadhi.output.report import write_c4_report
    report_path = write_c4_report(
        out_dir=out_dir,
        target=target,
        hypotheses=all_hypotheses,
        enrichment_data=enrichment_data,
        elapsed=elapsed,
        challenges=challenges,
        raw_count=raw_count,
        pocs=pocs,
        compound_exploits=compound_exploits,
        confidence_scores=confidence_scores,
        scope_list=scope_list,
    )
    console.print(f"\n  [bold green]Report:[/bold green]  {report_path}")
    console.print(f"  PoCs:     {poc_dir}  ({len(pocs)} file{'s' if len(pocs) != 1 else ''})")
    console.print(f"  Graph:    {viz_path}")
    console.print(f"  Folder:   {out_dir}")

    # ── CLI Summary ───────────────────────────────────────────────────────
    from rich.table import Table as _Table
    summary = _Table(title="Hunt Summary", show_lines=False, title_style="bold")
    summary.add_column("Metric", style="dim")
    summary.add_column("Value", style="bold")
    summary.add_row("Raw Hypotheses", str(raw_count))
    summary.add_row("Refuted by Critic", str(refuted_count))
    summary.add_row("Verified Findings", str(len(all_hypotheses)))
    sev_counts = {}
    for h in all_hypotheses:
        s = h.severity.value if hasattr(h.severity, 'value') else str(h.severity)
        sev_counts[s] = sev_counts.get(s, 0) + 1
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in sev_counts:
            color = {"Critical": "red", "High": "yellow", "Medium": "cyan", "Low": "green"}.get(sev, "dim")
            summary.add_row(f"  {sev}", f"[{color}]{sev_counts[sev]}[/{color}]")
    if enrichment_data.get("protocol_type"):
        summary.add_row("Protocol", f"[magenta]{enrichment_data['protocol_type']}[/magenta]")
    summary.add_row("Duration", f"{elapsed:.1f}s")
    console.print(summary)

    console.print(f"\n[bold green]  Hunt complete in {elapsed:.1f}s[/bold green]\n")


def _write_hunt_report(
    path: Path,
    target: str,
    hypotheses: list,
    enrichment_data: dict,
    elapsed: float,
    challenges: list | None = None,
    raw_count: int | None = None,
    pocs: dict[str, str] | None = None,
    compound_exploits: list | None = None,
    confidence_scores: list | None = None,
) -> None:
    """Write Markdown hunt report for comparison against human audit baselines."""
    import datetime
    lines = [
        "# Avadhi Hunt Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Duration:** {elapsed:.1f}s  ",
        "",
        "---",
        "",
    ]

    # Protocol context
    if enrichment_data.get("protocol_type"):
        lines += [
            "## Protocol Context",
            "",
            f"**Type:** {enrichment_data.get('protocol_type', 'unknown')}",
            "",
            enrichment_data.get("protocol_purpose", ""),
            "",
        ]

    # Invariants
    invariants = enrichment_data.get("invariants", [])
    if invariants:
        lines += ["## Inferred Invariants", ""]
        for inv in invariants:
            if isinstance(inv, dict):
                lines.append(f"- **{inv.get('id', '?')}**: {inv.get('description', '')} "
                           f"(severity if broken: {inv.get('severity_if_broken', '?')})")
        lines.append("")

    # Findings
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        hypotheses,
        key=lambda h: severity_order.get(
            h.severity.value if hasattr(h.severity, 'value') else str(h.severity), 5
        ),
    )

    refuted = (raw_count or len(sorted_findings)) - len(sorted_findings)
    lines += [
        "## Findings",
        "",
        f"**Raw Hypotheses:** {raw_count or len(sorted_findings)}  ",
        f"**Refuted by Critic:** {refuted}  ",
        f"**Verified Findings:** {len(sorted_findings)}",
        "",
    ]

    # Build challenge lookup for debate logs
    challenge_map: dict[str, str] = {}
    if challenges:
        for c in challenges:
            hid = getattr(c, "hypothesis_id", "") or c.get("hypothesis_id", "")
            verdict = getattr(c, "verdict", None)
            if verdict and hasattr(verdict, "value"):
                verdict = verdict.value
            challenge_text = getattr(c, "challenge", "") or c.get("challenge", "")
            if hid:
                challenge_map[hid] = f"Critic [{verdict}]: {challenge_text}"

    if not sorted_findings:
        lines.append("_No findings generated._")
    else:
        for i, h in enumerate(sorted_findings, 1):
            sev = h.severity.value if hasattr(h.severity, 'value') else str(h.severity)
            sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
                        "Low": "🟢", "Info": "⚪"}.get(sev, "⚫")
            lines += [
                f"### {sev_emoji} [{sev}] {h.title}",
                "",
                f"**ID:** `{h.id}`  ",
                f"**Category:** {h.category}  ",
                f"**Location:** `{h.location}`  ",
                f"**Hunter:** {h.hunter_agent}  ",
                "",
                "**Description:**",
                "",
                h.description,
                "",
            ]
            if h.attack_scenario:
                lines += [
                    "**Attack Scenario:**",
                    "",
                    h.attack_scenario,
                    "",
                ]
            if h.impact:
                lines += [
                    "**Impact:**",
                    "",
                    h.impact,
                    "",
                ]
            if h.evidence:
                lines += ["**Evidence:**", ""]
                for ev in h.evidence:
                    lines.append(f"- {ev}")
                lines.append("")
            # Critic debate log
            debate = challenge_map.get(h.id, "")
            if debate:
                confidence = h.confidence.value if hasattr(h.confidence, "value") else str(h.confidence)
                lines += [
                    f"**Confidence:** {confidence}",
                    "",
                    "<details><summary>Critic Debate Log</summary>",
                    "",
                    f"> {debate}",
                    "",
                    "</details>",
                    "",
                ]
            # PoC
            poc_code = (pocs or {}).get(h.id, "")
            if poc_code:
                lines += [
                    "<details><summary>Proof of Concept (Foundry)</summary>",
                    "",
                    "```solidity",
                    poc_code,
                    "```",
                    "",
                    "</details>",
                    "",
                ]
            lines += ["---", ""]

    # Confidence Score Table
    if confidence_scores:
        from avadhi.agents.confidence_scorer import scores_to_markdown_table
        lines += [
            "## 📊 Confidence Score Matrix",
            "",
            "*4-axis numerical scoring: Structural Evidence + Critic Verdict + Severity + RAG Corroboration*",
            "",
            scores_to_markdown_table(confidence_scores),
            "",
        ]

    # Compound Exploit Chains
    if compound_exploits:
        lines += [
            "## ⛓️  Compound Exploit Chains",
            "",
            "*The following findings can be combined into higher-severity compound attacks:*",
            "",
        ]
        for chain in compound_exploits:
            lines.append(chain.to_markdown())

    path.write_text("\n".join(lines))


@app.command(name="run-task")
def run_task(
    task_id: str = typer.Argument(..., help="Agent Arena task ID"),
):
    """
    Manually run an audit for a known Agent Arena task ID.

    Use this when you missed a webhook or want to run on-demand.
    Constructs the task URLs from the task ID and runs the full pipeline.
    """
    from avadhi.config import AGENTARENA_API_KEY

    if not AGENTARENA_API_KEY:
        console.print("[bold red]Error:[/bold red] AGENTARENA_API_KEY not set in .env")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]Avadhi -- Manual Task Run[/bold cyan]")
    console.print(f"[dim]   Task ID: {task_id}[/dim]\n")

    from avadhi.server.schemas import WebhookPayload
    from avadhi.server.handler import process_task

    payload = WebhookPayload(
        task_id=task_id,
        task_repository_url=f"https://backend.agentarena.com/api/task-repository/{task_id}",
        task_details_url=f"https://backend.agentarena.com/api/task-details/{task_id}",
        post_findings_url="https://arbiter.agentarena.com/process_findings",
    )

    process_task(payload)
    console.print(f"\n[bold green]Task {task_id} complete.[/bold green]\n")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to listen on"),
):
    """
    Start the Agent Arena webhook server.

    Requires AGENTARENA_API_KEY and WEBHOOK_AUTH_TOKEN in .env.
    """
    from avadhi.config import AGENTARENA_API_KEY, WEBHOOK_AUTH_TOKEN

    if not AGENTARENA_API_KEY:
        console.print("[bold red]Error:[/bold red] AGENTARENA_API_KEY not set in .env")
        raise typer.Exit(1)
    if not WEBHOOK_AUTH_TOKEN:
        console.print("[bold red]Error:[/bold red] WEBHOOK_AUTH_TOKEN not set in .env")
        raise typer.Exit(1)

    console.print("\n[bold cyan]Avadhi -- Agent Arena Server[/bold cyan]")
    console.print(f"[dim]   Host: {host}:{port}[/dim]")
    console.print(f"[dim]   API Key: {AGENTARENA_API_KEY[:8]}...[/dim]")
    console.print()

    import uvicorn
    from avadhi.server.app import app as fastapi_app
    uvicorn.run(fastapi_app, host=host, port=port)


@app.command()
def inspect(
    graph_file: str = typer.Argument(..., help="Path to saved graph JSON"),
    viz: bool = typer.Option(False, "--viz", help="Open visualization"),
):
    """Load and inspect a previously saved SecurityGraph."""
    from avadhi.core.graph import SecurityGraph
    sg = SecurityGraph.from_json(graph_file)
    _show_summary(sg)
    _show_attack_surface(sg)
    _show_external_calls(sg)
    if viz:
        viz_path = Path(graph_file).parent / "graph.html"
        export_graph_html(sg, viz_path)
        webbrowser.open(f"file://{viz_path.absolute()}")


# ── Display Helpers ──────────────────────────────────────────────────────────

def _show_summary(sg):
    s = sg.summary()
    table = Table(title="📊 Graph Summary", show_lines=False, title_style="bold")
    table.add_column("Metric", style="dim")
    table.add_column("Value", style="bold")
    table.add_row("Nodes", str(s["total_nodes"]))
    table.add_row("Edges", str(s["total_edges"]))
    table.add_row("Contracts", str(s["nodes_by_type"].get("Contract", 0)))
    table.add_row("Functions", str(s["nodes_by_type"].get("Function", 0)))
    table.add_row("State Vars", str(s["nodes_by_type"].get("StateVariable", 0)))
    table.add_row("Entry Points", str(s["entry_points"]))
    table.add_row("Unrestricted", f"[yellow]{s['unrestricted_entry_points']}[/yellow]"
                  if s["unrestricted_entry_points"] > 0 else "0")
    table.add_row("External Calls", str(s["external_calls"]))
    table.add_row("User-Controlled", f"[red]{s['user_controlled_calls']}[/red]"
                  if s["user_controlled_calls"] > 0 else "0")
    table.add_row("Token Flows", str(s["token_flows"]))

    # Show enrichment metadata if present
    protocol = sg.metadata.get("protocol_type", "")
    if protocol:
        table.add_row("Protocol", f"[magenta]{protocol}[/magenta]")
    console.print(table)


def _show_attack_surface(sg):
    entries = sg.get_entry_points()
    if not entries:
        return
    table = Table(title="⚔️  Attack Surface", show_lines=True)
    table.add_column("Function", style="cyan", max_width=40)
    table.add_column("Vis", style="yellow", width=8)
    table.add_column("Modifiers", style="green")
    table.add_column("Flags", style="red")
    for fn_id in entries:
        d = sg.G.nodes[fn_id]
        if d.get("visibility") not in ("external", "public"):
            continue
        mods = ", ".join(d.get("modifiers", [])) or "[yellow]NONE ⚠️[/yellow]"
        flags = ", ".join(sg.get_flags_for(fn_id))
        table.add_row(
            f"{d['contract']}.{d['name']}",
            d.get("visibility", ""),
            mods,
            flags or "-",
        )
    console.print(table)


def _show_external_calls(sg):
    ext = sg.get_external_calls()
    if not ext:
        return
    table = Table(title="🔗 External Calls", show_lines=True)
    table.add_column("From", style="cyan")
    table.add_column("Target", style="yellow")
    table.add_column("Type", width=10)
    table.add_column("Taint", style="red")
    for u, v, d in ext:
        src = sg.G.nodes.get(u, {})
        tgt = sg.G.nodes.get(v, {})
        taint = "⚠️ USER_INPUT" if d.get("data_source") == "user_input" else d.get("data_source", "")
        table.add_row(
            f"{src.get('contract','')}.{src.get('name','')}",
            tgt.get("target", v),
            d.get("call_type", ""),
            taint,
        )
    console.print(table)


def _show_token_flows(sg):
    flows = sg.get_token_flows()
    if not flows:
        return
    table = Table(title="💰 Token Flows", show_lines=True)
    table.add_column("Function", style="cyan")
    table.add_column("Operation", style="yellow")
    table.add_column("Token", style="green")
    for u, v, d in flows:
        src = sg.G.nodes.get(u, {})
        table.add_row(
            f"{src.get('contract','')}.{src.get('name','')}",
            d.get("flow_type", ""),
            sg.G.nodes.get(v, {}).get("name", v),
        )
    console.print(table)


def _show_patterns(patterns: dict):
    if not patterns:
        return
    table = Table(title="🏷️  Detected Patterns", show_lines=True)
    table.add_column("Pattern", style="cyan")
    table.add_column("Hits", style="yellow", justify="right")
    for flag, locs in sorted(patterns.items()):
        table.add_row(flag, str(len(locs)))
    console.print(table)


def _show_enrichment(data: dict):
    """Display LLM enrichment results."""
    # Protocol info
    protocol = data.get("protocol_type", "unknown")
    purpose = data.get("protocol_purpose", "")
    console.print(Panel(
        f"[bold magenta]{protocol.upper()}[/bold magenta]\n{purpose}",
        title="🏗  Protocol Classification",
        border_style="magenta",
    ))

    # Invariants
    invariants = data.get("invariants", [])
    if invariants:
        table = Table(title="📌 Inferred Invariants", show_lines=True)
        table.add_column("ID", style="yellow", width=10)
        table.add_column("Invariant", style="white")
        table.add_column("Severity if Broken", style="red", width=18)
        for inv in invariants:
            table.add_row(
                inv.get("id", "?"),
                inv.get("description", ""),
                inv.get("severity_if_broken", "?"),
            )
        console.print(table)

    # Trust boundaries
    boundaries = data.get("trust_boundaries", [])
    if boundaries:
        table = Table(title="🛡️  Trust Boundaries", show_lines=True)
        table.add_column("Actor", style="cyan")
        table.add_column("Trust Level", style="yellow")
        table.add_column("Description", style="dim")
        for tb in boundaries:
            level = tb.get("trust_level", "?")
            level_styled = (f"[green]{level}[/green]" if level == "FULLY_TRUSTED"
                           else f"[yellow]{level}[/yellow]" if level == "SEMI_TRUSTED"
                           else f"[red]{level}[/red]")
            table.add_row(
                tb.get("name", "?"),
                level_styled,
                tb.get("description", ""),
            )
        console.print(table)

    # Dangerous flows
    flows = data.get("dangerous_flows", [])
    if flows:
        table = Table(title="⚠️  Dangerous Flows", show_lines=True)
        table.add_column("From", style="cyan")
        table.add_column("To", style="yellow")
        table.add_column("Risk", style="red", width=8)
        table.add_column("Why", style="dim")
        for f in flows:
            table.add_row(
                f.get("from_function", "?"),
                f.get("to_target", "?"),
                f.get("risk", "?"),
                f.get("why", ""),
            )
        console.print(table)

    # Attack surface notes
    notes = data.get("attack_surface_notes", [])
    if notes:
        console.print(Panel(
            "\n".join(f"• {n}" for n in notes),
            title="🎯 Attack Surface Notes",
            border_style="yellow",
        ))
