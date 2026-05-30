"""
avadhi/server/handler.py — Background task handler for Agent Arena audits.

Downloads repo, fetches task details, runs the hunt pipeline, and submits findings.
"""
from __future__ import annotations

import io
import logging
import shutil
import tempfile
import zipfile
from pathlib import Path

import httpx

from avadhi.server.schemas import (
    Finding,
    FindingsSubmission,
    TaskDetails,
    WebhookPayload,
)

logger = logging.getLogger("avadhi.server")


def _get_api_key() -> str:
    import os
    key = os.getenv("AGENTARENA_API_KEY", "")
    if not key:
        raise RuntimeError("AGENTARENA_API_KEY not set")
    return key


def download_repository(url: str, dest: Path) -> Path:
    """Download and extract the task repository ZIP to dest directory."""
    api_key = _get_api_key()
    logger.info("Downloading repository from %s", url)

    with httpx.Client(timeout=300) as client:
        resp = client.get(url, headers={"X-API-Key": api_key})
        resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        zf.extractall(dest)

    # If the ZIP contains a single top-level directory, use that
    entries = list(dest.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def fetch_task_details(url: str) -> TaskDetails:
    """Fetch task metadata from Agent Arena."""
    api_key = _get_api_key()
    logger.info("Fetching task details from %s", url)

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers={"X-API-Key": api_key})
        resp.raise_for_status()

    return TaskDetails.model_validate(resp.json())


def submit_findings(url: str, task_id: str, findings: list[Finding]) -> None:
    """Submit findings back to Agent Arena."""
    api_key = _get_api_key()
    submission = FindingsSubmission(task_id=task_id, findings=findings)
    logger.info("Submitting %d findings for task %s", len(findings), task_id)

    with httpx.Client(timeout=60) as client:
        resp = client.post(
            url,
            json=submission.model_dump(),
            headers={"X-API-Key": api_key},
        )
        resp.raise_for_status()

    logger.info("Findings submitted successfully (status %d)", resp.status_code)


def _find_contracts_dir(repo_root: Path) -> Path:
    """Locate the Solidity contracts directory within the repo."""
    # Common convention directories
    for candidate in ["contracts", "src", "src/contracts"]:
        p = repo_root / candidate
        if p.is_dir():
            return p

    # Fallback: find any directory containing .sol files
    for sol_file in repo_root.rglob("*.sol"):
        return sol_file.parent

    # Last resort: use repo root
    return repo_root


def _hypotheses_to_findings(hypotheses: list) -> list[Finding]:
    """Convert Avadhi Hypothesis objects to Agent Arena Finding format."""
    findings = []
    for h in hypotheses:
        sev = h.severity.value if hasattr(h.severity, "value") else str(h.severity)
        # Map Critical -> High (Agent Arena uses High|Medium|Low|Info)
        if sev == "Critical":
            sev = "High"

        # Extract file paths from the location field
        file_paths = []
        if h.location:
            # Location format: "Contract.function:L123" or "path/to/File.sol:L123"
            loc_part = h.location.split(":")[0]
            file_paths.append(loc_part)

        description_parts = [h.description]
        if h.attack_scenario:
            description_parts.append(f"\n\n**Attack Scenario:**\n{h.attack_scenario}")
        if h.impact:
            description_parts.append(f"\n\n**Impact:**\n{h.impact}")
        if h.evidence:
            description_parts.append("\n\n**Evidence:**\n" + "\n".join(f"- {e}" for e in h.evidence))

        findings.append(Finding(
            title=h.title,
            description="\n".join(description_parts),
            severity=sev,
            file_paths=file_paths,
        ))
    return findings


def process_task(payload: WebhookPayload) -> None:
    """
    Full audit pipeline for an Agent Arena task.
    Runs in a background thread.
    """
    task_id = payload.task_id
    logger.info("Processing task %s", task_id)

    tmp_dir = None
    try:
        # Step 1: Fetch task details
        task_details = fetch_task_details(payload.task_details_url)
        logger.info("Task: %s — %s", task_details.title, task_details.description[:200])

        # Step 2: Download repository
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"avadhi_arena_{task_id}_"))
        repo_root = download_repository(payload.task_repository_url, tmp_dir)
        contracts_dir = _find_contracts_dir(repo_root)
        logger.info("Contracts directory: %s", contracts_dir)

        # Step 3: Determine scope from task details
        scope_list = task_details.selectedFiles if task_details.selectedFiles else None

        # Step 4: Run the Avadhi hunt pipeline
        hypotheses = _run_hunt(
            target=str(contracts_dir),
            scope_list=scope_list,
            task_details=task_details,
        )

        # Step 5: Convert and submit findings
        findings = _hypotheses_to_findings(hypotheses)
        submit_findings(payload.post_findings_url, task_id, findings)

        logger.info("Task %s complete: %d findings submitted", task_id, len(findings))

    except Exception:
        logger.exception("Failed to process task %s", task_id)
        # Submit empty findings on failure so Arena knows we attempted
        try:
            submit_findings(payload.post_findings_url, task_id, [])
        except Exception:
            logger.exception("Failed to submit empty findings for task %s", task_id)
    finally:
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _run_hunt(
    target: str,
    scope_list: list[str] | None,
    task_details: TaskDetails,
) -> list:
    """Run the core Avadhi hunt pipeline and return hypotheses."""
    from avadhi.recon.runner import run_recon
    from avadhi.utils.logging import AuditLogger

    import datetime
    import re

    # Create output directory
    from avadhi.config import OUTPUT_DIR
    protocol_slug = re.sub(r"[^\w-]", "_", task_details.title or "arena_audit").strip("_") or "audit"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = OUTPUT_DIR / f"{protocol_slug}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    audit_logger = AuditLogger(str(out_dir))
    audit_logger.log_phase("recon", "start", target=target, task_id=task_details.taskId)

    # Phase 1a+b: Recon
    sg, patterns = run_recon(target, scope=scope_list, verbose=False)
    audit_logger.log_phase("recon", "complete",
                           nodes=sg.G.number_of_nodes(),
                           edges=sg.G.number_of_edges())

    # Phase 1c: LLM Enrichment
    from avadhi.recon.enrichment import run_enrichment
    enrichment_data = run_enrichment(sg, logger=audit_logger, verbose=False)

    # Inject task context into graph metadata
    sg.metadata["task_description"] = task_details.description
    sg.metadata["task_title"] = task_details.title

    # Phase 1d: Invariant extraction
    try:
        from avadhi.agents.invariant import extract_invariants
        extract_invariants(sg, logger=audit_logger, verbose=False)
    except Exception as e:
        logger.warning("Invariant extraction failed: %s", e)

    # RAG pool init
    _rag_loop = None
    try:
        import asyncio
        import os
        if os.environ.get("DATABASE_URL"):
            from avadhi.rag.pool import get_rag_pool
            _rag_loop = asyncio.new_event_loop()
            _rag_pool = _rag_loop.run_until_complete(get_rag_pool())
            sg.metadata["rag_pool"] = _rag_pool
    except Exception as e:
        logger.warning("RAG pool init failed: %s", e)

    # Phase 2: Routing
    from avadhi.recon.parser import discover_sol_files
    sg.metadata["source_files"] = discover_sol_files(Path(target))

    from avadhi.agents.router import route
    manifest = route(sg)

    # Phase 2b: Convergence loop
    from avadhi.agents.hunters import AGENT_REGISTRY
    from avadhi.agents.convergence import run_convergence_loop
    all_hypotheses = run_convergence_loop(
        sg=sg, manifest=manifest, agent_registry=AGENT_REGISTRY,
        logger=audit_logger, verbose=False,
    )

    # Phase 2c: Depth analysis
    if all_hypotheses:
        try:
            from avadhi.agents.depth import run_depth_analysis
            all_hypotheses = run_depth_analysis(
                all_hypotheses, sg, logger=audit_logger, verbose=False
            )
        except Exception as e:
            logger.warning("Depth analysis failed: %s", e)

    # Phase 3: Judge
    from avadhi.agents.judge import run_judge
    surviving, challenges = run_judge(all_hypotheses, sg, logger=audit_logger, verbose=False)
    all_hypotheses = surviving

    # Phase 3b: Chain analysis
    from avadhi.agents.chain_analysis import run_chain_analysis
    run_chain_analysis(all_hypotheses, logger=audit_logger, verbose=False)

    # Phase 3c: Confidence scoring
    from avadhi.agents.confidence_scorer import score_hypotheses
    score_hypotheses(all_hypotheses, verbose=False)

    # Cleanup RAG
    if _rag_loop is not None:
        try:
            _rag_loop.close()
        except Exception:
            pass

    # Write report for local reference
    try:
        from avadhi.output.report import write_c4_report
        write_c4_report(
            out_dir=out_dir, target=target, hypotheses=all_hypotheses,
            enrichment_data=enrichment_data, elapsed=0,
            challenges=challenges, raw_count=len(all_hypotheses),
            pocs={}, compound_exploits=[], confidence_scores=[],
            scope_list=scope_list,
        )
    except Exception as e:
        logger.warning("Report generation failed: %s", e)

    return all_hypotheses
