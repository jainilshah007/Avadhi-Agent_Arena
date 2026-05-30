"""
avadhi/recon/runner.py — Phase 1 orchestrator.

Runs Phase 1a (structural analysis) + Phase 1b (pattern detection)
to produce a fully-populated SecurityGraph Layer 0.

Parser priority:
  1. Slither Python API  — accurate call graph, transitive writes, real modifiers
  2. Regex parser        — fast fallback when Slither is unavailable / fails
"""
from __future__ import annotations

from pathlib import Path

from avadhi.core.graph import SecurityGraph
from avadhi.recon.parser import discover_sol_files, parse_solidity
from avadhi.recon.slither import (
    build_graph_from_slither_api,
    try_slither,
    parse_slither_findings,
)
from avadhi.recon.patterns import run_patterns


def run_recon(
    target_path: str,
    scope: list[str] | None = None,
    verbose: bool = False,
) -> tuple[SecurityGraph, dict]:
    """
    Full Phase 1: Build SecurityGraph from source code.

    Returns: (SecurityGraph, pattern_results)
    """
    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Target not found: {target_path}")

    if verbose:
        print(f"\n{'═'*60}")
        print(f"  PHASE 1a: RECON — Structural Analysis")
        print(f"  Target: {target_path}")
        print(f"{'═'*60}\n")

    sg = SecurityGraph()
    sg.metadata["target_path"] = str(target)

    # Always discover source files (needed for patterns and LLM context)
    source_files = discover_sol_files(target, scope)
    if verbose:
        print(f"  📄 Found {len(source_files)} Solidity files")
    if not source_files:
        print("  FAILED No Solidity files found!")
        return sg, {}

    # ── 1. Slither Python API (primary) ───────────────────────────────────
    if verbose:
        print(f"  🔬 Attempting Slither Python API...")

    slither_ok = build_graph_from_slither_api(str(target), sg, verbose=verbose)

    if slither_ok:
        sg.metadata["parser"] = "slither"
        if verbose:
            print(f"  OK Using Slither-derived graph")
    else:
        # ── 2. Regex parser (fallback) ─────────────────────────────────
        if verbose:
            print(f"  WARNING  Slither API unavailable — using regex parser")
        sg.metadata["parser"] = "regex"
        for file_path, content in source_files.items():
            parse_solidity(file_path, content, sg)

        # Also try Slither CLI for detector findings (as flags)
        slither_data = try_slither(target_path)
        if slither_data:
            n_dets = len(slither_data.get("results", {}).get("detectors", []))
            if verbose:
                print(f"  🚩 Slither CLI: {n_dets} detector results as flags")
            parse_slither_findings(slither_data, sg)

    # Store source files for pattern scanning and LLM context
    sg.metadata["source_files"] = source_files

    if verbose:
        parser = sg.metadata.get("parser", "unknown")
        print(f"  📊 Graph: {sg.G.number_of_nodes()} nodes, "
              f"{sg.G.number_of_edges()} edges (parser: {parser})")

    # ── 2. Phase 1b: Pattern detection (always runs) ──────────────────────
    if verbose:
        print(f"\n{'═'*60}")
        print(f"  PHASE 1b: PATTERN DETECTION")
        print(f"{'═'*60}\n")

    pattern_results = run_patterns(sg)

    if verbose:
        detected = {k: v for k, v in pattern_results.items() if v}
        print(f"  🏷️  Detected {len(detected)} pattern types:\n")
        for flag, locs in sorted(detected.items()):
            print(f"    {flag:25s} — {len(locs)} hits")
        print()

    return sg, pattern_results
