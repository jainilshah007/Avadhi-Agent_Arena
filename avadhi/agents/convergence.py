"""
avadhi/agents/convergence.py — Iterative convergence loop for hunting.

Inspired by Nemesis's alternating Feynman ↔ State loop:
  - Iteration 1: Full run — all selected agents in parallel
  - Iteration 2+: Delta-only — agents receive previous findings as cross-feed
    context and only report NEW findings
  - Convergence: when an iteration produces no new findings, stop
  - Safety cap: MAX_ITERATIONS (default 3)

The key insight from Nemesis: bugs at intersections (e.g., an access control
gap that only matters because of a state desync) only emerge when agents
feed each other's findings back in.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, TYPE_CHECKING

from avadhi.core.graph import SecurityGraph
from avadhi.core.schemas import Hypothesis
from avadhi.agents.router import HuntManifest
from avadhi.config import HUNTER_CONCURRENCY

if TYPE_CHECKING:
    from avadhi.utils.logging import AuditLogger

# Maximum hunting iterations before forced stop
MAX_ITERATIONS = 3


def _dedup_key(h: Hypothesis) -> tuple[str, str]:
    """Deduplication key for a hypothesis: (location, category)."""
    return (h.location, h.category)


def _summarize_for_crossfeed(hypotheses: list[Hypothesis], max_chars: int = 3000) -> str:
    """Compress findings into a compact digest for cross-feed injection."""
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_h = sorted(
        hypotheses,
        key=lambda h: severity_order.get(
            h.severity.value if hasattr(h.severity, "value") else str(h.severity), 5
        ),
    )

    lines: list[str] = []
    total = 0
    for h in sorted_h:
        sev = h.severity.value if hasattr(h.severity, "value") else str(h.severity)
        desc = h.description[:150].replace("\n", " ")
        if len(h.description) > 150:
            desc += "..."
        line = f"[{sev}] {h.id}: {h.title} @ {h.location} — {desc}"
        if total + len(line) > max_chars:
            lines.append(f"... and {len(sorted_h) - len(lines)} more (truncated)")
            break
        lines.append(line)
        total += len(line) + 1

    return "\n".join(lines)


def run_convergence_loop(
    sg: SecurityGraph,
    manifest: HuntManifest,
    agent_registry: dict[str, Callable],
    logger: "AuditLogger | None" = None,
    verbose: bool = False,
) -> list[Hypothesis]:
    """
    Run the iterative hunting loop until convergence.

    Args:
        sg: SecurityGraph with source files and enrichment
        manifest: HuntManifest from the router
        agent_registry: Maps agent name → run_*_hunter callable
        logger: Optional audit logger
        verbose: Print progress

    Returns:
        All hypotheses from all iterations (deduplicated)
    """
    all_hypotheses: list[Hypothesis] = []
    seen_keys: set[tuple[str, str]] = set()

    selected_agents = [
        (name, agent_registry[name])
        for name in manifest.agents
        if name in agent_registry
    ]

    if not selected_agents:
        if verbose:
            print("  No agents selected by router")
        return []

    for iteration in range(1, MAX_ITERATIONS + 1):
        is_full_run = iteration == 1
        cross_feed = None if is_full_run else _summarize_for_crossfeed(all_hypotheses)

        if verbose:
            mode = "FULL" if is_full_run else "DELTA (cross-feed)"
            print(f"\n  --- Iteration {iteration}/{MAX_ITERATIONS} [{mode}] "
                  f"({len(selected_agents)} agents) ---")

        iteration_hypotheses: list[Hypothesis] = []

        def _run_agent(name: str, fn: Callable):
            try:
                results = fn(
                    sg,
                    logger=logger,
                    verbose=verbose,
                    cross_feed_context=cross_feed,
                )
                return name, results, None
            except Exception as e:
                return name, [], e

        if HUNTER_CONCURRENCY == 1:
            for name, fn in selected_agents:
                label, results, exc = _run_agent(name, fn)
                if exc:
                    if verbose:
                        print(f"    [{label}] FAILED: {exc}")
                else:
                    iteration_hypotheses.extend(results)
                    if verbose:
                        print(f"    [{label}] {len(results)} hypotheses")
        else:
            with ThreadPoolExecutor(max_workers=HUNTER_CONCURRENCY) as pool:
                futures = {
                    pool.submit(_run_agent, name, fn): name
                    for name, fn in selected_agents
                }
                for future in as_completed(futures):
                    label, results, exc = future.result()
                    if exc:
                        if verbose:
                            print(f"    [{label}] FAILED: {exc}")
                    else:
                        iteration_hypotheses.extend(results)
                        if verbose:
                            print(f"    [{label}] {len(results)} hypotheses")

        # Tag iteration and discovery path
        for h in iteration_hypotheses:
            h.iteration = iteration
            if iteration > 1:
                h.id = f"I{iteration}-{h.id}"

        # Dedup against all previous findings
        novel: list[Hypothesis] = []
        for h in iteration_hypotheses:
            key = _dedup_key(h)
            if key not in seen_keys:
                seen_keys.add(key)
                novel.append(h)

        if verbose:
            dupes = len(iteration_hypotheses) - len(novel)
            print(f"  Iteration {iteration}: {len(novel)} novel findings "
                  f"({dupes} duplicates dropped)")

        all_hypotheses.extend(novel)

        # Convergence check
        if not novel and iteration > 1:
            if verbose:
                print(f"  CONVERGED at iteration {iteration} (no new findings)")
            break

        if logger:
            logger.log_phase(
                "convergence", f"iteration_{iteration}",
                novel=len(novel),
                total=len(all_hypotheses),
            )

    if verbose:
        print(f"\n  Convergence loop complete: {len(all_hypotheses)} total findings")

    return all_hypotheses
