"""
avadhi/output/report.py — Code4rena-style report generator.

Produces a professional Markdown audit report modelled on the Code4rena
report format, with:
  - Cover page (protocol, date, stats)
  - Scope table
  - Severity summary table
  - Full per-finding sections (description, impact, PoC, mitigation)
  - Appendix: critic debate logs, confidence scores
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avadhi.core.schemas import Hypothesis, CriticChallenge


# ── Helpers ──────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_LABEL = {
    "Critical": "Critical Risk",
    "High":     "High Risk",
    "Medium":   "Medium Risk",
    "Low":      "Low Risk / Non-Critical",
    "Info":     "Informational",
}
SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Info":     "⚪",
}
# Short finding ID prefix per severity (e.g. H-01, M-02)
SEVERITY_PREFIX = {
    "Critical": "C",
    "High":     "H",
    "Medium":   "M",
    "Low":      "L",
    "Info":     "I",
}


def _sev(h) -> str:
    return h.severity.value if hasattr(h.severity, "value") else str(h.severity)


def _conf(h) -> str:
    return h.confidence.value if hasattr(h.confidence, "value") else str(h.confidence)


def _slugify(s: str) -> str:
    """Convert title to GitHub markdown anchor."""
    s = s.lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    return s.strip("-")


# ── Main Entry Point ──────────────────────────────────────────────────────────

def write_c4_report(
    out_dir: Path,
    target: str,
    hypotheses: list,
    enrichment_data: dict,
    elapsed: float,
    *,
    challenges: list | None = None,
    raw_count: int | None = None,
    pocs: dict[str, str] | None = None,
    compound_exploits: list | None = None,
    confidence_scores: list | None = None,
    scope_list: list[str] | None = None,
) -> Path:
    """
    Generate a Code4rena-style Markdown report and write it to `out_dir`.

    Returns the path to the written report file.
    """
    pocs = pocs or {}
    challenges = challenges or []

    # Sort findings by severity then by hunter
    findings = sorted(
        hypotheses,
        key=lambda h: (SEVERITY_ORDER.get(_sev(h), 5), h.hunter_agent),
    )

    # Build finding IDs that match C4 convention (H-01, M-02, …)
    counters: dict[str, int] = {}
    finding_ids: dict[str, str] = {}  # internal h.id -> C4-style ID
    for h in findings:
        sev = _sev(h)
        prefix = SEVERITY_PREFIX.get(sev, "F")
        counters[prefix] = counters.get(prefix, 0) + 1
        finding_ids[h.id] = f"{prefix}-{counters[prefix]:02d}"

    # Challenge lookup
    challenge_map: dict[str, str] = {}
    challenge_verdict: dict[str, str] = {}
    for c in challenges:
        hid = getattr(c, "hypothesis_id", "") or c.get("hypothesis_id", "")
        verdict = getattr(c, "verdict", None) or c.get("verdict", "")
        if hasattr(verdict, "value"):
            verdict = verdict.value
        text = getattr(c, "challenge", "") or c.get("challenge", "")
        if hid:
            challenge_map[hid] = text
            challenge_verdict[hid] = str(verdict)

    # Severity counts
    sev_counts: dict[str, int] = {}
    for h in findings:
        sev_counts[_sev(h)] = sev_counts.get(_sev(h), 0) + 1

    now = datetime.datetime.now()
    protocol_name = enrichment_data.get("protocol_type", Path(target).name).title()

    lines: list[str] = []

    # ── Cover Page ────────────────────────────────────────────────────────────
    lines += [
        f"# {protocol_name} — Avadhi Security Audit",
        "",
        f"**Audited by:** Avadhi Autonomous Auditing System  ",
        f"**Date:** {now.strftime('%B %d, %Y')}  ",
        f"**Target:** `{target}`  ",
        f"**Duration:** {elapsed:.0f}s  ",
        "",
        "---",
        "",
    ]

    # ── About Avadhi ─────────────────────────────────────────────────────────
    lines += [
        "## About Avadhi",
        "",
        "Avadhi is an autonomous multi-agent smart contract auditing system. "
        "It orchestrates 18+ specialized hunter agents to identify complex, "
        "exploitable vulnerabilities — from access control bypasses to cross-chain "
        "re-entrancy — and validates each finding through an adversarial Critic/Debate "
        "phase before generating runnable Foundry proof-of-concepts.",
        "",
        "---",
        "",
    ]

    # ── Summary ───────────────────────────────────────────────────────────────
    refuted = (raw_count or len(findings)) - len(findings)
    lines += [
        "## Summary",
        "",
        f"The Avadhi analysis yielded **{len(findings)} verified finding(s)** "
        f"from {raw_count or len(findings)} raw hypotheses "
        f"({refuted} refuted by the Critic agent).",
        "",
    ]

    if sev_counts:
        lines += [
            "| Severity | Count |",
            "|---|:---:|",
        ]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in sev_counts:
                lines.append(f"| {SEVERITY_EMOJI[sev]} **{SEVERITY_LABEL[sev]}** | {sev_counts[sev]} |")
        lines.append("")

    # ── Scope ─────────────────────────────────────────────────────────────────
    lines += ["## Scope", ""]
    if scope_list:
        lines += [
            "The following contracts were in scope for this audit:",
            "",
            "| Contract | Path |",
            "|---|---|",
        ]
        for s in scope_list:
            name = Path(s).name
            lines.append(f"| `{name}` | `{s}` |")
    else:
        lines += [
            f"All Solidity contracts under `{target}` were analyzed.",
        ]
    lines.append("")

    # ── Severity Criteria ─────────────────────────────────────────────────────
    lines += [
        "## Severity Criteria",
        "",
        "| Severity | Description |",
        "|---|---|",
        "| 🔴 **Critical** | Direct loss of funds, complete protocol compromise with no preconditions. |",
        "| 🟠 **High** | Loss of funds requiring some preconditions, or a severe DoS. |",
        "| 🟡 **Medium** | Indirect loss of funds, incorrect protocol behavior, or edge-case exploits. |",
        "| 🟢 **Low** | Best-practice violations, missing checks, or minor inaccuracies. |",
        "| ⚪ **Info** | Code quality, gas optimizations, or documentation improvements. |",
        "",
        "---",
        "",
    ]

    # ── Protocol Context (LLM Enrichment) ─────────────────────────────────────
    if enrichment_data.get("protocol_purpose"):
        lines += [
            "## Protocol Overview",
            "",
            enrichment_data.get("protocol_purpose", ""),
            "",
        ]
    invariants = enrichment_data.get("invariants", [])
    if invariants:
        lines += [
            "### Key Invariants",
            "",
            "The following invariants were inferred from the codebase:",
            "",
            "| ID | Invariant | Severity if Broken |",
            "|---|---|:---:|",
        ]
        for inv in invariants:
            if isinstance(inv, dict):
                lines.append(
                    f"| `{inv.get('id', '?')}` | {inv.get('description', '')} "
                    f"| {inv.get('severity_if_broken', '?')} |"
                )
        lines.append("")

    # ── Table of Contents ─────────────────────────────────────────────────────
    lines += ["## Findings", ""]

    # Group by severity for TOC
    by_sev: dict[str, list] = {}
    for h in findings:
        by_sev.setdefault(_sev(h), []).append(h)

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"### {SEVERITY_EMOJI[sev]} {SEVERITY_LABEL[sev]} ({len(group)} finding{'s' if len(group) > 1 else ''})")
        lines.append("")
        lines.append("| ID | Title | Location |")
        lines.append("|:---:|---|---|")
        for h in group:
            fid = finding_ids[h.id]
            anchor = _slugify(f"{fid} {h.title}")
            lines.append(f"| [{fid}](#{anchor}) | {h.title} | `{h.location}` |")
        lines.append("")

    lines += ["---", ""]

    # ── Detailed Findings ─────────────────────────────────────────────────────
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines += [
            f"## {SEVERITY_EMOJI[sev]} {SEVERITY_LABEL[sev]} Findings",
            "",
        ]
        for h in group:
            fid = finding_ids[h.id]
            _write_finding_section(
                lines, h, fid,
                poc_code=pocs.get(h.id),
                critic_text=challenge_map.get(h.id),
                critic_verdict=challenge_verdict.get(h.id),
            )

    # ── Compound Exploit Chains ───────────────────────────────────────────────
    if compound_exploits:
        lines += [
            "---",
            "",
            "## ⛓️ Compound Exploit Chains",
            "",
            "_The following findings can be combined into multi-step attacks:_",
            "",
        ]
        for chain in compound_exploits:
            lines.append(chain.to_markdown())
            lines.append("")

    # ── Appendix: Confidence Scores ───────────────────────────────────────────
    if confidence_scores:
        try:
            from avadhi.agents.confidence_scorer import scores_to_markdown_table
            lines += [
                "---",
                "",
                "## Appendix A: Confidence Score Matrix",
                "",
                "_4-axis scoring: Structural Evidence + Critic Verdict + Severity + RAG Corroboration_",
                "",
                scores_to_markdown_table(confidence_scores),
                "",
            ]
        except Exception:
            pass

    # ── Appendix: Methodology ─────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "## Appendix B: Audit Methodology",
        "",
        "| Phase | Description |",
        "|---|---|",
        "| **Phase 1 — Recon** | Structural parsing + SecurityGraph construction (nodes: contracts, functions, state vars; edges: CALLS, WRITES, READS, INHERITS). |",
        "| **Phase 1c — Enrichment** | LLM-based protocol classification, invariant extraction, and trust boundary mapping. |",
        "| **Phase 2 — Hunting** | 18+ specialized hunter agents run in parallel (AccessControl, Oracle, CrossChain, ERC20Safety, UpgradeableSafety, …). |",
        "| **Phase 2b — Cross-Feed** | Agents share findings; hunters re-scan with compound context. |",
        "| **Phase 2c — Depth** | High/Critical findings are re-examined with targeted RAG against known exploits. |",
        "| **Phase 3 — Critic** | Every hypothesis is adversarially challenged by a Critic LLM in parallel. |",
        "| **Phase 3b — Chain Analysis** | Multi-step exploit chains across findings are identified. |",
        "| **Phase 4 — PoC** | Runnable Foundry proof-of-concept tests are generated for verified findings. |",
        "",
        f"_Report generated by Avadhi v0.1 on {now.strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
    ]

    # Write
    report_file = out_dir / "report.md"
    report_file.write_text("\n".join(lines), encoding="utf-8")
    return report_file


# ── Finding Section ───────────────────────────────────────────────────────────

def _write_finding_section(
    lines: list[str],
    h,
    fid: str,
    poc_code: str | None,
    critic_text: str | None,
    critic_verdict: str | None,
) -> None:
    sev = _sev(h)
    emoji = SEVERITY_EMOJI.get(sev, "⚫")
    label = SEVERITY_LABEL.get(sev, sev)
    conf = _conf(h)

    lines += [
        f"### {fid} — {h.title}",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Severity** | {emoji} {label} |",
        f"| **Category** | {h.category} |",
        f"| **Location** | `{h.location}` |",
        f"| **Hunter** | {h.hunter_agent} |",
        f"| **Confidence** | {conf} |",
        "",
    ]

    # Description
    lines += [
        "#### Vulnerability Details",
        "",
        h.description,
        "",
    ]

    # Attack scenario
    if h.attack_scenario:
        lines += [
            "#### Attack Scenario",
            "",
            h.attack_scenario,
            "",
        ]

    # Impact
    if h.impact:
        lines += [
            "#### Impact",
            "",
            h.impact,
            "",
        ]

    # Evidence
    if h.evidence:
        lines += ["#### Evidence", ""]
        for ev in h.evidence:
            lines.append(f"- {ev}")
        lines.append("")

    # PoC
    if poc_code:
        lines += [
            "#### Proof of Concept",
            "",
            "<details>",
            "<summary>Foundry Test</summary>",
            "",
            "```solidity",
            poc_code.strip(),
            "```",
            "",
            "</details>",
            "",
        ]

    # Recommended Mitigation
    lines += [
        "#### Recommended Mitigation",
        "",
        "_Review the attack scenario above and apply the principle of least privilege, "
        "validate all external inputs, and add the necessary invariant checks._",
        "",
    ]

    # Critic debate (collapsible)
    if critic_text:
        lines += [
            "<details>",
            f"<summary>Critic Debate Log ({critic_verdict or 'N/A'})</summary>",
            "",
            f"> {critic_text}",
            "",
            "</details>",
            "",
        ]

    lines += ["---", ""]
