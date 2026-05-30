"""
avadhi/agents/invariant.py — Protocol Invariant Extractor (Phase 1d).

Inspired by Plamen/BEAST Phase 4: before hunters run, extract:
  1. Which state variables exist and which functions write them
  2. What invariants the protocol IMPLICITLY assumes are always true
  3. Which write sites might violate those invariants

Results are stored in sg.metadata["invariants"] and
sg.metadata["write_map"] for hunters to consume.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS
from avadhi.utils.llm import get_llm
from langchain_core.messages import SystemMessage, HumanMessage

if TYPE_CHECKING:
    from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor performing PROTOCOL INVARIANT ANALYSIS.

You are given a complete map of:
- Every state variable in the protocol
- Every function that writes each state variable
- The protocol type and any known invariants

Your job: identify the IMPLICIT invariants that this protocol MUST maintain for correct operation.
These are invariants that are NOT written in comments or NatSpec but that every function depends on.

Return a JSON array of invariant objects. Each invariant should capture:
1. What relationship must ALWAYS be true
2. Which state variables are involved
3. Which functions are responsible for maintaining it
4. Which functions are at HIGHEST RISK of violating it (write the relevant vars but may not maintain the relationship)

Focus on invariants in these categories:
- Fee/rate invariants: "minimum reward rate must hold on NET amount, not gross"
- State-machine invariants: "overrideCampaign must validate against EFFECTIVE state, not original"
- Balance invariants: "total distributed <= total deposited"
- Authorization invariants: "only initialized proxy can be upgraded"
- Time invariants: "end timestamp must always be > start timestamp"

Output format:
```json
[
  {
    "invariant": "Human-readable description of what must always be true",
    "variables": ["stateVar1", "stateVar2"],
    "responsible_functions": ["functionA", "functionB"],
    "risk_functions": ["functionC"],
    "category": "fee_rate|balance|state_machine|authorization|time|other"
  }
]
```

Return at most 8 invariants. Focus on the ones most likely to have real bugs."""


def extract_invariants(
    sg: SecurityGraph,
    logger: "AuditLogger | None" = None,
    verbose: bool = False,
) -> list[str]:
    """
    Phase 1d: Extract protocol invariants from the SecurityGraph.

    Stores results in:
      sg.metadata["invariants"] — list of invariant description strings
      sg.metadata["write_map"]  — dict[var_name -> [fn_names]] for hunter use

    Returns the list of invariant strings.
    """
    if verbose:
        print("   InvariantExtractor: mapping state variable write sites...")

    # ── Build write map ──────────────────────────────────────────────────────
    write_map: dict[str, list[str]] = {}   # var_name -> [fn_names]
    var_contract_map: dict[str, str] = {}  # var_name -> contract

    for var_id, vdata in sg.get_nodes_by_type(STATE_VAR):
        if vdata.get("is_constant") or vdata.get("is_immutable"):
            continue
        var_name = f"{vdata.get('contract','')}.{vdata.get('name','')}"
        writers = sg.get_writers(var_id)
        writer_names = [
            f"{sg.G.nodes.get(w, {}).get('contract','')}.{sg.G.nodes.get(w, {}).get('name','')}"
            for w in writers
        ]
        write_map[var_name] = writer_names
        var_contract_map[var_name] = vdata.get("contract", "")

    if not write_map:
        if verbose:
            print("  ℹ️  InvariantExtractor: no state variables found")
        return []

    # ── Build LLM context ────────────────────────────────────────────────────
    # Group by contract for readability
    contract_vars: dict[str, list[str]] = {}
    for var_name, writers in write_map.items():
        contract = var_contract_map.get(var_name, "Unknown")
        contract_vars.setdefault(contract, []).append(
            f"  {var_name} → written by: [{', '.join(writers[:6])}]"
        )

    context_parts = [
        f"# Protocol Type: {sg.metadata.get('enrichment_data', {}).get('protocol_type', 'DeFi')}",
        "",
        "# State Variable Write Map (variable → functions that write it)",
    ]
    for contract, var_lines in sorted(contract_vars.items()):
        context_parts.append(f"\n## Contract: {contract}")
        context_parts.extend(var_lines[:20])  # cap per contract

    # Add any existing enrichment invariants as seed
    existing = sg.metadata.get("invariants", [])
    if existing:
        context_parts.append("\n# Known Invariants (from Phase 1c enrichment)")
        for inv in existing:
            context_parts.append(f"- {inv}")

    context = "\n".join(context_parts)

    if verbose:
        print(f"  📊 InvariantExtractor: {len(write_map)} vars across "
              f"{len(contract_vars)} contracts → querying LLM...")

    # ── Call LLM ─────────────────────────────────────────────────────────────
    llm = get_llm()
    start = time.time()

    try:
        from avadhi.agents.hunters.base import _invoke_with_backoff
        response = _invoke_with_backoff(
            llm,
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=context)],
            hunter_name="InvariantExtractor",
            max_retries=4
        )
        response_text = response.content if hasattr(response, "content") else str(response)
    except Exception as exc:
        if verbose:
            print(f"  WARNING  InvariantExtractor: LLM call failed ({exc})")
        sg.metadata["write_map"] = write_map
        return []

    latency_ms = int((time.time() - start) * 1000)

    # ── Parse response ────────────────────────────────────────────────────────
    import json

    invariant_strings: list[str] = []
    raw_invariants: list[dict] = []

    try:
        # Extract JSON from response
        text = response_text
        if "```json" in text:
            start_idx = text.index("```json") + 7
            end_idx = text.index("```", start_idx) if "```" in text[start_idx:] else len(text)
            text = text[start_idx:end_idx].strip()
        elif "```" in text:
            start_idx = text.index("```") + 3
            end_idx = text.index("```", start_idx) if "```" in text[start_idx:] else len(text)
            text = text[start_idx:end_idx].strip()

        raw_invariants = json.loads(text)
        for item in raw_invariants:
            inv_str = item.get("invariant", "")
            if inv_str:
                category = item.get("category", "other")
                risk_fns = item.get("risk_functions", [])
                risk_str = f" (WARNING risk: {', '.join(risk_fns[:3])})" if risk_fns else ""
                invariant_strings.append(f"[{category}] {inv_str}{risk_str}")
    except (json.JSONDecodeError, ValueError):
        # Fall back to treating response as plain text bullet points
        for line in response_text.split("\n"):
            line = line.strip().lstrip("-•*").strip()
            if len(line) > 20:
                invariant_strings.append(line)

    # ── Store in sg.metadata ─────────────────────────────────────────────────
    sg.metadata["write_map"] = write_map
    # Merge with any existing invariants — don't overwrite Phase 1c results
    existing_invariants = sg.metadata.get("invariants", [])
    merged = list(dict.fromkeys(existing_invariants + invariant_strings))  # dedup, preserve order
    sg.metadata["invariants"] = merged

    if verbose:
        print(f"    InvariantExtractor: {len(invariant_strings)} invariants extracted "
              f"({latency_ms}ms)")
        for inv in invariant_strings[:5]:
            print(f"    • {inv[:100]}")

    return invariant_strings
