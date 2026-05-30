"""
avadhi/agents/hunters/gas_dos.py — Gas / DoS Hunter.

Hunts for:
  - Unbounded loops over arrays that grow with user action
  - Nested loops with multiplicative gas cost
  - External calls inside loops (gas griefing)
  - Block gas limit DoS vectors
  - State machine deadlocks (functions that can permanently block protocol)
"""
from __future__ import annotations

import re
from avadhi.core.graph import SecurityGraph, FUNCTION, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in GAS and DENIAL-OF-SERVICE vulnerabilities.

You are given source code of functions that CONTAIN LOOPS or are called by loop-containing functions, along with graph context.

Your job is to find REAL gas/DoS vulnerabilities:

1. **Unbounded Loops**: Loops that iterate over arrays/mappings that grow with user actions
   (e.g., iterating all depositors, all ticket holders). These can exceed the block gas limit.

2. **Nested Loops with Multiplicative Cost**: Two or more nested loops where the product
   of iterations can blow up (e.g., `for i in N: for j in M:` where N*M > 10000).
   Especially dangerous when N or M are user-controlled or grow over time.
   PAY CLOSE ATTENTION to library functions that generate subsets or combinations —
   these often have exponential or factorial complexity hidden behind clean APIs.

3. **External Calls Inside Loops**: Each external call costs ~2600 gas minimum. A loop
   making N external calls can hit gas limits or be griefed by a reverting callee.

4. **State Machine Deadlocks**: Functions that can permanently block protocol operations.
   Example: a drawing settlement function that reverts when gas is insufficient, making
   it impossible to advance the protocol state.

5. **Griefing Vectors**: Where an attacker can cheaply cause expensive operations for others.

For each finding, calculate or estimate the gas cost growth. Be specific about what value
of N causes the function to exceed the block gas limit (typically 30M on Ethereum, 25M on
Base/L2s). Vague "this could use a lot of gas" is NOT sufficient — quantify it.

DO NOT flag:
- Loops with hardcoded small bounds (e.g., iterating over 5 enum values)
- View/pure functions UNLESS they are called by a state-changing function (the caller pays gas)
- Loops where the array size is admin-controlled and bounded by governance"""


# Regex to find for/while loops in Solidity source
_RE_LOOP = re.compile(r'\b(for|while)\s*\(')


def _scan_source_for_loops(source_files: dict[str, str]) -> dict[str, list[dict]]:
    """
    Scan source files for functions containing loops.
    Returns: {file_path: [{name, line, has_nested_loop, loop_count}]}
    """
    results: dict[str, list[dict]] = {}

    for file_path, content in source_files.items():
        lines = content.split("\n")
        # Track which function we're in by scanning for function declarations
        current_fn = None
        current_fn_line = 0
        brace_depth = 0
        fn_loops: dict[str, dict] = {}  # fn_name -> {line, loop_count, lines}

        for i, line in enumerate(lines):
            # Track brace depth
            brace_depth += line.count("{") - line.count("}")

            # Detect function declarations
            fn_match = re.search(r'\bfunction\s+(\w+)\s*\(', line)
            if fn_match:
                current_fn = fn_match.group(1)
                current_fn_line = i + 1

            # Detect loops
            if current_fn and _RE_LOOP.search(line):
                if current_fn not in fn_loops:
                    fn_loops[current_fn] = {
                        "name": current_fn,
                        "line": current_fn_line,
                        "loop_count": 0,
                        "loop_lines": [],
                    }
                fn_loops[current_fn]["loop_count"] += 1
                fn_loops[current_fn]["loop_lines"].append(i + 1)

        if fn_loops:
            for info in fn_loops.values():
                info["has_nested_loop"] = info["loop_count"] >= 2
            results[file_path] = list(fn_loops.values())

    return results


def run_gas_dos_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for gas/DoS vulnerabilities.

    Strategy:
      1. Scan SOURCE CODE for functions containing loops (for/while)
      2. From graph: find settlement/batch/process functions with high complexity
      3. Include library functions (not just external/public) since they contain
         the actual loop logic
      4. Provide full source of loop-containing functions to LLM
    """
    source_files = sg.metadata.get("source_files", {})

    # === Source-level loop scanning ===
    loop_fns: dict[str, list[dict]] = {}
    if source_files:
        loop_fns = _scan_source_for_loops(source_files)

    # Collect source snippets for ALL loop-containing functions (including internal/library)
    # Sort by loop_count descending so nested-loop functions get priority in the budget
    all_fn_infos: list[tuple[str, dict]] = []  # (file_path, info)
    loop_context_lines: list[str] = []

    for file_path, fn_infos in loop_fns.items():
        for info in fn_infos:
            all_fn_infos.append((file_path, info))
            nested = "WARNING NESTED LOOPS" if info["has_nested_loop"] else ""
            loop_context_lines.append(
                f"- {info['name']}() at {file_path}:L{info['line']} "
                f"— {info['loop_count']} loop(s) {nested} "
                f"(loop lines: {info['loop_lines']})"
            )

    # Prioritize: nested loops first, then by loop count
    all_fn_infos.sort(key=lambda x: x[1]["loop_count"], reverse=True)

    loop_snippets: list[str] = []
    total_chars = 0

    for file_path, info in all_fn_infos:
        content = source_files.get(file_path, "")
        lines = content.split("\n")

        # Extract the function source (from declaration to end)
        fn_line = info["line"] - 1  # 0-indexed
        start = max(0, fn_line - 2)
        # Find the end of the function by counting braces
        depth = 0
        end = fn_line
        found_open = False
        for j in range(fn_line, min(len(lines), fn_line + 200)):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth > 0:
                found_open = True
            if found_open and depth <= 0:
                end = j + 1
                break
        else:
            end = min(len(lines), fn_line + 100)

        snippet = "\n".join(lines[start:end])
        if total_chars + len(snippet) < 15000:
            loop_snippets.append(
                f"// {file_path} — {info['name']}() "
                f"(L{info['line']}, {info['loop_count']} loops)\n{snippet}"
            )
            total_chars += len(snippet)

    # === Graph-level analysis: find callers of loop functions ===
    graph_candidates: list[str] = []
    graph_reasons: dict[str, list[str]] = {}

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("visibility") not in ("external", "public"):
            continue
        if data.get("mutability") in ("view", "pure"):
            continue

        contract_id = f"contract:{data.get('contract', '')}"
        contract_node = sg.G.nodes.get(contract_id, {})
        if contract_node.get("is_interface"):
            continue

        reasons = []

        # High fan-out
        callees = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                   if d.get("type") == CALLS]
        if len(callees) >= 3:
            reasons.append(f"high_fanout: calls {len(callees)} internal functions")

        # Heavy writer (settlement-type)
        writes = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                  if d.get("type") == WRITES]
        if len(writes) >= 4:
            reasons.append(f"heavy_writer: modifies {len(writes)} state vars")

        fn_name = data.get("name", "").lower()
        if any(k in fn_name for k in ("batch", "settle", "process", "distribute",
                                       "claim", "run", "execute", "draw",
                                       "callback", "count", "calculate")):
            reasons.append(f"name_signal: '{data.get('name', '')}'")

        if reasons:
            graph_candidates.append(fn_id)
            graph_reasons[fn_id] = reasons

    if not loop_snippets and not graph_candidates:
        if verbose:
            print("  ℹ️  GasDoSHunter: No loop-containing or gas-sensitive functions found")
        return []

    if verbose:
        print(f"   GasDoSHunter: {len(loop_snippets)} functions with loops (source scan), "
              f"{len(graph_candidates)} graph candidates")

    # Build context — highlight nested loops first (highest severity)
    nested_fns = [(fp, info) for fp, info in all_fn_infos if info["has_nested_loop"]]
    context_lines = []
    if nested_fns:
        context_lines.append("#  HIGHEST PRIORITY — Functions With NESTED Loops\n")
        context_lines.append(
            "These have multiplicative or exponential gas complexity. "
            "Analyze these FIRST and report findings for each.\n"
        )
        for fp, info in nested_fns:
            context_lines.append(
                f"- **{info['name']}()** at {fp}:L{info['line']} "
                f"— {info['loop_count']} nested loops (lines: {info['loop_lines']})"
            )
        context_lines.append("")

    context_lines.append("# All Functions Containing Loops (from source scan)\n")
    context_lines.extend(loop_context_lines)

    if graph_candidates:
        context_lines.append("\n# Public/External Functions With Complex Logic (from graph)")
        for fn_id in graph_candidates[:15]:
            node = sg.G.nodes[fn_id]
            reasons = graph_reasons[fn_id]
            context_lines.append(
                f"- {node['contract']}.{node['name']}() "
                f"modifiers={node.get('modifiers', []) or 'NONE'}"
            )
            for r in reasons:
                context_lines.append(f"  ���️ {r}")

    context = "\n".join(context_lines)

    # Source: combine loop snippets + graph candidate source
    graph_source = get_source_for_functions(sg, graph_candidates[:10], max_chars=5000)
    all_source = "\n\n".join(loop_snippets)
    if graph_source and graph_source != "(no source available)":
        all_source += "\n\n" + graph_source

    if not all_source.strip():
        all_source = "(no source available)"

    return call_hunter(
        hunter_name="GasDoSHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=all_source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
