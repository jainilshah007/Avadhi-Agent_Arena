"""
avadhi/recon/parser.py — Regex-based Solidity parser.

Extracts contracts, functions, state variables, external calls,
token flows, events, and modifiers from raw .sol source code.
Populates SecurityGraph Layer 0 (deterministic facts).

Falls back to this when Slither is not available.
"""
from __future__ import annotations

import re
from pathlib import Path

from avadhi.config import SKIP_DIRS
from avadhi.core.graph import (
    SecurityGraph, TAINT_USER_INPUT, TAINT_STATE, MODIFIER, STATE_VAR,
)


# ═══════════════════════════════════════════════════════════════════════════════
# File Discovery
# ═══════════════════════════════════════════════════════════════════════════════

def discover_sol_files(target: Path, scope: list[str] | None = None) -> dict[str, str]:
    """Find all .sol files under target, return {path: content}."""
    files: dict[str, str] = {}
    for f in sorted(target.rglob("*.sol")):
        if not f.is_file():
            continue
        if any(skip in f.parts for skip in SKIP_DIRS):
            continue
        if scope:
            rel_path = str(f.relative_to(target))
            # Match against multiple strategies:
            # 1. Exact rel_path match (scope relative to target)
            # 2. Exact filename match (scope is bare filenames)
            # 3. Suffix match (scope relative to parent dir, e.g. "contracts/Foo.sol")
            if not any(
                s == rel_path or s == f.name or s.endswith("/" + rel_path)
                for s in scope
            ):
                continue
        try:
            files[str(f)] = f.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  ⚠️  Cannot read {f}: {e}")
    return files


# ═══════════════════════════════════════════════════════════════════════════════
# Regex Patterns
# ═══════════════════════════════════════════════════════════════════════════════

RE_CONTRACT = re.compile(
    r"(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)"
    r"(?:\s+is\s+([^{]+))?\s*\{",
)

RE_FUNCTION = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*"
    r"((?:(?!returns\s*\()[\w]+\s*(?:\([^)]*\))?\s*)*)"
    r"(?:returns\s*\(([^)]*)\))?\s*[{;]",
)

RE_STATE_VAR = re.compile(
    r"^\s+((?:mapping\s*\([^)]+\)|uint\d*|int\d*|address|bool|bytes\d*|"
    r"string|IERC\w+|I\w+)\s*(?:\[\])?\s*"
    r"(?:public|private|internal|immutable|constant|\s)*)\s+(\w+)\s*[;=]",
    re.MULTILINE,
)

RE_MODIFIER_DEF = re.compile(r"modifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{")
RE_EVENT_DEF = re.compile(r"event\s+(\w+)\s*\(")
RE_EXTERNAL_CALL = re.compile(
    r"(\w+(?:\.\w+)*)\s*\.\s*(call|delegatecall|staticcall|transfer|send)\s*[({(]",
)
RE_EXTERNAL_CALL_BROAD = re.compile(
    r"(\w+(?:\.\w+)*)\.(?:call|delegatecall|staticcall)\s*\(",
)
RE_TOKEN_OP = re.compile(
    r"(\w+)\s*\.\s*(transfer|transferFrom|safeTransfer|safeTransferFrom|approve|safeApprove)\s*\(",
)
RE_EMIT = re.compile(r"emit\s+(\w+)\s*\(")
RE_ONLY_MODIFIER = re.compile(r"\b(only\w+)\b")

# Words that look like var names but aren't
VAR_BLACKLIST = frozenset({"returns", "memory", "storage", "calldata", "indexed"})


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_body(content: str, brace_pos: int) -> tuple[str, int]:
    """Extract text between matched braces starting at brace_pos (after '{')."""
    depth = 1
    pos = brace_pos
    while pos < len(content) and depth > 0:
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
        pos += 1
    return content[brace_pos:pos - 1], pos


def _line_number(content: str, char_pos: int) -> int:
    return content[:char_pos].count("\n") + 1


def _extract_param_names(params_str: str) -> list[str]:
    """Extract parameter names from a function signature."""
    if not params_str.strip():
        return []
    names = []
    for p in params_str.split(","):
        parts = p.strip().split()
        if parts:
            name = parts[-1]
            if name not in VAR_BLACKLIST:
                names.append(name)
    return names


def _infer_taint(target_expr: str, param_names: list[str]) -> str:
    """Determine if an external call target is user-controlled."""
    target_root = target_expr.split(".")[0] if "." in target_expr else target_expr

    # Direct param match
    if target_root in param_names:
        return TAINT_USER_INPUT

    # Struct field from param (e.g., _bridgeDetails.to)
    for p in param_names:
        if p and target_expr.startswith(p + "."):
            return TAINT_USER_INPUT

    return TAINT_STATE


# ═══════════════════════════════════════════════════════════════════════════════
# Data Flow Inference (READS / WRITES)
# ═══════════════════════════════════════════════════════════════════════════════

RE_DELETE = re.compile(r"\bdelete\s+(\w+)")


def _infer_data_flow(fn_body: str, contract_name: str, fn_name: str,
                     param_names: list[str], sg: SecurityGraph):
    """Infer READS and WRITES edges by scanning function body for state variable references."""
    # Collect state variables for this contract
    contract_vars: set[str] = set()
    for node_id, data in sg.G.nodes(data=True):
        if (data.get("type") == STATE_VAR
                and data.get("contract") == contract_name
                and not data.get("is_constant")
                and not data.get("is_immutable")):
            contract_vars.add(data.get("name", ""))

    if not contract_vars:
        return

    # Also collect inherited contract vars
    contract_node_data = sg.G.nodes.get(f"contract:{contract_name}", {})
    inheritance = contract_node_data.get("inheritance", [])
    for parent in inheritance:
        for node_id, data in sg.G.nodes(data=True):
            if (data.get("type") == STATE_VAR
                    and data.get("contract") == parent
                    and not data.get("is_constant")
                    and not data.get("is_immutable")):
                contract_vars.add(data.get("name", ""))

    # Exclude local variables / parameter names from being treated as state vars
    local_names = set(param_names)
    # Also detect local variable declarations (type varName = ...)
    for local_m in re.finditer(r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|string)\s+(\w+)", fn_body):
        local_names.add(local_m.group(1))

    # Find which state vars are written (LHS of assignment) and read
    written_vars: set[str] = set()
    read_vars: set[str] = set()

    for var in contract_vars:
        if var in local_names:
            continue
        escaped = re.escape(var)
        # Check if var is mentioned at all
        if not re.search(r'\b' + escaped + r'\b', fn_body):
            continue
        read_vars.add(var)

        # Check for write patterns:
        # 1. varName = (not ==, !=)
        # 2. varName += / -= / *= / etc.
        # 3. varName[...] =
        # 4. varName.field =
        # 5. varName++ / varName--
        # 6. ++varName / --varName
        # 7. delete varName
        write_patterns = [
            escaped + r'(?:\s*\[[^\]]*\])*(?:\.\w+)*\s*[+\-*/|&^%]?=[^=]',
            escaped + r'\s*\+\+',
            escaped + r'\s*--',
            r'\+\+\s*' + escaped,
            r'--\s*' + escaped,
            r'\bdelete\s+' + escaped,
        ]
        for pat in write_patterns:
            if re.search(pat, fn_body):
                written_vars.add(var)
                break

    # Build a map from var name to node ID (handles inheritance)
    var_node_map: dict[str, str] = {}
    for node_id, data in sg.G.nodes(data=True):
        if data.get("type") == STATE_VAR:
            name = data.get("name", "")
            ctr = data.get("contract", "")
            if ctr == contract_name or ctr in inheritance:
                var_node_map[name] = node_id

    fn_node = f"fn:{contract_name}.{fn_name}"

    # Add edges — WRITES takes priority over READS since NetworkX DiGraph
    # only allows one edge per (u, v) pair. A write implies a read anyway.
    for var in written_vars:
        dst = var_node_map.get(var)
        if dst and sg.G.has_node(fn_node):
            sg.G.add_edge(fn_node, dst, type="WRITES")
    for var in read_vars - written_vars:
        dst = var_node_map.get(var)
        if dst and sg.G.has_node(fn_node):
            sg.G.add_edge(fn_node, dst, type="READS")


# ═══════════════════════════════════════════════════════════════════════════════
# Main Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_solidity(file_path: str, content: str, sg: SecurityGraph):
    """Parse one Solidity file and populate the SecurityGraph."""

    for cm in RE_CONTRACT.finditer(content):
        contract_name = cm.group(1)
        parents_raw = cm.group(2)
        parents = [p.strip() for p in parents_raw.split(",")
                   if p.strip()] if parents_raw else []

        # Detect contract kind
        declaration = content[cm.start():cm.end()]
        is_interface = "interface" in declaration
        is_library = "library" in declaration
        is_abstract = "abstract" in content[max(0, cm.start() - 15):cm.start()]

        # Extract body
        body, _ = _extract_body(content, cm.end())
        sloc = sum(1 for line in body.split("\n")
                   if line.strip() and not line.strip().startswith("//")
                   and not line.strip().startswith("*"))

        sg.add_contract(
            contract_name, file=file_path, sloc=sloc,
            inheritance=parents, is_interface=is_interface,
            is_library=is_library, is_abstract=is_abstract,
        )

        # State variables
        for sv in RE_STATE_VAR.finditer(body):
            var_name = sv.group(2)
            if var_name and var_name not in VAR_BLACKLIST:
                decl = sv.group(1)
                sg.add_state_var(
                    contract_name, var_name,
                    var_type=decl.strip(),
                    is_constant="constant" in decl,
                    is_immutable="immutable" in decl,
                )

        # Modifier definitions
        for mod_m in RE_MODIFIER_DEF.finditer(body):
            mod_id = f"modifier:{mod_m.group(1)}"
            if not sg.G.has_node(mod_id):
                sg.G.add_node(mod_id, type=MODIFIER, name=mod_m.group(1),
                              contract=contract_name)

        # Event definitions
        for ev_m in RE_EVENT_DEF.finditer(body):
            ev_id = f"event:{contract_name}.{ev_m.group(1)}"
            if not sg.G.has_node(ev_id):
                sg.G.add_node(ev_id, type="Event", name=ev_m.group(1),
                              contract=contract_name)

        # Functions
        for fn in RE_FUNCTION.finditer(body):
            _parse_function(fn, body, content, cm, contract_name, sg, file_path)


def _parse_function(fn_match, contract_body: str, file_content: str,
                    contract_match, contract_name: str, sg: SecurityGraph,
                    file_path: str = ""):
    """Parse a single function and its body."""
    fn_name = fn_match.group(1)
    fn_params = fn_match.group(2).strip()
    fn_quals = fn_match.group(3) or ""

    # Visibility
    visibility = "internal"
    for v in ("external", "public", "private", "internal"):
        if v in fn_quals:
            visibility = v
            break

    # Mutability
    mutability = "nonpayable"
    for m in ("view", "pure", "payable"):
        if m in fn_quals:
            mutability = m
            break

    # Access control modifiers
    modifiers = RE_ONLY_MODIFIER.findall(fn_quals)
    fn_line = _line_number(file_content, contract_match.start() + fn_match.start())

    # Extract function body
    last_char = contract_body[fn_match.end() - 1] if fn_match.end() > 0 else ""
    if last_char == "{":
        fn_body, _ = _extract_body(contract_body, fn_match.end())
        fn_end_line = fn_line + fn_body.count("\n")
    else:
        fn_body = ""
        fn_end_line = fn_line

    sg.add_function(
        contract_name, fn_name,
        visibility=visibility, mutability=mutability,
        modifiers=modifiers, params=fn_params,
        line_start=fn_line, line_end=fn_end_line,
        file=file_path,
    )

    if not fn_body:
        return

    param_names = _extract_param_names(fn_params)

    # External calls
    seen_pos: set[int] = set()
    for regex in (RE_EXTERNAL_CALL, RE_EXTERNAL_CALL_BROAD):
        for ec in regex.finditer(fn_body):
            if ec.start() in seen_pos:
                continue
            seen_pos.add(ec.start())
            target_expr = ec.group(1)
            call_type = ec.group(2)
            data_source = _infer_taint(target_expr, param_names)

            sg.add_external_call(
                contract_name, fn_name, call_type,
                target=target_expr, call_type=call_type,
                data_source=data_source,
                value_sent=(call_type in ("transfer", "send") or
                            "value" in fn_body[max(0, ec.start() - 20):ec.start()]),
                line=_line_number(file_content,
                                  contract_match.start() + fn_match.start() + ec.start()),
            )

    # Token operations
    for tok in RE_TOKEN_OP.finditer(fn_body):
        sg.add_token_flow(
            contract_name, fn_name,
            token=tok.group(1), flow_type=tok.group(2),
            line=_line_number(file_content,
                              contract_match.start() + fn_match.start() + tok.start()),
        )

    # Events
    for em in RE_EMIT.finditer(fn_body):
        sg.add_event(contract_name, fn_name, em.group(1))

    # Internal calls (functions starting with _)
    for call_m in re.finditer(r"\b(_\w+)\s*\(", fn_body):
        callee = call_m.group(1)
        sg.add_call(contract_name, fn_name, contract_name, callee)

    # Data flow: WRITES and READS for state variables
    _infer_data_flow(fn_body, contract_name, fn_name, param_names, sg)
