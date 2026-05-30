"""
avadhi/recon/slither.py — Slither integration.

Two modes:
  1. build_graph_from_slither_api()  — Python API, primary graph builder.
     Gives accurate modifiers, transitive state-write sets, internal call
     graph, and low/high-level external call extraction.

  2. try_slither() / parse_slither_findings()  — CLI subprocess, used to
     layer detector findings as flags on top of the graph.  Falls back to
     this when Python API fails.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from avadhi.config import SLITHER_PATH
from avadhi.core.graph import (
    SecurityGraph, TAINT_USER_INPUT, TAINT_STATE,
)

if TYPE_CHECKING:
    pass

# Slither emits a lot of INFO/WARNING noise — suppress during API calls
_SLITHER_LOGGERS = [
    "Slither", "CryticCompile", "ContractSolcParsing",
    "slither", "crytic_compile",
]

# Path segments that indicate out-of-scope code (vendor, test, mock, etc.)
# Mirrors avadhi.config.SKIP_DIRS for consistency.
# Note: "/lib/" was removed — it's too aggressive and filters out project-owned
# libraries (e.g., contracts/lib/TicketComboTracker.sol). Instead we match
# specific vendor library paths like forge-std, openzeppelin, solmate, etc.
_VENDOR_MARKERS = frozenset({
    "node_modules", "/forge-std/", "/openzeppelin/", "/solmate/",
    "/solady/", "/@openzeppelin/",
    "/test/", "/tests/", "/mock/", "/mocks/", "/script/",
    "/artifacts/", "/cache/", "/out/", "/build/",
})


# ─────────────────────────────────────────────────────────────────────────────
# Compilation root detection
# ─────────────────────────────────────────────────────────────────────────────

# Ordered list of (filename, framework_name) pairs to look for
_FRAMEWORK_CONFIGS = [
    ("foundry.toml",         "foundry"),
    ("hardhat.config.ts",    "hardhat"),
    ("hardhat.config.js",    "hardhat"),
    ("truffle-config.js",    "truffle"),
    ("brownie-config.yaml",  "brownie"),
]


def _find_compilation_root(start: Path) -> tuple[Path, str | None]:
    """
    Walk upward from `start` (up to 5 levels) searching for a compilation
    framework config file.

    Returns:
        (project_root, framework_name)  if a config is found
        (start, None)                    if nothing is found (caller uses start as-is)
    """
    candidate = start if start.is_dir() else start.parent
    for _ in range(5):
        for filename, framework in _FRAMEWORK_CONFIGS:
            if (candidate / filename).exists():
                return candidate, framework
        parent = candidate.parent
        if parent == candidate:   # filesystem root
            break
        candidate = parent
    return start if start.is_dir() else start.parent, None



def build_graph_from_slither_api(
    target_path: str,
    sg: SecurityGraph,
    verbose: bool = False,
) -> bool:
    """
    Populate `sg` using the Slither Python API.

    Returns True if at least one in-scope contract was parsed.
    Returns False to signal the caller to fall back to the regex parser.
    """
    try:
        _silence_slither_loggers()
        from slither import Slither  # type: ignore

        # --- Auto-detect compilation framework ----------------------------
        project_root, framework = _find_compilation_root(Path(target_path))

        slither_kwargs: dict = {}
        if framework == "foundry":
            slither_kwargs["compile_force_framework"] = "foundry"
            slither_target = str(project_root)
        elif framework == "hardhat":
            slither_kwargs["compile_force_framework"] = "hardhat"
            slither_target = str(project_root)
        elif framework == "truffle":
            slither_kwargs["compile_force_framework"] = "truffle"
            slither_target = str(project_root)
        else:
            # No config found — try passing target as-is (works for single files)
            slither_target = target_path

        if verbose and framework:
            print(f"  Slither: detected {framework} project root at {project_root}")

        # Run Slither in a thread with a hard timeout — compilation can hang
        # indefinitely if node_modules are absent or solc is slow to download.
        import concurrent.futures as _cf
        from avadhi.config import SLITHER_TIMEOUT
        _SLITHER_TIMEOUT = SLITHER_TIMEOUT

        def _init_slither():
            return Slither(slither_target, **slither_kwargs)

        with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
            _fut = _pool.submit(_init_slither)
            try:
                sl = _fut.result(timeout=_SLITHER_TIMEOUT)
            except _cf.TimeoutError:
                if verbose:
                    print(f"  Slither init timed out after {_SLITHER_TIMEOUT}s — using regex parser")
                return False

    except Exception as e:
        if verbose:
            print(f"  Slither API init failed: {e}")
        return False

    contracts_added = 0

    for contract in sl.contracts:
        if not _is_in_scope(contract):
            continue

        file_path = _contract_file(contract)
        parents = [p.name for p in contract.inheritance]

        sg.add_contract(
            contract.name,
            file=file_path,
            sloc=0,
            inheritance=parents,
            is_interface=contract.is_interface,
            is_library=contract.is_library,
            is_abstract=getattr(contract, "is_abstract", False),
        )
        contracts_added += 1

        # ── State variables ───────────────────────────────────────────────
        for sv in contract.state_variables:
            sg.add_state_var(
                contract.name, sv.name,
                var_type=str(sv.type),
                is_constant=sv.is_constant,
                is_immutable=sv.is_immutable,
            )

        # ── Functions ─────────────────────────────────────────────────────
        all_fns = list(contract.functions) + list(contract.modifiers)
        for fn in all_fns:
            # Skip inherited definitions (only add where declared)
            if getattr(fn, "contract_declarer", None) != contract:
                continue
            _add_function_to_graph(fn, contract, sg)

    if verbose:
        print(f"  ✅ Slither API: {contracts_added} in-scope contracts")

    if contracts_added == 0:
        return False

    # Second pass: wire call/read/write edges (needs all nodes present first)
    for contract in sl.contracts:
        if not _is_in_scope(contract):
            continue
        all_fns = list(contract.functions) + list(contract.modifiers)
        for fn in all_fns:
            if getattr(fn, "contract_declarer", None) != contract:
                continue
            _add_edges_for_function(fn, contract, sg)

    return True


def _silence_slither_loggers():
    for name in _SLITHER_LOGGERS:
        logging.getLogger(name).setLevel(logging.CRITICAL)
    logging.disable(logging.CRITICAL)


def _is_in_scope(contract) -> bool:
    """Return True if the contract is a project file, not a vendor dependency."""
    try:
        fp = str(contract.source_mapping.filename.absolute)
    except Exception:
        return False
    return not any(marker in fp for marker in _VENDOR_MARKERS)


def _contract_file(contract) -> str:
    try:
        return str(contract.source_mapping.filename.absolute)
    except Exception:
        return ""


def _add_function_to_graph(fn, contract, sg: SecurityGraph):
    """Register a function node in the SecurityGraph."""
    # Mutability
    if getattr(fn, "view", False):
        mutability = "view"
    elif getattr(fn, "pure", False):
        mutability = "pure"
    elif getattr(fn, "payable", False):
        mutability = "payable"
    else:
        mutability = "nonpayable"

    # All modifiers (including custom ones like noEmergencyMode)
    modifier_names = [m.name for m in getattr(fn, "modifiers", [])]

    # Parameters as a compact string
    try:
        params_str = ", ".join(
            f"{p.type} {p.name}" for p in fn.parameters
        )
    except Exception:
        params_str = ""

    # Source location
    try:
        lines = fn.source_mapping.lines
        line_start = lines[0] if lines else 0
        line_end = lines[-1] if lines else 0
    except Exception:
        line_start = line_end = 0

    sg.add_function(
        contract.name, fn.name,
        visibility=getattr(fn, "visibility", "internal"),
        mutability=mutability,
        modifiers=modifier_names,
        params=params_str,
        line_start=line_start,
        line_end=line_end,
    )

    # Store the source file path on the node so get_source_for_functions
    # can do a direct lookup without scanning all files.
    fn_id = f"fn:{contract.name}.{fn.name}"
    file_path = _contract_file(contract)
    if file_path and sg.G.has_node(fn_id):
        sg.G.nodes[fn_id]["file"] = file_path


def _add_edges_for_function(fn, contract, sg: SecurityGraph):
    """Add READS, WRITES, CALLS, EXTERNAL_CALL, TOKEN_FLOW edges."""
    fn_id = f"fn:{contract.name}.{fn.name}"
    if not sg.G.has_node(fn_id):
        return

    param_names = {p.name for p in getattr(fn, "parameters", [])}

    # ── Direct state writes ────────────────────────────────────────────────
    try:
        for sv in fn.state_variables_written:
            sv_id = f"var:{sv.contract.name}.{sv.name}"
            if sg.G.has_node(sv_id):
                if not sg.G.has_edge(fn_id, sv_id):
                    sg.G.add_edge(fn_id, sv_id, type="WRITES")
    except Exception:
        pass

    # ── Transitive state writes (through internal calls) ──────────────────
    try:
        for sv in fn.all_state_variables_written():
            sv_id = f"var:{sv.contract.name}.{sv.name}"
            if sg.G.has_node(sv_id):
                if not sg.G.has_edge(fn_id, sv_id):
                    sg.G.add_edge(fn_id, sv_id, type="WRITES")
    except Exception:
        pass

    # ── State reads ───────────────────────────────────────────────────────
    try:
        for sv in fn.state_variables_read:
            sv_id = f"var:{sv.contract.name}.{sv.name}"
            if sg.G.has_node(sv_id):
                if not sg.G.has_edge(fn_id, sv_id):
                    sg.G.add_edge(fn_id, sv_id, type="READS")
    except Exception:
        pass

    # ── Internal call graph ───────────────────────────────────────────────
    try:
        for ic in fn.internal_calls:
            if not hasattr(ic, "name") or not hasattr(ic, "contract_declarer"):
                continue
            callee_id = f"fn:{ic.contract_declarer.name}.{ic.name}"
            if sg.G.has_node(callee_id) and not sg.G.has_edge(fn_id, callee_id):
                sg.G.add_edge(fn_id, callee_id, type="CALLS")
    except Exception:
        pass

    # ── Low-level external calls (.call / .delegatecall) ──────────────────
    try:
        for (ref, call_type) in fn.low_level_calls:
            target_str = _resolve_ref(ref, param_names)
            taint = TAINT_USER_INPUT if _is_user_controlled(ref, param_names) else TAINT_STATE
            sg.add_external_call(
                contract.name, fn.name, call_type,
                target=target_str, call_type=call_type,
                data_source=taint,
                value_sent=False,
                line=_fn_line(fn),
            )
    except Exception:
        pass

    # ── High-level calls (token flows + known contract interactions) ───────
    try:
        for hc in fn.high_level_calls:
            # Slither ≥0.10 returns (Contract, Function) 2-tuples
            ext_contract = hc[0]
            fn_called = hc[1]
            called_name = getattr(fn_called, "name", "")
            ext_name = getattr(ext_contract, "name", "")
            if called_name in (
                "transfer", "transferFrom", "safeTransfer",
                "safeTransferFrom", "approve", "safeApprove",
            ):
                sg.add_token_flow(
                    contract.name, fn.name,
                    token=ext_name,
                    flow_type=called_name,
                )
    except Exception:
        pass


def _resolve_ref(ref, param_names: set) -> str:
    """Get a human-readable target label from a ReferenceVariable."""
    points_to = getattr(ref, "points_to", None)
    if points_to is not None:
        name = getattr(points_to, "name", str(points_to))
        return str(name)
    return str(ref)


def _is_user_controlled(ref, param_names: set) -> bool:
    """True if the reference ultimately points to a function parameter."""
    obj = ref
    visited: set = set()
    while obj is not None and id(obj) not in visited:
        visited.add(id(obj))
        name = getattr(obj, "name", "")
        if name in param_names:
            return True
        obj = getattr(obj, "points_to", None)
    return False


def _fn_line(fn) -> int:
    try:
        lines = fn.source_mapping.lines
        return lines[0] if lines else 0
    except Exception:
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Secondary: Slither CLI subprocess (detector findings as flags)
# ─────────────────────────────────────────────────────────────────────────────

def try_slither(target: str) -> dict | None:
    """Run slither --json - and return parsed output, or None if unavailable."""
    try:
        result = subprocess.run(
            [SLITHER_PATH, target, "--json", "-"],
            capture_output=True, text=True, timeout=120,
            cwd=target if Path(target).is_dir() else str(Path(target).parent),
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        print("  ⚠️  Slither timed out (120s)")
    except json.JSONDecodeError:
        print("  ⚠️  Slither output not valid JSON")
    return None


def parse_slither_findings(data: dict, sg: SecurityGraph):
    """Add Slither detector findings as flags on relevant graph nodes."""
    for det in data.get("results", {}).get("detectors", []):
        severity = det.get("impact", "").lower()
        check = det.get("check", "")
        if severity not in ("high", "medium"):
            continue
        for elem in det.get("elements", []):
            if elem.get("type") == "function":
                contract = (elem.get("type_specific_fields", {})
                           .get("parent", {}).get("name", ""))
                fn_name = elem.get("name", "")
                if contract and fn_name:
                    sg.add_flag(f"fn:{contract}.{fn_name}", f"SLITHER:{check}")
