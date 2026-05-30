"""
avadhi/core/graph.py — Security-first knowledge graph.

Every node and edge is designed for vulnerability detection.
Layer 0 = deterministic facts (from parser/Slither)
Layer 1 = LLM-enriched annotations (invariants, taint, trust)

The SecurityGraph is the central data structure that all agents
query against. It's built in Phase 1 and enriched throughout the pipeline.
"""
from __future__ import annotations

import json
from enum import Enum
from html import escape as html_escape
from pathlib import Path
from typing import Any

import networkx as nx


# ═══════════════════════════════════════════════════════════════════════════════
# Node & Edge Type Enums
# ═══════════════════════════════════════════════════════════════════════════════

class NodeType(str, Enum):
    CONTRACT = "Contract"
    FUNCTION = "Function"
    STATE_VAR = "StateVariable"
    MODIFIER = "Modifier"
    EVENT = "Event"
    EXTERNAL_TARGET = "ExternalTarget"
    TOKEN = "Token"
    INVARIANT = "Invariant"
    TRUST_BOUNDARY = "TrustBoundary"


class EdgeType(str, Enum):
    CALLS = "CALLS"
    READS = "READS"
    WRITES = "WRITES"
    GUARDS = "GUARDED_BY"
    INHERITS = "INHERITS"
    BELONGS_TO = "BELONGS_TO"
    EXTERNAL_CALL = "EXTERNAL_CALL"
    TOKEN_FLOW = "TOKEN_FLOW"
    EMITS = "EMITS"
    DEPENDS_ON = "DEPENDS_ON"
    VIOLATES = "VIOLATES"


# Backwards-compat aliases so existing code using `from avadhi.core.graph import CONTRACT` still works
CONTRACT = NodeType.CONTRACT
FUNCTION = NodeType.FUNCTION
STATE_VAR = NodeType.STATE_VAR
MODIFIER = NodeType.MODIFIER
EVENT = NodeType.EVENT
EXTERNAL_TARGET = NodeType.EXTERNAL_TARGET
TOKEN = NodeType.TOKEN
INVARIANT = NodeType.INVARIANT
TRUST_BOUNDARY = NodeType.TRUST_BOUNDARY

CALLS = EdgeType.CALLS
READS = EdgeType.READS
WRITES = EdgeType.WRITES
GUARDS = EdgeType.GUARDS
INHERITS = EdgeType.INHERITS
BELONGS_TO = EdgeType.BELONGS_TO
EXTERNAL_CALL = EdgeType.EXTERNAL_CALL
TOKEN_FLOW = EdgeType.TOKEN_FLOW
EMITS = EdgeType.EMITS
DEPENDS_ON = EdgeType.DEPENDS_ON
VIOLATES = EdgeType.VIOLATES


# ═══════════════════════════════════════════════════════════════════════════════
# Taint Labels
# ═══════════════════════════════════════════════════════════════════════════════
TAINT_USER_INPUT = "user_input"
TAINT_STATE = "state"
TAINT_CONSTANT = "constant"
TAINT_COMPUTED = "computed"


class SecurityGraph:
    """
    A directed graph where every node/edge carries security-relevant metadata.

    Built bottom-up:
      1. Parser/Slither fills Layer 0 (facts)
      2. Pattern grep attaches flags
      3. LLM adds Layer 1 (semantic annotations, invariants, trust model)

    Thread-safe for reads. Not designed for concurrent writes.
    """

    def __init__(self):
        self.G = nx.DiGraph()
        self.flags: dict[str, list[str]] = {}
        self.metadata: dict[str, Any] = {}

    # ── Node Builders ────────────────────────────────────────────────────────

    def add_contract(self, name: str, *, file: str = "", sloc: int = 0,
                     inheritance: list[str] | None = None,
                     is_interface: bool = False, is_library: bool = False,
                     is_abstract: bool = False):
        node_id = f"contract:{name}"
        self.G.add_node(node_id, type=NodeType.CONTRACT, name=name, file=file,
                        sloc=sloc, is_interface=is_interface,
                        is_library=is_library, is_abstract=is_abstract)
        for parent in (inheritance or []):
            parent_id = f"contract:{parent}"
            if not self.G.has_node(parent_id):
                self.G.add_node(parent_id, type=NodeType.CONTRACT, name=parent)
            self.G.add_edge(node_id, parent_id, type=EdgeType.INHERITS)

    def add_function(self, contract: str, name: str, *,
                     visibility: str = "internal",
                     mutability: str = "nonpayable",
                     modifiers: list[str] | None = None,
                     params: str = "",
                     line_start: int = 0, line_end: int = 0,
                     file: str = ""):
        fn_id = f"fn:{contract}.{name}"
        self.G.add_node(fn_id, type=NodeType.FUNCTION, contract=contract, name=name,
                        visibility=visibility, mutability=mutability,
                        modifiers=modifiers or [], params=params,
                        line_start=line_start, line_end=line_end,
                        file=file)
        contract_id = f"contract:{contract}"
        if self.G.has_node(contract_id):
            self.G.add_edge(fn_id, contract_id, type=EdgeType.BELONGS_TO)
        for mod in (modifiers or []):
            mod_id = f"modifier:{mod}"
            if not self.G.has_node(mod_id):
                self.G.add_node(mod_id, type=NodeType.MODIFIER, name=mod)
            self.G.add_edge(fn_id, mod_id, type=EdgeType.GUARDS)

    def add_state_var(self, contract: str, name: str, *,
                      var_type: str = "", visibility: str = "internal",
                      is_constant: bool = False, is_immutable: bool = False):
        sv_id = f"var:{contract}.{name}"
        self.G.add_node(sv_id, type=NodeType.STATE_VAR, contract=contract, name=name,
                        var_type=var_type, visibility=visibility,
                        is_constant=is_constant, is_immutable=is_immutable)

    # ── Edge Builders ────────────────────────────────────────────────────────

    def add_call(self, caller_contract: str, caller_fn: str,
                 callee_contract: str, callee_fn: str):
        src = f"fn:{caller_contract}.{caller_fn}"
        dst = f"fn:{callee_contract}.{callee_fn}"
        self.G.add_edge(src, dst, type=EdgeType.CALLS)

    def add_read(self, contract: str, function: str, var_name: str):
        src = f"fn:{contract}.{function}"
        dst = f"var:{contract}.{var_name}"
        if self.G.has_node(dst):
            self.G.add_edge(src, dst, type=EdgeType.READS)

    def add_write(self, contract: str, function: str, var_name: str):
        src = f"fn:{contract}.{function}"
        dst = f"var:{contract}.{var_name}"
        if self.G.has_node(dst):
            self.G.add_edge(src, dst, type=EdgeType.WRITES)

    def add_external_call(self, contract: str, function: str, target_fn: str,
                          *, target: str = "", call_type: str = "call",
                          data_source: str = TAINT_STATE,
                          value_sent: bool = False, line: int = 0):
        src = f"fn:{contract}.{function}"
        ext_id = f"ext:{contract}.{function}.{target}"
        self.G.add_node(ext_id, type=NodeType.EXTERNAL_TARGET, target=target,
                        data_source=data_source, line=line)
        self.G.add_edge(src, ext_id, type=EdgeType.EXTERNAL_CALL,
                        call_type=call_type, data_source=data_source,
                        value_sent=value_sent)

    def add_token_flow(self, contract: str, function: str, *,
                       token: str = "", flow_type: str = "transfer",
                       line: int = 0):
        src = f"fn:{contract}.{function}"
        tok_id = f"token:{token}"
        if not self.G.has_node(tok_id):
            self.G.add_node(tok_id, type=NodeType.TOKEN, name=token)
        self.G.add_edge(src, tok_id, type=EdgeType.TOKEN_FLOW,
                        flow_type=flow_type, line=line)

    def add_event(self, contract: str, function: str, event_name: str):
        ev_id = f"event:{contract}.{event_name}"
        if not self.G.has_node(ev_id):
            self.G.add_node(ev_id, type=NodeType.EVENT, name=event_name,
                            contract=contract)
        src = f"fn:{contract}.{function}"
        self.G.add_edge(src, ev_id, type=EdgeType.EMITS)

    # ── Flags ────────────────────────────────────────────────────────────────

    def add_flag(self, node_id: str, flag: str):
        if node_id not in self.flags:
            self.flags[node_id] = []
        if flag not in self.flags[node_id]:
            self.flags[node_id].append(flag)

    def add_global_flag(self, flag: str):
        if "global_flags" not in self.metadata:
            self.metadata["global_flags"] = []
        if flag not in self.metadata["global_flags"]:
            self.metadata["global_flags"].append(flag)

    def get_flags_for(self, node_id: str) -> list[str]:
        return self.flags.get(node_id, [])

    # ── Layer 1: LLM-enriched nodes ─────────────────────────────────────────

    def add_invariant(self, inv_id: str, description: str, *,
                      source: str = "inferred",
                      formal_expr: str = "",
                      related_vars: list[str] | None = None):
        node_id = f"invariant:{inv_id}"
        self.G.add_node(node_id, type=NodeType.INVARIANT, description=description,
                        source=source, formal_expr=formal_expr)
        for var in (related_vars or []):
            var_id = f"var:{var}"
            if self.G.has_node(var_id):
                self.G.add_edge(node_id, var_id, type=EdgeType.DEPENDS_ON)

    def add_trust_boundary(self, name: str, trust_level: str,
                           actors: list[str] | None = None,
                           description: str = ""):
        node_id = f"trust:{name}"
        self.G.add_node(node_id, type=NodeType.TRUST_BOUNDARY, name=name,
                        trust_level=trust_level, actors=actors or [],
                        description=description)

    # ── Queries ──────────────────────────────────────────────────────────────

    def get_entry_points(self) -> list[str]:
        """All external/public functions = attack surface."""
        return [n for n, d in self.G.nodes(data=True)
                if d.get("type") == NodeType.FUNCTION
                and d.get("visibility") in ("external", "public")]

    def get_unrestricted_entry_points(self) -> list[str]:
        """Entry points with NO access control modifiers."""
        return [n for n in self.get_entry_points()
                if not self.G.nodes[n].get("modifiers")]

    def get_external_calls(self) -> list[tuple[str, str, dict]]:
        return [(u, v, d) for u, v, d in self.G.edges(data=True)
                if d.get("type") == EdgeType.EXTERNAL_CALL]

    def get_user_controlled_calls(self) -> list[tuple[str, str, dict]]:
        return [(u, v, d) for u, v, d in self.G.edges(data=True)
                if d.get("type") == EdgeType.EXTERNAL_CALL
                and d.get("data_source") == TAINT_USER_INPUT]

    def get_token_flows(self) -> list[tuple[str, str, dict]]:
        return [(u, v, d) for u, v, d in self.G.edges(data=True)
                if d.get("type") == EdgeType.TOKEN_FLOW]

    def get_writers(self, var_node_id: str) -> list[str]:
        return [u for u, v, d in self.G.edges(data=True)
                if v == var_node_id and d.get("type") == EdgeType.WRITES]

    def get_readers(self, var_node_id: str) -> list[str]:
        return [u for u, v, d in self.G.edges(data=True)
                if v == var_node_id and d.get("type") in (EdgeType.READS, EdgeType.WRITES)]

    def get_path(self, source: str, target: str) -> list[str] | None:
        try:
            return nx.shortest_path(self.G, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def get_nodes_by_type(self, node_type: str | NodeType) -> list[tuple[str, dict]]:
        return [(n, d) for n, d in self.G.nodes(data=True)
                if d.get("type") == node_type]

    def get_functions_for_contract(self, contract_name: str) -> list[tuple[str, dict]]:
        """Get all functions belonging to a contract."""
        prefix = f"fn:{contract_name}."
        return [(n, d) for n, d in self.G.nodes(data=True)
                if n.startswith(prefix) and d.get("type") == NodeType.FUNCTION]

    def get_state_vars_for_contract(self, contract_name: str) -> list[tuple[str, dict]]:
        """Get all state variables belonging to a contract."""
        prefix = f"var:{contract_name}."
        return [(n, d) for n, d in self.G.nodes(data=True)
                if n.startswith(prefix) and d.get("type") == NodeType.STATE_VAR]

    def get_callers(self, fn_node_id: str) -> list[str]:
        """Get all functions that call this function."""
        return [u for u, v, d in self.G.edges(data=True)
                if v == fn_node_id and d.get("type") == EdgeType.CALLS]

    def get_callees(self, fn_node_id: str) -> list[str]:
        """Get all functions called by this function."""
        return [v for u, v, d in self.G.edges(data=True)
                if u == fn_node_id and d.get("type") == EdgeType.CALLS]

    def get_call_chain(self, fn_node_id: str, max_depth: int = 5) -> dict:
        """Get the full call chain from a function, up to max_depth."""
        visited = set()
        chain: dict[str, list[str]] = {}

        def _walk(node: str, depth: int):
            if depth > max_depth or node in visited:
                return
            visited.add(node)
            callees = self.get_callees(node)
            if callees:
                chain[node] = callees
                for callee in callees:
                    _walk(callee, depth + 1)

        _walk(fn_node_id, 0)
        return chain

    def get_state_flow(self, var_node_id: str) -> dict:
        """Get the complete read/write flow for a state variable."""
        writers = self.get_writers(var_node_id)
        readers = [u for u, v, d in self.G.edges(data=True)
                   if v == var_node_id and d.get("type") == EdgeType.READS]
        return {
            "variable": var_node_id,
            "writers": writers,
            "readers": readers,
        }

    # ── Summary ──────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        nodes_by_type: dict[str, int] = {}
        for _, d in self.G.nodes(data=True):
            t = d.get("type", "unknown")
            # Handle both enum and string
            key = t.value if isinstance(t, Enum) else str(t)
            nodes_by_type[key] = nodes_by_type.get(key, 0) + 1

        edges_by_type: dict[str, int] = {}
        for _, _, d in self.G.edges(data=True):
            t = d.get("type", "unknown")
            key = t.value if isinstance(t, Enum) else str(t)
            edges_by_type[key] = edges_by_type.get(key, 0) + 1

        return {
            "total_nodes": self.G.number_of_nodes(),
            "total_edges": self.G.number_of_edges(),
            "nodes_by_type": nodes_by_type,
            "edges_by_type": edges_by_type,
            "entry_points": len(self.get_entry_points()),
            "unrestricted_entry_points": len(self.get_unrestricted_entry_points()),
            "external_calls": len(self.get_external_calls()),
            "user_controlled_calls": len(self.get_user_controlled_calls()),
            "token_flows": len(self.get_token_flows()),
            "global_flags": self.metadata.get("global_flags", []),
            "flagged_nodes": sum(1 for v in self.flags.values() if v),
        }

    # ── Serialization ────────────────────────────────────────────────────────

    def to_json(self, path: str | Path):
        data = {
            "graph": nx.node_link_data(self.G),
            "flags": self.flags,
            "metadata": {k: v for k, v in self.metadata.items()
                         if k not in ("source_files", "rag_pool")},
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    @classmethod
    def from_json(cls, path: str | Path) -> "SecurityGraph":
        with open(path) as f:
            data = json.load(f)
        sg = cls()
        sg.G = nx.node_link_graph(data["graph"])
        sg.flags = data.get("flags", {})
        sg.metadata = data.get("metadata", {})
        return sg

    def to_context_string(self, max_chars: int = 8000) -> str:
        """Compact text for LLM context window."""
        lines = ["# SecurityGraph Context\n"]

        # Contracts (non-interface only)
        contracts = [(n, d) for n, d in self.G.nodes(data=True)
                     if d.get("type") == NodeType.CONTRACT and not d.get("is_interface")]
        lines.append(f"## Contracts ({len(contracts)})")
        for n, d in contracts:
            flags = self.get_flags_for(n)
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            lines.append(f"- {d['name']} ({d.get('sloc', '?')} sloc){flag_str}")

        # Entry points
        entries = self.get_entry_points()
        lines.append(f"\n## Entry Points ({len(entries)})")
        for fn_id in entries[:30]:
            d = self.G.nodes[fn_id]
            mods = d.get("modifiers", [])
            mod_str = f" [{', '.join(mods)}]" if mods else " [UNRESTRICTED]"
            lines.append(f"- {d['contract']}.{d['name']}() {d.get('visibility','')}{mod_str}")
        if len(entries) > 30:
            lines.append(f"  ... and {len(entries) - 30} more")

        # External calls
        ext = self.get_external_calls()
        if ext:
            lines.append(f"\n## External Calls ({len(ext)})")
            for u, v, d in ext:
                src = self.G.nodes.get(u, {})
                tgt = self.G.nodes.get(v, {})
                taint = " USER_INPUT" if d.get("data_source") == TAINT_USER_INPUT else ""
                lines.append(f"- {src.get('contract','')}.{src.get('name','')} -> "
                             f"{tgt.get('target',v)} ({d.get('call_type','')}){taint}")

        # Token flows
        tflows = self.get_token_flows()
        if tflows:
            lines.append(f"\n## Token Flows ({len(tflows)})")
            for u, v, d in tflows:
                src = self.G.nodes.get(u, {})
                lines.append(f"- {src.get('contract','')}.{src.get('name','')} "
                             f"-> {d.get('flow_type','')} {self.G.nodes.get(v, {}).get('name', v)}")

        # Global flags
        gflags = self.metadata.get("global_flags", [])
        if gflags:
            lines.append(f"\n## Detected Patterns")
            for f in gflags:
                lines.append(f"- {f}")

        result = "\n".join(lines)
        if len(result) > max_chars:
            result = result[:max_chars] + "\n... (truncated)"
        return result

    def extract_source_snippets(self) -> dict[str, dict]:
        """Extract source code snippets for each function node.

        Returns: {fn_node_id: {"code": "...", "file": "...", "start": N, "end": N}}
        """
        source_files = self.metadata.get("source_files", {})
        if not source_files:
            return {}

        snippets: dict[str, dict] = {}
        for node_id, data in self.G.nodes(data=True):
            ntype = data.get("type")
            if isinstance(ntype, Enum):
                ntype = ntype.value
            if ntype != "Function":
                continue

            line_start = data.get("line_start", 0)
            line_end = data.get("line_end", 0)
            contract = data.get("contract", "")
            node_file = data.get("file", "")

            if not line_start:
                continue

            # Find the source file
            candidates = (
                [(node_file, source_files[node_file])]
                if node_file and node_file in source_files
                else [(fp, c) for fp, c in source_files.items() if contract in c]
            )

            for file_path, content in candidates:
                lines = content.split("\n")
                start = max(0, line_start - 1)
                end = min(len(lines), line_end if line_end else line_start + 60)
                snippet = "\n".join(lines[start:end])
                snippets[node_id] = {
                    "code": snippet,
                    "file": file_path,
                    "start": line_start,
                    "end": line_end or line_start + len(snippet.split("\n")),
                }
                break

        return snippets

    def to_viz_data(self) -> dict:
        """Export graph data in a format suitable for vis.js visualization."""
        nodes = []
        edges = []

        color_map = {
            NodeType.CONTRACT: {"background": "#4A90D9", "border": "#2C5F8A"},
            NodeType.FUNCTION: {"background": "#7B68EE", "border": "#5B48CE"},
            NodeType.STATE_VAR: {"background": "#50C878", "border": "#30A858"},
            NodeType.MODIFIER: {"background": "#FFD700", "border": "#DAA520"},
            NodeType.EVENT: {"background": "#87CEEB", "border": "#5F9EA0"},
            NodeType.EXTERNAL_TARGET: {"background": "#FF6347", "border": "#CC4433"},
            NodeType.TOKEN: {"background": "#FF8C00", "border": "#CC6600"},
            NodeType.INVARIANT: {"background": "#DDA0DD", "border": "#BA55D3"},
            NodeType.TRUST_BOUNDARY: {"background": "#98FB98", "border": "#66CDAA"},
        }

        shape_map = {
            NodeType.CONTRACT: "box",
            NodeType.FUNCTION: "dot",
            NodeType.STATE_VAR: "diamond",
            NodeType.MODIFIER: "triangle",
            NodeType.EVENT: "star",
            NodeType.EXTERNAL_TARGET: "triangleDown",
            NodeType.TOKEN: "hexagon",
            NodeType.INVARIANT: "ellipse",
            NodeType.TRUST_BOUNDARY: "square",
        }

        for node_id, data in self.G.nodes(data=True):
            ntype = data.get("type", "unknown")
            # Normalize to enum for lookups
            if isinstance(ntype, str):
                try:
                    ntype = NodeType(ntype)
                except ValueError:
                    pass
            flags = self.get_flags_for(node_id)
            label = data.get("name", node_id.split(":")[-1])

            is_dangerous = (
                ntype == NodeType.EXTERNAL_TARGET and data.get("data_source") == TAINT_USER_INPUT
                or ntype == NodeType.FUNCTION and not data.get("modifiers")
                   and data.get("visibility") in ("external", "public")
            )

            node = {
                "id": node_id,
                "label": label,
                "group": ntype.value if isinstance(ntype, Enum) else str(ntype),
                "shape": shape_map.get(ntype, "dot"),
                "color": color_map.get(ntype, {"background": "#999", "border": "#666"}),
                "title": self._node_tooltip(node_id, data, flags),
                "font": {"size": 12},
                "data": self._node_metadata(node_id, data),
            }

            if is_dangerous:
                node["color"] = {"background": "#FF4444", "border": "#CC0000"}
                node["borderWidth"] = 3

            if flags:
                node["borderWidth"] = 2

            nodes.append(node)

        edge_color_map = {
            EdgeType.CALLS: "#666666",
            EdgeType.READS: "#50C878",
            EdgeType.WRITES: "#FF6347",
            EdgeType.GUARDS: "#FFD700",
            EdgeType.INHERITS: "#4A90D9",
            EdgeType.BELONGS_TO: "#CCCCCC",
            EdgeType.EXTERNAL_CALL: "#FF0000",
            EdgeType.TOKEN_FLOW: "#FF8C00",
            EdgeType.EMITS: "#87CEEB",
            EdgeType.DEPENDS_ON: "#DDA0DD",
        }

        for u, v, data in self.G.edges(data=True):
            etype = data.get("type", "")
            if isinstance(etype, str):
                try:
                    etype = EdgeType(etype)
                except ValueError:
                    pass

            edge = {
                "from": u,
                "to": v,
                "label": etype.value if isinstance(etype, Enum) else str(etype),
                "color": {"color": edge_color_map.get(etype, "#999")},
                "arrows": "to",
                "font": {"size": 8, "align": "middle"},
            }
            if etype == EdgeType.EXTERNAL_CALL:
                edge["width"] = 3
                edge["dashes"] = True
            if etype == EdgeType.TOKEN_FLOW:
                edge["width"] = 2

            edges.append(edge)

        return {"nodes": nodes, "edges": edges}

    def _node_metadata(self, node_id: str, data: dict) -> dict:
        """Build structured metadata dict for visualization."""
        meta = {"id": node_id}
        ntype = data.get("type")
        if isinstance(ntype, Enum):
            ntype = ntype.value

        if ntype == "Function":
            meta.update({
                "contract": data.get("contract", ""),
                "visibility": data.get("visibility", ""),
                "mutability": data.get("mutability", ""),
                "modifiers": data.get("modifiers", []),
                "params": data.get("params", ""),
                "file": data.get("file", ""),
                "line_start": data.get("line_start", 0),
                "line_end": data.get("line_end", 0),
                "callers": self.get_callers(node_id),
                "callees": self.get_callees(node_id),
            })
        elif ntype == "Contract":
            meta.update({
                "file": data.get("file", ""),
                "sloc": data.get("sloc", 0),
                "is_interface": data.get("is_interface", False),
                "is_library": data.get("is_library", False),
                "is_abstract": data.get("is_abstract", False),
                "functions": [n for n, _ in self.get_functions_for_contract(data.get("name", ""))],
                "state_vars": [n for n, _ in self.get_state_vars_for_contract(data.get("name", ""))],
            })
        elif ntype == "StateVariable":
            meta.update({
                "contract": data.get("contract", ""),
                "var_type": data.get("var_type", ""),
                "is_constant": data.get("is_constant", False),
                "is_immutable": data.get("is_immutable", False),
                "writers": self.get_writers(node_id),
                "readers": [u for u, v, d in self.G.edges(data=True)
                           if v == node_id and d.get("type") == EdgeType.READS],
            })
        elif ntype == "ExternalTarget":
            meta.update({
                "target": data.get("target", ""),
                "data_source": data.get("data_source", ""),
                "line": data.get("line", 0),
            })

        meta["flags"] = self.get_flags_for(node_id)
        return meta

    def _node_tooltip(self, node_id: str, data: dict, flags: list[str]) -> str:
        """Build HTML tooltip for vis.js node hover — XSS safe."""
        parts = [f"<b>{html_escape(node_id)}</b>"]
        for k, v in data.items():
            if k != "type" and v:
                parts.append(f"{html_escape(str(k))}: {html_escape(str(v))}")
        if flags:
            parts.append(f"<b>Flags:</b> {html_escape(', '.join(flags))}")
        return "<br>".join(parts)
