"""
avadhi/viz/export.py — Export SecurityGraph to interactive HTML.

A full-featured auditor workstation:
  - Click any function node -> see actual Solidity source with syntax highlighting
  - Contract clustering with visual grouping
  - Call chain tracing with code context
  - State variable read/write flow
  - Resizable code panel
  - Hypothesis findings overlay with severity badges
  - Keyboard-driven navigation
"""
from __future__ import annotations

import json
from html import escape as html_escape
from pathlib import Path

from avadhi.core.graph import SecurityGraph


def _safe_json(data) -> str:
    """JSON encode with XSS-safe escaping."""
    return json.dumps(data, default=str).replace("</", "<\\/")


def _build_hypothesis_map(hypotheses: list | None) -> dict:
    """Map node IDs to hypothesis findings for overlay."""
    if not hypotheses:
        return {}
    hmap: dict[str, list[dict]] = {}
    for h in hypotheses:
        loc = getattr(h, "location", "") or ""
        # Location is typically "Contract.function" — map to fn:Contract.function
        parts = loc.split(".")
        if len(parts) >= 2:
            fn_id = f"fn:{loc}"
            contract_id = f"contract:{parts[0]}"
        else:
            fn_id = ""
            contract_id = f"contract:{loc}" if loc else ""

        sev = getattr(h, "severity", "")
        if hasattr(sev, "value"):
            sev = sev.value

        entry = {
            "id": getattr(h, "id", ""),
            "title": getattr(h, "title", ""),
            "severity": str(sev),
            "category": getattr(h, "category", ""),
            "description": (getattr(h, "description", "") or "")[:200],
        }

        for nid in [fn_id, contract_id]:
            if nid:
                hmap.setdefault(nid, [])
                hmap[nid].append(entry)

    return hmap


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>Avadhi Security Graph</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css"/>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-solidity.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-numbers/prism-line-numbers.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-numbers/prism-line-numbers.min.css"/>
    <style>
        :root {
            --bg-primary: #0a0e14;
            --bg-secondary: #11151c;
            --bg-tertiary: #1a1f2b;
            --bg-hover: #232a38;
            --border: #2a3040;
            --border-focus: #58a6ff;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #484f58;
            --accent: #7B68EE;
            --accent-dim: #7B68EE25;
            --accent-glow: #7B68EE40;
            --danger: #ff4757;
            --warning: #ffa502;
            --success: #2ed573;
            --info: #58a6ff;
            --critical: #ff2d55;
            --high: #ff6348;
            --medium: #ffa502;
            --low: #2ed573;
            --code-bg: #0a0e14;
            --glass: rgba(17, 21, 28, 0.88);
            --glass-border: rgba(42, 48, 64, 0.6);
            --glow-danger: 0 0 12px rgba(255, 71, 87, 0.4);
            --glow-accent: 0 0 12px rgba(123, 104, 238, 0.3);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            overflow: hidden;
            font-size: 13px;
        }
        #app { display: flex; height: 100vh; }

        /* ---- Scrollbar ---- */
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

        /* ---- Left Sidebar ---- */
        #sidebar {
            width: 320px; min-width: 320px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            display: flex; flex-direction: column;
            z-index: 20;
        }
        .sidebar-header {
            padding: 16px 18px;
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center; gap: 12px;
            background: linear-gradient(135deg, #11151c 0%, #151a26 100%);
        }
        .sidebar-header .logo {
            width: 32px; height: 32px;
            background: linear-gradient(135deg, var(--accent), #a855f7);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 15px; font-weight: 800; color: white;
            box-shadow: 0 2px 12px rgba(123, 104, 238, 0.35);
        }
        .sidebar-header h1 { font-size: 15px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.3px; }
        .sidebar-header h1 span { color: var(--accent); }
        .sidebar-header .version { font-size: 9px; color: var(--text-muted); margin-left: auto; letter-spacing: 0.5px; }

        .search-wrap { padding: 10px 14px; border-bottom: 1px solid var(--border); }
        #search {
            width: 100%; padding: 8px 12px 8px 32px;
            background: var(--bg-primary); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text-primary);
            font-size: 12px; font-family: inherit;
            transition: all 0.15s;
        }
        #search:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }
        .search-wrap { position: relative; }
        .search-wrap::before {
            content: '\1F50D'; position: absolute; left: 24px; top: 50%; transform: translateY(-50%);
            font-size: 11px; pointer-events: none;
        }

        .tab-bar { display: flex; border-bottom: 1px solid var(--border); }
        .tab {
            flex: 1; padding: 8px 4px; text-align: center;
            font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.7px;
            color: var(--text-muted); cursor: pointer;
            border-bottom: 2px solid transparent; transition: all 0.15s;
        }
        .tab:hover { color: var(--text-secondary); background: var(--bg-tertiary); }
        .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

        .tab-content { flex: 1; overflow-y: auto; display: none; }
        .tab-content.active { display: block; }

        /* Stats */
        .stats { padding: 12px 16px; }
        .stat-row {
            display: flex; justify-content: space-between; padding: 4px 0;
            font-size: 12px;
        }
        .stat-row .label { color: var(--text-secondary); }
        .stat-row .value {
            font-weight: 600; font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
            font-size: 11px;
        }
        .stat-row .value.danger { color: var(--danger); }
        .stat-row .value.warn { color: var(--warning); }
        .stat-divider {
            font-size: 9px; text-transform: uppercase; letter-spacing: 1px;
            color: var(--text-muted); padding: 8px 0 4px;
            border-top: 1px solid var(--border); margin-top: 8px;
        }

        /* Contracts clickable list */
        .contract-item {
            display: flex; justify-content: space-between; align-items: center;
            padding: 8px 16px; cursor: pointer; transition: all 0.12s;
            border-bottom: 1px solid var(--border);
        }
        .contract-item:hover { background: var(--bg-hover); padding-left: 20px; }
        .contract-item .cname { color: var(--info); font-weight: 600; font-size: 12px; }
        .contract-item .cmeta { color: var(--text-muted); font-size: 10px; font-family: monospace; }

        /* Findings summary */
        .findings-banner {
            margin: 8px 14px; padding: 8px 12px;
            background: linear-gradient(135deg, rgba(255,45,85,0.08), rgba(255,99,72,0.08));
            border: 1px solid rgba(255,71,87,0.2);
            border-radius: 8px; font-size: 11px;
        }
        .findings-banner .fb-title { font-weight: 700; color: var(--danger); font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
        .sev-row { display: flex; gap: 6px; flex-wrap: wrap; }
        .sev-badge {
            display: inline-flex; align-items: center; gap: 3px;
            padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700;
        }
        .sev-critical { background: rgba(255,45,85,0.15); color: #ff2d55; border: 1px solid rgba(255,45,85,0.3); }
        .sev-high { background: rgba(255,99,72,0.15); color: #ff6348; border: 1px solid rgba(255,99,72,0.3); }
        .sev-medium { background: rgba(255,165,2,0.12); color: #ffa502; border: 1px solid rgba(255,165,2,0.3); }
        .sev-low { background: rgba(46,213,115,0.12); color: #2ed573; border: 1px solid rgba(46,213,115,0.3); }
        .sev-info { background: rgba(88,166,255,0.12); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }

        /* Filters */
        .filters { padding: 12px 16px; }
        .filter-section { margin-bottom: 12px; }
        .filter-section h4 {
            font-size: 9px; text-transform: uppercase; letter-spacing: 0.7px;
            color: var(--text-muted); margin-bottom: 6px;
        }
        .fbtn {
            display: inline-block; padding: 3px 8px; margin: 2px;
            border-radius: 12px; border: 1px solid var(--border);
            background: transparent; color: var(--text-secondary);
            font-family: inherit; font-size: 10px; cursor: pointer; transition: all 0.12s;
        }
        .fbtn:hover { background: var(--bg-tertiary); border-color: var(--text-muted); }
        .fbtn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
        .fbtn.qf { background: var(--bg-tertiary); border-color: var(--border); color: var(--text-secondary); }
        .fbtn.qf:hover { border-color: var(--accent); color: var(--accent); }

        /* Inspector panel */
        #details { padding: 14px; }
        .det-header { font-size: 14px; font-weight: 700; color: var(--accent); word-break: break-all; }
        .det-type {
            font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px;
            color: var(--text-muted); margin: 3px 0 12px;
            display: flex; align-items: center; gap: 6px;
        }
        .det-section { margin-bottom: 12px; }
        .det-section h5 {
            font-size: 9px; text-transform: uppercase; letter-spacing: 0.7px;
            color: var(--text-muted); margin-bottom: 4px;
            padding-bottom: 3px; border-bottom: 1px solid var(--border);
        }
        .det-row { font-size: 12px; padding: 3px 0; display: flex; gap: 8px; }
        .det-row .dk { color: var(--text-muted); min-width: 72px; font-size: 11px; }
        .det-row .dv { color: var(--text-primary); word-break: break-all; }
        .tag {
            display: inline-block; padding: 1px 6px; margin: 1px;
            border-radius: 4px; font-size: 10px; font-weight: 600;
        }
        .tag-flag { background: rgba(255,71,87,0.1); color: var(--danger); border: 1px solid rgba(255,71,87,0.25); }
        .tag-mod { background: rgba(255,165,2,0.1); color: var(--warning); border: 1px solid rgba(255,165,2,0.25); }
        .tag-vis { background: rgba(88,166,255,0.1); color: var(--info); border: 1px solid rgba(88,166,255,0.25); }
        .tag-unr { background: rgba(255,71,87,0.15); color: var(--danger); border: 1px solid rgba(255,71,87,0.35); animation: pulse 2s ease-in-out infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }

        .finding-card {
            background: rgba(255,71,87,0.06); border: 1px solid rgba(255,71,87,0.15);
            border-radius: 6px; padding: 6px 8px; margin: 3px 0; font-size: 11px;
            cursor: pointer; transition: all 0.12s;
        }
        .finding-card:hover { background: rgba(255,71,87,0.12); border-color: rgba(255,71,87,0.3); }
        .finding-card .fc-sev { font-weight: 700; font-size: 9px; text-transform: uppercase; letter-spacing: 0.3px; }
        .finding-card .fc-title { color: var(--text-primary); margin-top: 2px; }
        .finding-card .fc-cat { color: var(--text-muted); font-size: 10px; }

        .conn-item {
            display: flex; align-items: center; gap: 6px;
            padding: 3px 0; font-size: 11px; cursor: pointer; color: var(--text-secondary);
            transition: color 0.1s;
        }
        .conn-item:hover { color: var(--accent); }
        .conn-item .etype {
            font-size: 8px; padding: 1px 5px; border-radius: 3px;
            background: var(--bg-tertiary); color: var(--text-muted); font-weight: 600;
        }

        .trace-btn {
            margin-top: 8px; padding: 7px 14px;
            background: linear-gradient(135deg, var(--accent), #a855f7);
            color: white; border: none; border-radius: 8px;
            font-family: inherit; font-size: 11px; cursor: pointer; width: 100%;
            font-weight: 600; letter-spacing: 0.3px;
            box-shadow: 0 2px 8px rgba(123,104,238,0.3);
            transition: all 0.15s;
        }
        .trace-btn:hover { opacity: 0.9; box-shadow: 0 4px 16px rgba(123,104,238,0.4); transform: translateY(-1px); }
        .view-code-btn {
            margin-top: 4px; padding: 6px 14px;
            background: var(--bg-tertiary); color: var(--info);
            border: 1px solid var(--border); border-radius: 8px;
            font-family: inherit; font-size: 11px; cursor: pointer; width: 100%;
            font-weight: 600; transition: all 0.12s;
        }
        .view-code-btn:hover { background: var(--bg-hover); border-color: var(--info); }

        /* ---- Graph container ---- */
        #graph-area { flex: 1; display: flex; flex-direction: column; position: relative; min-width: 0; }
        #graph-container {
            flex: 1 1 auto; position: relative; min-height: 200px; width: 100%; height: 100%;
            background: radial-gradient(ellipse at center, #0f1420 0%, #0a0e14 100%);
        }

        /* Toolbar */
        #toolbar {
            position: absolute; top: 12px; right: 12px;
            display: flex; gap: 4px; z-index: 10;
        }
        .tb {
            padding: 6px 11px; background: var(--glass); backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border); border-radius: 8px;
            color: var(--text-secondary); font-family: inherit; font-size: 10px;
            cursor: pointer; transition: all 0.15s; font-weight: 500;
        }
        .tb:hover { background: var(--bg-tertiary); color: var(--text-primary); border-color: var(--text-muted); }
        .tb.active { background: var(--accent); border-color: var(--accent); color: white; box-shadow: var(--glow-accent); }

        /* Breadcrumb */
        #breadcrumb {
            position: absolute; top: 12px; left: 12px;
            background: var(--glass); backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border); border-radius: 8px;
            padding: 6px 14px; font-size: 11px; color: var(--text-secondary); z-index: 10;
            max-width: 50%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
            display: none;
        }
        #breadcrumb span { color: var(--accent); cursor: pointer; font-weight: 600; }
        #breadcrumb span:hover { text-decoration: underline; }

        /* Legend */
        #legend {
            position: absolute; bottom: 36px; left: 12px;
            background: var(--glass); backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border); border-radius: 10px;
            padding: 10px 14px; font-size: 10px; z-index: 10;
            max-height: 240px; overflow-y: auto;
        }
        .leg-title { font-size: 8px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 4px; font-weight: 600; }
        .leg-item { display: flex; align-items: center; gap: 6px; padding: 2px 0; color: var(--text-secondary); }
        .leg-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        .leg-line { width: 14px; height: 2px; display: inline-block; border-radius: 1px; }

        /* ---- Code Panel (bottom) ---- */
        #code-panel {
            height: 0; min-height: 0;
            background: var(--bg-secondary);
            border-top: 2px solid var(--accent);
            display: flex; flex-direction: column;
            transition: height 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            overflow: hidden;
        }
        #code-panel.open { height: 320px; }
        #code-panel-header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 8px 16px; background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border); cursor: ns-resize; flex-shrink: 0;
        }
        #code-panel-header .title {
            font-size: 12px; font-weight: 600; color: var(--text-primary);
            display: flex; align-items: center; gap: 10px;
        }
        #code-panel-header .title .file-path { color: var(--text-muted); font-weight: 400; font-size: 10px; }
        #code-panel-header .title .line-badge {
            background: linear-gradient(135deg, var(--accent), #a855f7);
            color: white; font-size: 9px;
            padding: 2px 8px; border-radius: 10px; font-weight: 700;
        }
        .code-close {
            background: none; border: none; color: var(--text-muted);
            font-size: 18px; cursor: pointer; padding: 2px 8px; border-radius: 6px;
            transition: all 0.12s;
        }
        .code-close:hover { background: var(--bg-hover); color: var(--text-primary); }
        #code-body {
            flex: 1; overflow: auto; padding: 0;
        }
        #code-body pre {
            margin: 0; padding: 14px 18px; font-size: 12.5px; line-height: 1.7;
            background: var(--code-bg) !important;
        }
        #code-body code {
            font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
            font-size: 12.5px;
        }
        /* Override Prism line numbers */
        .line-numbers .line-numbers-rows { border-right: 1px solid var(--border) !important; }
        .line-numbers .line-numbers-rows > span::before { color: var(--text-muted) !important; }

        /* Resize handle */
        #resize-handle {
            height: 5px; background: transparent; cursor: ns-resize;
            position: absolute; left: 320px; right: 0; z-index: 30;
        }

        /* Minimap */
        #minimap {
            position: absolute; bottom: 36px; right: 12px;
            width: 150px; height: 90px;
            background: var(--glass); backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border); border-radius: 8px;
            z-index: 10; overflow: hidden;
        }

        /* Status bar */
        #statusbar {
            position: absolute; bottom: 0; left: 0; right: 0;
            height: 24px; background: var(--bg-tertiary);
            border-top: 1px solid var(--border);
            display: flex; align-items: center; padding: 0 14px;
            font-size: 10px; color: var(--text-muted); gap: 14px; z-index: 15;
        }
        #statusbar .sep { color: var(--border); }
        #statusbar .kbd {
            background: var(--bg-primary); padding: 1px 5px; border-radius: 3px;
            font-size: 9px; font-family: monospace; border: 1px solid var(--border);
        }

        /* ---- Animated glow for findings ---- */
        @keyframes glow-pulse {
            0%, 100% { box-shadow: 0 0 6px rgba(255,71,87,0.3); }
            50% { box-shadow: 0 0 16px rgba(255,71,87,0.6); }
        }
    </style>
</head>
<body>
<div id="app">
<div id="sidebar">
    <div class="sidebar-header">
        <div class="logo">A</div>
        <h1>Avadhi <span>Graph</span></h1>
        <span class="version">v2</span>
    </div>
    <div class="search-wrap">
        <input type="text" id="search" placeholder="  Search nodes... (/ to focus)" />
    </div>
    <div class="tab-bar">
        <div class="tab active" data-tab="overview">Overview</div>
        <div class="tab" data-tab="filters">Filters</div>
        <div class="tab" data-tab="findings">Findings</div>
        <div class="tab" data-tab="details">Inspector</div>
    </div>
    <div class="tab-content active" id="tab-overview">
        <div class="stats" id="stats"></div>
        <div id="findings-banner"></div>
        <div id="contracts-list"></div>
    </div>
    <div class="tab-content" id="tab-filters">
        <div class="filters">
            <div class="filter-section"><h4>Node Types</h4><div id="type-filters"></div></div>
            <div class="filter-section"><h4>Edge Types</h4><div id="edge-filters"></div></div>
            <div class="filter-section"><h4>Contracts</h4><div id="contract-filters"></div></div>
            <div class="filter-section">
                <h4>Quick Filters</h4>
                <button class="fbtn qf" id="qf-entry">Entry Points</button>
                <button class="fbtn qf" id="qf-unr">Unrestricted</button>
                <button class="fbtn qf" id="qf-ext">External Calls</button>
                <button class="fbtn qf" id="qf-flag">Flagged</button>
                <button class="fbtn qf" id="qf-findings">With Findings</button>
                <button class="fbtn qf" id="qf-reset" style="color:var(--danger)">Reset All</button>
            </div>
        </div>
    </div>
    <div class="tab-content" id="tab-findings">
        <div id="findings-list" style="padding:10px 14px"></div>
    </div>
    <div class="tab-content" id="tab-details">
        <div id="details"><p style="color:var(--text-muted);padding:14px;font-size:12px;">Click a node to inspect.<br><span style="font-size:10px;color:var(--text-muted)">Or press Tab to cycle nodes.</span></p></div>
    </div>
</div>
<div id="graph-area">
    <div id="graph-container">
        <div id="breadcrumb"></div>
        <div id="toolbar">
            <button class="tb" id="btn-fit" title="Fit (F)">Fit</button>
            <button class="tb" id="btn-physics" title="Physics (P)">Physics</button>
            <button class="tb" id="btn-labels" title="Edge Labels (L)">Labels</button>
            <button class="tb" id="btn-hier" title="Hierarchy (H)">Hierarchy</button>
            <button class="tb" id="btn-cluster" title="Cluster by Contract (C)">Cluster</button>
            <button class="tb" id="btn-png" title="Export PNG">PNG</button>
        </div>
        <div id="legend"></div>
        <div id="minimap"></div>
    </div>
    <div id="resize-handle"></div>
    <div id="code-panel">
        <div id="code-panel-header">
            <div class="title">
                <span id="code-fn-name">No function selected</span>
                <span class="file-path" id="code-file-path"></span>
                <span class="line-badge" id="code-line-badge" style="display:none"></span>
            </div>
            <button class="code-close" id="code-close" title="Close (Esc)">&times;</button>
        </div>
        <div id="code-body"><pre class="line-numbers"><code class="language-solidity" id="code-content">// Click a function node to view its source code</code></pre></div>
    </div>
</div>
</div>
<div id="statusbar">
    <span id="st-nodes"></span><span class="sep">|</span>
    <span id="st-edges"></span><span class="sep">|</span>
    <span id="st-sel"></span>
    <span style="margin-left:auto"><span class="kbd">/</span> Search &nbsp;<span class="kbd">F</span> Fit &nbsp;<span class="kbd">C</span> Cluster &nbsp;<span class="kbd">P</span> Physics &nbsp;<span class="kbd">Esc</span> Reset</span>
</div>

<script>
// ===== DATA =====
const G = __GRAPH_DATA__;
const S = __SUMMARY_DATA__;
const FL = __FLAGS_DATA__;
const SRC = __SOURCE_DATA__;
const HYP = __HYPO_DATA__;

function esc(s){ const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }
function escAttr(s){ return String(s).replace(/'/g,"&#39;").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

// ===== SEVERITY HELPERS =====
const SEV_ORDER = {Critical:0,High:1,Medium:2,Low:3,Info:4};
const SEV_COLORS = {Critical:'#ff2d55',High:'#ff6348',Medium:'#ffa502',Low:'#2ed573',Info:'#58a6ff'};
function sevClass(s){ return 'sev-'+(s||'info').toLowerCase(); }

// ===== STATS =====
document.getElementById('stats').innerHTML = `
<div class="stat-row"><span class="label">Nodes</span><span class="value">${S.total_nodes}</span></div>
<div class="stat-row"><span class="label">Edges</span><span class="value">${S.total_edges}</span></div>
<div class="stat-divider">Attack Surface</div>
<div class="stat-row"><span class="label">Entry Points</span><span class="value">${S.entry_points}</span></div>
<div class="stat-row"><span class="label">Unrestricted</span><span class="value ${S.unrestricted_entry_points>0?'warn':''}">${S.unrestricted_entry_points}</span></div>
<div class="stat-row"><span class="label">External Calls</span><span class="value">${S.external_calls}</span></div>
<div class="stat-row"><span class="label">User-Controlled</span><span class="value ${S.user_controlled_calls>0?'danger':''}">${S.user_controlled_calls}</span></div>
<div class="stat-row"><span class="label">Token Flows</span><span class="value">${S.token_flows}</span></div>
${S.global_flags&&S.global_flags.length?`<div class="stat-divider">Patterns</div>${S.global_flags.map(f=>`<div class="stat-row"><span class="label">${esc(f)}</span><span class="value"><span class="tag tag-flag">!</span></span></div>`).join('')}`:''}
`;

// ===== FINDINGS BANNER + LIST =====
(function(){
    const allFindings = [];
    Object.values(HYP).forEach(arr=>arr.forEach(h=>{if(!allFindings.find(f=>f.id===h.id))allFindings.push(h);}));
    if(!allFindings.length){
        document.getElementById('findings-banner').innerHTML='';
        document.getElementById('findings-list').innerHTML='<p style="color:var(--text-muted)">No findings. Run a hunt to generate vulnerability hypotheses.</p>';
        return;
    }
    // Count by severity
    const sc={};allFindings.forEach(h=>{sc[h.severity]=(sc[h.severity]||0)+1;});
    let bh='<div class="findings-banner"><div class="fb-title">'+allFindings.length+' Findings</div><div class="sev-row">';
    ['Critical','High','Medium','Low','Info'].forEach(s=>{if(sc[s])bh+=`<span class="sev-badge ${sevClass(s)}">${sc[s]} ${s}</span>`;});
    bh+='</div></div>';
    document.getElementById('findings-banner').innerHTML=bh;

    // Findings list
    allFindings.sort((a,b)=>(SEV_ORDER[a.severity]||5)-(SEV_ORDER[b.severity]||5));
    let fl='';
    allFindings.forEach(h=>{
        const col=SEV_COLORS[h.severity]||'#888';
        // Find a matching node to focus on
        const nid=Object.keys(HYP).find(k=>HYP[k].some(x=>x.id===h.id))||'';
        fl+=`<div class="finding-card" onclick="if('${escAttr(nid)}')focusNode('${escAttr(nid)}')">
            <div class="fc-sev" style="color:${col}">${esc(h.severity)}</div>
            <div class="fc-title">${esc(h.title)}</div>
            <div class="fc-cat">${esc(h.category)}</div>
        </div>`;
    });
    document.getElementById('findings-list').innerHTML=fl;
})();

// ===== CONTRACTS LIST =====
const contracts = G.nodes.filter(n=>n.group==='Contract'&&n.data&&!n.data.is_interface);
const clEl = document.getElementById('contracts-list');
clEl.innerHTML = contracts.map(c => {
    const fn=(c.data.functions||[]).length, vr=(c.data.state_vars||[]).length;
    const nh=Object.keys(HYP).filter(k=>k.startsWith('fn:'+c.label+'.')).reduce((s,k)=>s+HYP[k].length,0);
    return `<div class="contract-item" onclick="focusNode('${escAttr(c.id)}')">
        <span class="cname">${esc(c.label)}${nh?` <span class="sev-badge sev-high" style="font-size:8px;padding:0 5px">${nh}</span>`:''}</span>
        <span class="cmeta">${fn}fn ${vr}var ${c.data.sloc||'?'}sloc</span>
    </div>`;
}).join('');

// ===== COLORS =====
const TC = {Contract:'#4A90D9',Function:'#7B68EE',StateVariable:'#50C878',Modifier:'#FFD700',Event:'#87CEEB',ExternalTarget:'#FF6347',Token:'#FF8C00',Invariant:'#DDA0DD',TrustBoundary:'#98FB98'};
const EC = {CALLS:'#666',READS:'#50C878',WRITES:'#FF6347',GUARDED_BY:'#FFD700',INHERITS:'#4A90D9',BELONGS_TO:'#333',EXTERNAL_CALL:'#FF4444',TOKEN_FLOW:'#FF8C00',EMITS:'#87CEEB',DEPENDS_ON:'#DDA0DD'};

// ===== LEGEND =====
let lh='<div class="leg-title">Nodes</div>';
Object.entries(TC).forEach(([t,c])=>{lh+=`<div class="leg-item"><span class="leg-dot" style="background:${c}"></span>${esc(t)}</div>`;});
lh+='<div class="leg-title" style="margin-top:8px">Edges</div>';
Object.entries(EC).forEach(([t,c])=>{if(t!=='BELONGS_TO')lh+=`<div class="leg-item"><span class="leg-line" style="background:${c}"></span>${esc(t)}</div>`;});
document.getElementById('legend').innerHTML=lh;

// ===== FILTERS =====
const nTypes=[...new Set(G.nodes.map(n=>n.group))];
const eTypes=[...new Set(G.edges.map(e=>e.label))];
const cNames=contracts.map(c=>c.label);
const aN=new Set(nTypes), aE=new Set(eTypes), aC=new Set(cNames);

function mkFilters(id,items,active,cls){
    const el=document.getElementById(id);
    items.forEach(t=>{const b=document.createElement('button');b.className='fbtn '+(cls||'')+' active';b.textContent=t;
    b.onclick=()=>{b.classList.toggle('active');if(active.has(t))active.delete(t);else active.add(t);applyFilters();};el.appendChild(b);});
}
mkFilters('type-filters',nTypes,aN);
mkFilters('edge-filters',eTypes,aE);
mkFilters('contract-filters',cNames,aC);

let qf=null;
function setQF(m){if(qf===m){qf=null;}else{qf=m;}applyFilters();}
document.getElementById('qf-entry').onclick=()=>setQF('entry');
document.getElementById('qf-unr').onclick=()=>setQF('unr');
document.getElementById('qf-ext').onclick=()=>setQF('ext');
document.getElementById('qf-flag').onclick=()=>setQF('flag');
document.getElementById('qf-findings').onclick=()=>setQF('findings');
document.getElementById('qf-reset').onclick=()=>{qf=null;aN.clear();nTypes.forEach(t=>aN.add(t));aE.clear();eTypes.forEach(t=>aE.add(t));aC.clear();cNames.forEach(t=>aC.add(t));document.querySelectorAll('.fbtn').forEach(b=>b.classList.add('active'));applyFilters();};

// ===== VIS.JS =====
// Enhance node sizing based on connectivity and findings
G.nodes.forEach(n=>{
    const findings=HYP[n.id]||[];
    if(findings.length>0){
        // Add red glow to nodes with findings
        const worst=findings.reduce((a,b)=>(SEV_ORDER[a.severity]||5)<(SEV_ORDER[b.severity]||5)?a:b);
        const col=SEV_COLORS[worst.severity]||'#ff4757';
        n.color={background:col+'30',border:col,highlight:{background:col+'50',border:col}};
        n.borderWidth=3;
        n.shadow={enabled:true,size:10,x:0,y:0,color:col+'40'};
    }
    // Scale function nodes by connectivity
    if(n.group==='Function'){
        const conns=G.edges.filter(e=>e.from===n.id||e.to===n.id).length;
        n.size=Math.max(8,Math.min(20,6+conns*1.5));
    }
    // Scale contract nodes by SLOC
    if(n.group==='Contract'&&n.data){
        const s=n.data.sloc||100;
        n.font={...n.font,size:Math.max(11,Math.min(16,10+Math.sqrt(s)*0.3))};
    }
});

const nodes=new vis.DataSet(G.nodes);
const edges=new vis.DataSet(G.edges.map((e,i)=>({...e,id:'e'+i})));
const container=document.getElementById('graph-container');
let physOn=true,labelsOn=true,hierOn=false;

const net=new vis.Network(container,{nodes,edges},{
    physics:{enabled:true,solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:-50,centralGravity:0.006,springLength:160,springConstant:0.035,damping:0.45,avoidOverlap:0.4},stabilization:{iterations:250,fit:true}},
    interaction:{hover:true,tooltipDelay:200,multiselect:true,keyboard:{enabled:true},navigationButtons:false,zoomSpeed:0.7},
    nodes:{font:{color:'#e6edf3',size:11,face:"'Inter',-apple-system,sans-serif"},borderWidth:1.5,shadow:{enabled:true,size:4,x:0,y:2,color:'rgba(0,0,0,0.3)'}},
    edges:{font:{color:'#484f58',size:7,face:'monospace',strokeWidth:0},smooth:{type:'cubicBezier',roundness:0.35},hoverWidth:2,selectionWidth:2},
});

// Minimap
const mm=new vis.Network(document.getElementById('minimap'),{nodes,edges},{
    physics:false,interaction:{dragNodes:false,dragView:false,zoomView:false,selectable:false},
    nodes:{font:{size:0},borderWidth:0,size:2},edges:{width:0.3,font:{size:0},smooth:false}
});
net.on('afterDrawing',()=>{try{mm.fit();}catch(e){}});

// ===== FILTERS =====
function applyFilters(){
    nodes.update(G.nodes.map(n=>{
        let v=aN.has(n.group);
        if(v&&n.data&&n.data.contract)v=aC.has(n.data.contract);
        if(v&&qf){
            if(qf==='entry')v=n.group==='Function'&&['external','public'].includes(n.data?.visibility);
            else if(qf==='unr')v=n.group==='Function'&&['external','public'].includes(n.data?.visibility)&&(!n.data?.modifiers||n.data.modifiers.length===0);
            else if(qf==='ext')v=n.group==='ExternalTarget'||G.edges.some(e=>e.label==='EXTERNAL_CALL'&&e.from===n.id);
            else if(qf==='flag')v=(FL[n.id]||[]).length>0;
            else if(qf==='findings')v=(HYP[n.id]||[]).length>0||G.nodes.some(nn=>nn.data?.contract===n.label&&(HYP[nn.id]||[]).length>0);
        }
        return {id:n.id,hidden:!v};
    }));
    edges.update(G.edges.map((e,i)=>({id:'e'+i,hidden:!aE.has(e.label)})));
    updStatus();
}
function updStatus(){
    const vn=G.nodes.filter(n=>!nodes.get(n.id)?.hidden).length;
    const ve=G.edges.filter((_,i)=>!edges.get('e'+i)?.hidden).length;
    document.getElementById('st-nodes').textContent=`Nodes: ${vn}/${G.nodes.length}`;
    document.getElementById('st-edges').textContent=`Edges: ${ve}/${G.edges.length}`;
}
updStatus();

// ===== SEARCH =====
document.getElementById('search').addEventListener('input',e=>{
    const q=e.target.value.toLowerCase().trim();
    if(!q){applyFilters();return;}
    const m=G.nodes.filter(n=>n.id.toLowerCase().includes(q)||n.label.toLowerCase().includes(q)||(n.data?.contract||'').toLowerCase().includes(q)||(n.data?.params||'').toLowerCase().includes(q)).map(n=>n.id);
    nodes.update(G.nodes.map(n=>({id:n.id,hidden:!m.includes(n.id)})));
    if(m.length===1){net.focus(m[0],{scale:1.5,animation:{duration:300}});net.selectNodes(m);showDetails(m[0],false);}
    updStatus();
});

// ===== TABS =====
document.querySelectorAll('.tab').forEach(tab=>{
    tab.onclick=()=>{document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));tab.classList.add('active');document.getElementById('tab-'+tab.dataset.tab).classList.add('active');};
});

// ===== TOOLBAR =====
document.getElementById('btn-fit').onclick=()=>net.fit({animation:{duration:400}});
document.getElementById('btn-physics').onclick=function(){physOn=!physOn;net.setOptions({physics:{enabled:physOn}});this.classList.toggle('active',physOn);};
document.getElementById('btn-labels').onclick=function(){labelsOn=!labelsOn;edges.update(G.edges.map((e,i)=>({id:'e'+i,font:{size:labelsOn?7:0}})));this.classList.toggle('active',labelsOn);};
document.getElementById('btn-hier').onclick=function(){hierOn=!hierOn;if(hierOn)net.setOptions({layout:{hierarchical:{direction:'UD',sortMethod:'hubsize',nodeSpacing:130,levelSeparation:110}},physics:{enabled:false}});else net.setOptions({layout:{hierarchical:false},physics:{enabled:physOn}});this.classList.toggle('active',hierOn);};
document.getElementById('btn-png').onclick=()=>{const c=container.querySelector('canvas');if(c){const a=document.createElement('a');a.download='avadhi-graph.png';a.href=c.toDataURL('image/png');a.click();}};

// ===== CLUSTERING =====
let clustered=false;
document.getElementById('btn-cluster').onclick=function(){
    if(clustered){net.setData({nodes,edges});clustered=false;this.classList.remove('active');return;}
    const cMap={};
    G.nodes.forEach(n=>{if(n.data&&n.data.contract){const c=n.data.contract;if(!cMap[c])cMap[c]=[];cMap[c].push(n.id);}});
    Object.entries(cMap).forEach(([cname,nids])=>{
        if(nids.length<2)return;
        const col=TC.Contract;
        const nh=nids.reduce((s,id)=>s+(HYP[id]||[]).length,0);
        net.cluster({joinCondition:(opt)=>nids.includes(opt.id),
            clusterNodeProperties:{label:cname+' ('+nids.length+')'+(nh?' ['+nh+' findings]':''),shape:'box',
                color:{background:nh?'#ff474720':col+'20',border:nh?'#ff4757':col},
                font:{size:14,color:'#fff',bold:true},
                borderWidth:nh?3:2,margin:12,
                shadow:nh?{enabled:true,size:8,color:'rgba(255,71,87,0.3)'}:{enabled:false}}});
    });
    clustered=true;this.classList.add('active');
};

// ===== NODE CLICK =====
function focusNode(id){net.focus(id,{scale:1.5,animation:{duration:400,easingFunction:'easeInOutQuad'}});net.selectNodes([id]);showDetails(id,false);}

net.on('click',p=>{if(p.nodes.length>0)showDetails(p.nodes[0],true);});

// ===== CODE PANEL =====
function openCode(nodeId){
    const src=SRC[nodeId];
    if(!src||!src.code){return;}
    const node=nodes.get(nodeId);
    const panel=document.getElementById('code-panel');
    panel.classList.add('open');
    document.getElementById('code-fn-name').textContent=(node?.data?.contract||'')+'.'+esc(node?.label||'');
    const fp=src.file||'';
    const short=fp.split('/').slice(-2).join('/');
    document.getElementById('code-file-path').textContent=short;
    const lb=document.getElementById('code-line-badge');
    lb.style.display='inline';
    lb.textContent='L'+src.start+(src.end?'-'+src.end:'');

    const codeEl=document.getElementById('code-content');
    codeEl.textContent=src.code;
    codeEl.className='language-solidity';
    Prism.highlightElement(codeEl);

    const pre=codeEl.parentElement;
    pre.style.counterReset='linenumber '+(src.start-1);
}
document.getElementById('code-close').onclick=()=>document.getElementById('code-panel').classList.remove('open');

// ===== RESIZE CODE PANEL =====
(function(){
    const handle=document.getElementById('resize-handle');
    const panel=document.getElementById('code-panel');
    let dragging=false,startY,startH;
    handle.addEventListener('mousedown',e=>{dragging=true;startY=e.clientY;startH=panel.offsetHeight;document.body.style.cursor='ns-resize';e.preventDefault();});
    document.addEventListener('mousemove',e=>{if(!dragging)return;const dy=startY-e.clientY;const nh=Math.max(80,Math.min(startH+dy,window.innerHeight*0.7));panel.style.height=nh+'px';handle.style.bottom=(nh)+'px';});
    document.addEventListener('mouseup',()=>{if(dragging){dragging=false;document.body.style.cursor='';net.redraw();}});
    const obs=new MutationObserver(()=>{if(panel.classList.contains('open')){handle.style.bottom=panel.offsetHeight+'px';handle.style.display='block';}else{handle.style.display='none';}});
    obs.observe(panel,{attributes:true,attributeFilter:['class']});
})();

// ===== DETAILS PANEL =====
function showDetails(nodeId, switchTab){
    // Only switch to Inspector tab when clicking directly on the graph canvas
    if(switchTab){
        document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
        document.querySelector('[data-tab="details"]').classList.add('active');
        document.getElementById('tab-details').classList.add('active');
    }

    const node=nodes.get(nodeId);if(!node)return;
    const d=node.data||{};
    const flags=FL[nodeId]||[];
    const findings=HYP[nodeId]||[];
    const det=document.getElementById('details');
    let h=`<div class="det-header">${esc(node.label)}</div>`;
    h+=`<div class="det-type">${esc(node.group)}`;
    if(findings.length)h+=` <span class="sev-badge ${sevClass(findings[0].severity)}" style="font-size:8px">${findings.length} finding${findings.length>1?'s':''}</span>`;
    h+=`</div>`;

    // Properties
    h+='<div class="det-section"><h5>Properties</h5>';
    if(node.group==='Function'){
        h+=`<div class="det-row"><span class="dk">Contract</span><span class="dv">${esc(d.contract)}</span></div>`;
        h+=`<div class="det-row"><span class="dk">Visibility</span><span class="dv"><span class="tag tag-vis">${esc(d.visibility)}</span></span></div>`;
        h+=`<div class="det-row"><span class="dk">Mutability</span><span class="dv">${esc(d.mutability)}</span></div>`;
        if(d.params)h+=`<div class="det-row"><span class="dk">Params</span><span class="dv" style="font-size:11px;font-family:monospace">${esc(d.params)}</span></div>`;
        if(d.file)h+=`<div class="det-row"><span class="dk">File</span><span class="dv" style="font-size:10px">${esc(d.file.split('/').slice(-2).join('/'))}</span></div>`;
        if(d.line_start)h+=`<div class="det-row"><span class="dk">Lines</span><span class="dv">${d.line_start}${d.line_end?' - '+d.line_end:''}</span></div>`;
        if(d.modifiers&&d.modifiers.length>0)h+=`<div class="det-row"><span class="dk">Modifiers</span><span class="dv">${d.modifiers.map(m=>`<span class="tag tag-mod">${esc(m)}</span>`).join(' ')}</span></div>`;
        else if(['external','public'].includes(d.visibility))h+=`<div class="det-row"><span class="dk">Modifiers</span><span class="dv"><span class="tag tag-unr">UNRESTRICTED</span></span></div>`;
    }else if(node.group==='Contract'){
        if(d.file)h+=`<div class="det-row"><span class="dk">File</span><span class="dv">${esc(d.file.split('/').slice(-2).join('/'))}</span></div>`;
        h+=`<div class="det-row"><span class="dk">SLOC</span><span class="dv">${d.sloc||'?'}</span></div>`;
    }else if(node.group==='StateVariable'){
        h+=`<div class="det-row"><span class="dk">Contract</span><span class="dv">${esc(d.contract)}</span></div>`;
        if(d.var_type)h+=`<div class="det-row"><span class="dk">Type</span><span class="dv" style="font-family:monospace;font-size:11px">${esc(d.var_type)}</span></div>`;
    }else if(node.group==='ExternalTarget'){
        h+=`<div class="det-row"><span class="dk">Target</span><span class="dv">${esc(d.target)}</span></div>`;
        h+=`<div class="det-row"><span class="dk">Taint</span><span class="dv">${d.data_source==='user_input'?'<span class="tag tag-flag">USER INPUT</span>':esc(d.data_source)}</span></div>`;
    }
    h+='</div>';

    if(flags.length>0){h+='<div class="det-section"><h5>Flags</h5>'+flags.map(f=>`<span class="tag tag-flag">${esc(f)}</span> `).join('')+'</div>';}

    // Findings for this node
    if(findings.length>0){
        h+='<div class="det-section"><h5>Findings ('+findings.length+')</h5>';
        findings.forEach(f=>{
            const col=SEV_COLORS[f.severity]||'#888';
            h+=`<div class="finding-card"><div class="fc-sev" style="color:${col}">${esc(f.severity)}</div><div class="fc-title">${esc(f.title)}</div><div class="fc-cat">${esc(f.category)}</div></div>`;
        });
        h+='</div>';
    }

    // State var flow
    if(node.group==='StateVariable'){
        if(d.writers&&d.writers.length){h+='<div class="det-section"><h5>Writers</h5>';d.writers.forEach(w=>{const wn=nodes.get(w);h+=`<div class="conn-item" onclick="focusNode('${escAttr(w)}')"><span class="etype" style="color:#FF6347">W</span>${esc(wn?.label||w)}</div>`;});h+='</div>';}
        if(d.readers&&d.readers.length){h+='<div class="det-section"><h5>Readers</h5>';d.readers.forEach(r=>{const rn=nodes.get(r);h+=`<div class="conn-item" onclick="focusNode('${escAttr(r)}')"><span class="etype" style="color:#50C878">R</span>${esc(rn?.label||r)}</div>`;});h+='</div>';}
    }

    // Function callers/callees
    if(node.group==='Function'){
        if(d.callers&&d.callers.length){h+='<div class="det-section"><h5>Called By ('+d.callers.length+')</h5>';d.callers.forEach(c=>{const cn=nodes.get(c);h+=`<div class="conn-item" onclick="focusNode('${escAttr(c)}')"><span class="etype">IN</span>${esc(cn?.label||c)}</div>`;});h+='</div>';}
        if(d.callees&&d.callees.length){h+='<div class="det-section"><h5>Calls ('+d.callees.length+')</h5>';d.callees.forEach(c=>{const cn=nodes.get(c);h+=`<div class="conn-item" onclick="focusNode('${escAttr(c)}')"><span class="etype">OUT</span>${esc(cn?.label||c)}</div>`;});h+='</div>';}
        // Action buttons
        if(SRC[nodeId])h+=`<button class="view-code-btn" onclick="openCode('${escAttr(nodeId)}')">View Source Code</button>`;
        h+=`<button class="trace-btn" onclick="traceChain('${escAttr(nodeId)}')">Trace Call Chain</button>`;
    }

    // Contract: functions + vars
    if(node.group==='Contract'){
        const fids=d.functions||[];
        if(fids.length){h+='<div class="det-section"><h5>Functions ('+fids.length+')</h5>';fids.forEach(fid=>{const fn=nodes.get(fid);if(!fn)return;const fd=fn.data||{};const vis=fd.visibility||'';const isE=['external','public'].includes(vis);const isU=isE&&(!fd.modifiers||fd.modifiers.length===0);const hasSrc=!!SRC[fid];const hasF=(HYP[fid]||[]).length;
        h+=`<div class="conn-item" onclick="focusNode('${escAttr(fid)}')">${isE?`<span class="tag tag-vis" style="font-size:8px">${esc(vis)}</span>`:''}${isU?'<span class="tag tag-unr" style="font-size:8px;padding:0 3px">!</span>':''} ${esc(fn.label)}${fd.line_start?' <span style="color:var(--text-muted);font-size:9px">:'+fd.line_start+'</span>':''}${hasF?` <span class="sev-badge sev-high" style="font-size:7px;padding:0 4px">${hasF}</span>`:''}${hasSrc?' <span style="color:var(--info);font-size:8px;cursor:pointer" onclick="event.stopPropagation();openCode(\''+escAttr(fid)+'\')">code</span>':''}</div>`;});h+='</div>';}
        const vids=d.state_vars||[];
        if(vids.length){h+='<div class="det-section"><h5>State Vars ('+vids.length+')</h5>';vids.forEach(vid=>{const vn=nodes.get(vid);if(!vn)return;h+=`<div class="conn-item" onclick="focusNode('${escAttr(vid)}')">${esc(vn.label)} <span style="color:var(--text-muted);font-size:9px">${esc(vn.data?.var_type||'')}</span></div>`;});h+='</div>';}
    }

    // All connections
    const ce=net.getConnectedEdges(nodeId);
    if(ce.length){h+='<div class="det-section"><h5>Connections ('+ce.length+')</h5>';ce.slice(0,30).forEach(eid=>{const e=edges.get(eid);if(!e)return;const other=e.from===nodeId?nodes.get(e.to):nodes.get(e.from);const dir=e.from===nodeId?'&rarr;':'&larr;';const col=EC[e.label]||'#888';h+=`<div class="conn-item" onclick="focusNode('${escAttr(other?.id||'')}')"><span class="etype" style="color:${col}">${esc(e.label)}</span> ${dir} ${esc(other?.label||'?')}</div>`;});if(ce.length>30)h+=`<div style="color:var(--text-muted);font-size:10px;padding:3px 0">... and ${ce.length-30} more</div>`;h+='</div>';}

    det.innerHTML=h;
    document.getElementById('st-sel').textContent='Selected: '+node.label;

    // Auto-open code panel for functions
    if(node.group==='Function'&&SRC[nodeId])openCode(nodeId);
}

// ===== CALL CHAIN TRACE =====
function traceChain(startId){
    const visited=new Set(),cn=new Set(),ce=new Set();
    function walk(id,depth){
        if(depth>8||visited.has(id))return;visited.add(id);cn.add(id);
        G.edges.forEach((e,i)=>{
            if(e.from===id&&(e.label==='CALLS'||e.label==='WRITES'||e.label==='READS'||e.label==='EXTERNAL_CALL'||e.label==='TOKEN_FLOW')){
                ce.add('e'+i);cn.add(e.to);
                if(e.label==='CALLS')walk(e.to,depth+1);
            }
        });
    }
    walk(startId,0);
    // Also include parent contract
    const nd=nodes.get(startId);
    if(nd?.data?.contract){const cid='contract:'+nd.data.contract;cn.add(cid);}
    nodes.update(G.nodes.map(n=>({id:n.id,hidden:!cn.has(n.id)})));
    edges.update(G.edges.map((e,i)=>({id:'e'+i,hidden:!ce.has('e'+i)})));
    const sn=nodes.get(startId);
    const bc=document.getElementById('breadcrumb');
    bc.innerHTML=`Call chain: <span onclick="focusNode('${escAttr(startId)}')">${esc(sn?.label||startId)}</span> (${cn.size} nodes) &mdash; <span onclick="applyFilters();document.getElementById('breadcrumb').style.display='none'">Reset</span>`;
    bc.style.display='block';
    net.fit({nodes:[...cn],animation:{duration:400}});
    updStatus();
}

// ===== DOUBLE-CLICK: open code =====
net.on('doubleClick',p=>{if(p.nodes.length>0&&SRC[p.nodes[0]])openCode(p.nodes[0]);});

// ===== KEYBOARD =====
document.addEventListener('keydown',e=>{
    if(e.target.tagName==='INPUT')return;
    if(e.key==='f'||e.key==='F')net.fit({animation:{duration:300}});
    if(e.key==='Escape'){applyFilters();document.getElementById('breadcrumb').style.display='none';document.getElementById('search').value='';document.getElementById('code-panel').classList.remove('open');}
    if(e.key==='/'||e.key==='s'){e.preventDefault();document.getElementById('search').focus();}
    if(e.key==='c'||e.key==='C')document.getElementById('btn-cluster').click();
    if(e.key==='p'||e.key==='P')document.getElementById('btn-physics').click();
    if(e.key==='h'||e.key==='H')document.getElementById('btn-hier').click();
    if(e.key==='l'||e.key==='L')document.getElementById('btn-labels').click();
});

net.once('stabilizationIterationsDone',()=>{net.fit({animation:false});updStatus();});
</script>
</body>
</html>"""


def export_graph_html(sg: SecurityGraph, output_path: str | Path,
                      hypotheses: list | None = None) -> str:
    """
    Export SecurityGraph to an interactive HTML file with source code preview.

    Args:
        sg: The SecurityGraph to visualize
        output_path: Where to save the HTML file
        hypotheses: Optional list of Hypothesis objects to overlay

    Returns: The absolute path of the saved file
    """
    viz_data = sg.to_viz_data()
    summary = sg.summary()
    source_snippets = sg.extract_source_snippets()
    hypo_map = _build_hypothesis_map(hypotheses)

    html = HTML_TEMPLATE
    html = html.replace("__GRAPH_DATA__", _safe_json(viz_data))
    html = html.replace("__SUMMARY_DATA__", _safe_json(summary))
    html = html.replace("__FLAGS_DATA__", _safe_json(sg.flags))
    html = html.replace("__SOURCE_DATA__", _safe_json(source_snippets))
    html = html.replace("__HYPO_DATA__", _safe_json(hypo_map))

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return str(output_path.absolute())
