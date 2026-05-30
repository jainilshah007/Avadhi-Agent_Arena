"""
avadhi/recon/enrichment.py — Phase 1c: LLM Enrichment (Layer 1).

Takes the Layer 0 SecurityGraph (structural facts) and uses the LLM to add:
  1. Protocol classification (type, purpose)
  2. Trust boundary model (who's trusted, how much)
  3. Inferred invariants (what MUST hold true for security)
  4. Semantic taint labels (which inputs are user-controlled)
  5. Critical path annotations (which paths matter most for security)

This is the bridge between "I see code structure" and "I understand what this protocol does."
"""
from __future__ import annotations

import json
import time
from typing import Any

from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.graph import SecurityGraph
from avadhi.utils.llm import get_llm
from avadhi.utils.logging import AuditLogger


# ═══════════════════════════════════════════════════════════════════════════════
# Prompts
# ═══════════════════════════════════════════════════════════════════════════════

ENRICHMENT_SYSTEM = """You are a senior smart contract security auditor. 
You are given a structural analysis of a Solidity codebase (contracts, functions, state variables, external calls, token flows, detected patterns).

Your job is to add SEMANTIC understanding that static analysis cannot provide:
1. What TYPE of protocol is this? (lottery, DEX, lending, vault, staking, bridge, governance, NFT marketplace, etc.)
2. Who are the TRUST BOUNDARIES? (which roles exist, what trust level each has)
3. What INVARIANTS must hold for this protocol to be secure?
4. Which data flows are DANGEROUS and why?

Be precise. Be security-focused. Every annotation you add helps hunters find vulnerabilities."""

ENRICHMENT_PROMPT = """## SecurityGraph Analysis

{graph_context}

## Source Code Snippets (key functions only)

{source_snippets}

## Detected Patterns

{patterns}

---

Based on the above, provide your enrichment analysis as JSON with this exact structure:

```json
{{
  "protocol_type": "lottery|dex|lending|vault|staking|bridge|governance|nft|other",
  "protocol_purpose": "One sentence describing what this protocol does",
  "trust_boundaries": [
    {{
      "name": "owner|admin|operator|keeper|user|attacker",
      "trust_level": "FULLY_TRUSTED|SEMI_TRUSTED|UNTRUSTED",
      "description": "What this actor can do and what limits them",
      "related_modifiers": ["onlyOwner"]
    }}
  ],
  "invariants": [
    {{
      "id": "INV-001",
      "description": "Human-readable invariant statement",
      "formal": "totalDeposited >= totalWithdrawn (always)",
      "related_vars": ["ContractName.varName"],
      "severity_if_broken": "Critical|High|Medium",
      "source": "inferred|documented"
    }}
  ],
  "dangerous_flows": [
    {{
      "description": "What makes this flow dangerous",
      "from_function": "ContractName.functionName",
      "to_target": "what it reaches",
      "risk": "Critical|High|Medium",
      "why": "Why this is a risk"
    }}
  ],
  "attack_surface_notes": [
    "Key insight about the attack surface that a hunter should know"
  ]
}}
```

IMPORTANT:
- Only include invariants you can actually infer from the code/structure
- For trust_boundaries, look at modifier usage to determine roles
- For dangerous_flows, focus on user-controlled inputs reaching sensitive operations
- Use actual contract/function names from the graph, not generic examples"""


def _get_source_snippets(sg: SecurityGraph, max_chars: int = 6000) -> str:
    """Extract the most security-relevant source snippets for LLM context."""
    source_files = sg.metadata.get("source_files", {})
    if not source_files:
        return "(no source code available)"

    snippets = []
    total_chars = 0

    # Prioritize: files with external calls, token flows, unrestricted entry points
    priority_contracts = set()
    for u, v, d in sg.get_external_calls():
        node = sg.G.nodes.get(u, {})
        if node.get("contract"):
            priority_contracts.add(node["contract"])
    for u, v, d in sg.get_token_flows():
        node = sg.G.nodes.get(u, {})
        if node.get("contract"):
            priority_contracts.add(node["contract"])

    for file_path, content in source_files.items():
        # Skip interfaces
        if "/interfaces/" in file_path or "/lib/" in file_path:
            continue

        # Check if this file has priority contracts
        is_priority = any(c in file_path for c in priority_contracts)
        if is_priority or total_chars < max_chars // 2:
            snippet = content[:max_chars // len(source_files)]
            snippets.append(f"### {file_path}\n```solidity\n{snippet}\n```")
            total_chars += len(snippet)
            if total_chars >= max_chars:
                break

    return "\n\n".join(snippets) if snippets else "(source too large, using graph only)"


def _get_patterns_text(sg: SecurityGraph) -> str:
    """Format detected patterns for the prompt."""
    flags = sg.metadata.get("global_flags", [])
    if not flags:
        return "No patterns detected."
    return "\n".join(f"- {f}" for f in flags)


def _parse_enrichment_response(text: str) -> dict | None:
    """Extract JSON from LLM response (handles markdown code blocks)."""
    # Try to find JSON in code block
    if "```json" in text:
        start = text.index("```json") + 7
        if "```" in text[start:]:
            end = text.index("```", start)
            text = text[start:end].strip()
        else:
            text = text[start:].strip()
    elif "```" in text:
        start = text.index("```") + 3
        if "```" in text[start:]:
            end = text.index("```", start)
            text = text[start:end].strip()
        else:
            text = text[start:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        for i, ch in enumerate(text):
            if ch == "{":
                depth = 0
                for j in range(i, len(text)):
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[i:j + 1])
                        except json.JSONDecodeError:
                            break
                break
    return None


def _apply_enrichment(sg: SecurityGraph, data: dict):
    """Apply LLM enrichment data to the SecurityGraph."""
    # Protocol metadata
    sg.metadata["protocol_type"] = data.get("protocol_type", "unknown")
    sg.metadata["protocol_purpose"] = data.get("protocol_purpose", "")
    sg.metadata["attack_surface_notes"] = data.get("attack_surface_notes", [])

    # Trust boundaries
    for tb in data.get("trust_boundaries", []):
        sg.add_trust_boundary(
            name=tb.get("name", "unknown"),
            trust_level=tb.get("trust_level", "UNTRUSTED"),
            actors=tb.get("related_modifiers", []),
            description=tb.get("description", ""),
        )

    # Invariants
    for inv in data.get("invariants", []):
        related_vars = inv.get("related_vars", [])
        sg.add_invariant(
            inv_id=inv.get("id", f"INV-{id(inv)}"),
            description=inv.get("description", ""),
            source=inv.get("source", "inferred"),
            formal_expr=inv.get("formal", ""),
            related_vars=related_vars,
        )

    # Dangerous flows — add as metadata for hunters
    sg.metadata["dangerous_flows"] = data.get("dangerous_flows", [])


# ═══════════════════════════════════════════════════════════════════════════════
# Main Runner
# ═══════════════════════════════════════════════════════════════════════════════

def run_enrichment(sg: SecurityGraph, logger: AuditLogger | None = None,
                   verbose: bool = False) -> dict:
    """
    Phase 1c: LLM enrichment of SecurityGraph.

    Adds Layer 1 (semantic understanding) on top of Layer 0 (structural facts).
    Returns the raw enrichment data dict.
    """
    if verbose:
        print(f"\n{'═'*60}")
        print(f"  PHASE 1c: LLM ENRICHMENT (Layer 1)")
        print(f"{'═'*60}\n")

    # Build prompt
    graph_context = sg.to_context_string(max_chars=6000)
    source_snippets = _get_source_snippets(sg, max_chars=6000)
    patterns_text = _get_patterns_text(sg)

    prompt = ENRICHMENT_PROMPT.format(
        graph_context=graph_context,
        source_snippets=source_snippets,
        patterns=patterns_text,
    )

    if verbose:
        print(f"   Prompt: {len(prompt)} chars")
        print(f"  🤖 Calling LLM...")

    # Call LLM
    llm = get_llm()
    start = time.time()

    from avadhi.agents.hunters.base import _invoke_with_backoff

    response = _invoke_with_backoff(
        llm,
        [SystemMessage(content=ENRICHMENT_SYSTEM), HumanMessage(content=prompt)],
        hunter_name="ReconEnrich",
        max_retries=4
    )
    latency_ms = int((time.time() - start) * 1000)

    response_text = response.content if hasattr(response, "content") else str(response)

    # Log
    if logger:
        usage = getattr(response, "usage_metadata", {}) or {}
        logger.log_llm_call(
            agent="enrichment",
            model=str(getattr(llm, "model", "unknown")),
            phase="recon_enrichment",
            prompt_tokens=usage.get("input_tokens", 0),
            completion_tokens=usage.get("output_tokens", 0),
            latency_ms=latency_ms,
        )

    if verbose:
        print(f"  OK Response: {len(response_text)} chars ({latency_ms}ms)")

    # Parse response
    enrichment_data = _parse_enrichment_response(response_text)
    if not enrichment_data:
        print("  WARNING  Failed to parse LLM response as JSON")
        if verbose:
            print(f"  Raw response:\n{response_text[:500]}")
        return {}

    # Apply to graph
    _apply_enrichment(sg, enrichment_data)

    if verbose:
        print(f"\n  📊 Enrichment Results:")
        print(f"    Protocol: {enrichment_data.get('protocol_type', '?')} — "
              f"{enrichment_data.get('protocol_purpose', '?')}")
        print(f"    Trust Boundaries: {len(enrichment_data.get('trust_boundaries', []))}")
        print(f"    Invariants: {len(enrichment_data.get('invariants', []))}")
        print(f"    Dangerous Flows: {len(enrichment_data.get('dangerous_flows', []))}")
        print(f"    Attack Notes: {len(enrichment_data.get('attack_surface_notes', []))}")

        # Print invariants
        for inv in enrichment_data.get("invariants", []):
            print(f"    📌 {inv.get('id', '?')}: {inv.get('description', '')}")

        # Print dangerous flows
        for flow in enrichment_data.get("dangerous_flows", []):
            print(f"    WARNING  {flow.get('from_function', '?')} → {flow.get('to_target', '?')}: "
                  f"{flow.get('why', '')}")

    if verbose:
        print(f"\n  OK Phase 1c complete.\n")

    return enrichment_data
