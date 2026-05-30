from __future__ import annotations

import json
from pathlib import Path
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage

from avadhi.core.graph import SecurityGraph
from avadhi.utils.llm import get_llm, invoke_with_fallback
from avadhi.utils.logging import AuditLogger

class InvariantPrecomputeResult(BaseModel):
    write_sites: dict[str, list[str]] = Field(description="Map of state variable to the functions that write to it")
    mirror_pairs: list[dict] = Field(description="List of variable pairs that should conceptually reflect each other (e.g., totalAssets and sum(balances))")
    conditional_writes: list[str] = Field(description="Description of state variables that are only updated under specific conditions (e.g., inside an if statement)")
    accumulation_exposures: list[str] = Field(description="Description of state variables that only ever increase or decrease, indicating a potential vulnerability if they never reset")
    semantic_invariants: list[dict] = Field(description="List of fine-grained invariants linked to specific write-sites with severity_if_broken")

SYSTEM_PROMPT = """You are an expert smart contract security researcher. Your goal is to pre-compute semantic invariants and state mutation mapping before the hunting phase begins.
You will be provided with:
1. High-level protocol enrichment data.
2. A list of all state variables and the functions that write to or read from them.

Your task is to analyze these mutation paths and output a precise JSON describing the expected semantic invariants for the system.
Focus on:
- Identifying "mirror variables" (e.g., a vault's `totalAssets` should match the sum of all individual user `balances`).
- Identifying "conditional writes" (e.g., `rewardRate` is only updated when `currentEpochComplete` is true).
- Identifying "accumulation exposures" (e.g., `totalPayout` only ever increases, so it could overflow or hit a cap).
- Defining strict, code-grounded semantic invariants that must hold true after specific state transitions.

Return your analysis strictly in the requested JSON format.
"""

def run_invariant_precompute(
    sg: SecurityGraph,
    enrichment_data: dict,
    logger: AuditLogger | None = None,
) -> dict:
    """
    Phase 2a: Enumerate write sites and compute semantic invariants.
    """
    if logger:
        logger.log_phase("invariant_precompute", "start")

    # 1. Build a map of variable to writers and readers from the graph
    var_map = {}
    for node, data in sg.G.nodes(data=True):
        if data.get("type") == "StateVariable":
            writers = [src for src, dst, edata in sg.G.in_edges(node, data=True) if edata.get("type") == "WRITES"]
            readers = [src for src, dst, edata in sg.G.in_edges(node, data=True) if edata.get("type") == "READS"]
            var_map[node] = {
                "type": data.get("var_type", "unknown"),
                "writers": writers,
                "readers": readers
            }

    context = f"High-level Enrichment:\n{json.dumps(enrichment_data, indent=2)}\n\nState Variable Map:\n{json.dumps(var_map, indent=2)}"

    llm = get_llm()
    structured_llm = llm.with_structured_output(InvariantPrecomputeResult)
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=context)
    ]

    try:
        if logger:
            logger.log_llm_call("invariant_precompute", "gpt-5.4", prompt_tokens=0) # Placeholder for token count
        result = invoke_with_fallback(structured_llm, messages)
        result_dict = result.model_dump()
        
        # Merge into SG metadata
        sg.metadata["semantic_invariants"] = result_dict

        if logger:
            logger.log_phase("invariant_precompute", "complete", extracted_invariants=len(result_dict.get("semantic_invariants", [])))
            
        return result_dict
    except Exception as e:
        if logger:
            logger.log_phase("invariant_precompute", "failed", error=str(e))
        return {
            "write_sites": {},
            "mirror_pairs": [],
            "conditional_writes": [],
            "accumulation_exposures": [],
            "semantic_invariants": []
        }
