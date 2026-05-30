"""avadhi/agents/hunters — Specialized vulnerability hunter agents.

V2 architecture: 6 consolidated agents (down from 18) with intelligent routing.

  Always-on:
    - ReasoningAgent    (Feynman method — WHY-based questioning)
    - StructuralAgent   (State coupling — mutation matrix analysis)
    - VectorScanAgent   (Systematic check against known attack vectors)

  Flag-gated:
    - EconomicAgent     (Oracle, flash loan, DeFi math, token quirks)
    - ExecutionTraceAgent (Parameter flow, cross-tx state, interleaving)
    - PeripheryAgent    (Libraries, helpers, base contracts — >= 5 contracts)

Legacy hunters remain importable for backward compatibility.
"""

# ── V2 consolidated agents ──────────────────────────────────────────────────
from avadhi.agents.hunters.reasoning import run_reasoning_hunter
from avadhi.agents.hunters.structural import run_structural_hunter
from avadhi.agents.hunters.vector_scan import run_vector_scan_hunter
from avadhi.agents.hunters.economic import run_economic_hunter
from avadhi.agents.hunters.execution_trace import run_execution_trace_hunter
from avadhi.agents.hunters.periphery import run_periphery_hunter

# ── Agent registry — maps router keys to callables ──────────────────────────
AGENT_REGISTRY: dict[str, callable] = {
    "reasoning":       run_reasoning_hunter,
    "structural":      run_structural_hunter,
    "vector_scan":     run_vector_scan_hunter,
    "economic":        run_economic_hunter,
    "execution_trace": run_execution_trace_hunter,
    "periphery":       run_periphery_hunter,
}

# ── Legacy hunters (still importable) ────────────────────────────────────────
from avadhi.agents.hunters.access_control import run_access_control_hunter
from avadhi.agents.hunters.external_call import run_external_call_hunter
from avadhi.agents.hunters.cryptography import run_cryptography_hunter
from avadhi.agents.hunters.defi_math import run_defi_math_hunter
from avadhi.agents.hunters.proxy import run_proxy_hunter
from avadhi.agents.hunters.cross_chain import run_cross_chain_hunter
from avadhi.agents.hunters.gas_dos import run_gas_dos_hunter
from avadhi.agents.hunters.accounting import run_accounting_hunter
from avadhi.agents.hunters.fee_accounting import run_fee_accounting_hunter
from avadhi.agents.hunters.callback import run_callback_hunter
from avadhi.agents.hunters.oracle import run_oracle_hunter
from avadhi.agents.hunters.reentrancy import run_reentrancy_hunter
from avadhi.agents.hunters.governance import run_governance_hunter
from avadhi.agents.hunters.metatx import run_metatx_hunter
from avadhi.agents.hunters.statemachine import run_state_machine_hunter
from avadhi.agents.hunters.integration import run_integration_hunter
from avadhi.agents.hunters.erc20_safety import run_erc20_safety_hunter
from avadhi.agents.hunters.upgradeable_safety import run_upgradeable_safety_hunter

__all__ = [
    # V2
    "AGENT_REGISTRY",
    "run_reasoning_hunter",
    "run_structural_hunter",
    "run_vector_scan_hunter",
    "run_economic_hunter",
    "run_execution_trace_hunter",
    "run_periphery_hunter",
    # Legacy
    "run_access_control_hunter",
    "run_external_call_hunter",
    "run_cryptography_hunter",
    "run_defi_math_hunter",
    "run_proxy_hunter",
    "run_cross_chain_hunter",
    "run_gas_dos_hunter",
    "run_accounting_hunter",
    "run_fee_accounting_hunter",
    "run_callback_hunter",
    "run_oracle_hunter",
    "run_reentrancy_hunter",
    "run_governance_hunter",
    "run_metatx_hunter",
    "run_state_machine_hunter",
    "run_integration_hunter",
    "run_erc20_safety_hunter",
    "run_upgradeable_safety_hunter",
]
