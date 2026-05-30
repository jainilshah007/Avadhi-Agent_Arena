"""
avadhi/agents/hunters/fee_accounting.py — Fee & Accounting Logic Hunter.

Hunts for:
  - Validate-before-modify: validation on a variable that is later overwritten
    in the same function (e.g. validate gross amount, then overwrite with net)
  - Gross vs. net fee mismatches: minimum/rate checks applied to pre-fee
    amounts that don't hold after fees are deducted
  - Rate bypass via parameter substitution: changing duration/period/epoch
    without re-validating the resulting rate against the minimum
  - Override/shadow state misuse: validating against an original record when
    an effective override record exists (campaign override anchoring bug)
  - Missing re-validation after state mutation within the same function
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in FEE LOGIC and ACCOUNTING VALIDATION vulnerabilities.

You are given a SecurityGraph view showing functions involved in fee computation, rate validation, and parameter overrides, along with their source code.

Your job is to find REAL fee-accounting vulnerabilities. Focus on these specific and high-value patterns:

## 1. Validate-Before-Modify (CRITICAL PATTERN)
A function validates a variable, then overwrites it with a modified version, without re-validating.

```solidity
// VULNERABLE: validates amount (gross), then overwrites with net
if (amount < minimumRate) revert;        // ← validates GROSS
uint netAmount = amount - computeFee(amount);  // ← overwrites
campaign.amount = netAmount;               // ← stored is NET, but minimum check was on GROSS
```

Hunt for: functions that call a fee/tax/commission computation AND have a validation check on the same variable BEFORE the fee computation. Ask: is the validation repeated AFTER the fee is deducted?

## 2. Duration-Based Rate Bypass
The protocol enforces a minimum `amount / duration` rate. A separate function allows changing `duration` but does NOT re-validate the rate with the new duration.

```solidity
// VULNERABLE: minimum rate validated at creation
if ((amount * HOUR) / duration < minRate) revert;  // ← rate check at creation

// BYPASS: override changes duration, rate never re-checked
function override(id, newDuration) {
    campaign.duration = newDuration;  // ← no rate re-check!
}
```

Hunt for: functions that set/override a duration, period, or epoch parameter WITHOUT containing the same rate validation that the creation function has.

## 3. Stale/Original State Validation (Shadow State Bug)
The protocol stores BOTH an original record AND an override/amended record for the same entity. Validation functions query the original instead of the effective (latest) record.

```solidity
mapping(bytes32 => Campaign) public campaignList;      // original
mapping(bytes32 => Campaign) public campaignOverrides;  // effective

function overrideCampaign(bytes32 id, ...) {
    Campaign memory base = campaignList[id];  // ← always reads ORIGINAL, not overrides[id]!
    if (block.timestamp > base.startTimestamp) revert;  // ← compares vs original start
}
```

Hunt for: contracts with two mappings/structs storing the same entity (original vs override, base vs amended, snapshot vs current). Check if validations always use the correct/latest version.

## 4. Fee Recipient / Rate Asymmetry
Fee rates or recipients can be set to values that violate protocol economics:
- Fee rate set to 100% (all funds taken as fee, zero distributed)
- Fee recipient set to zero address (fees burned, not collected)
- Fee rate changeable mid-campaign/epoch, affecting in-flight rewards

## 5. Missing Slippage / Minimum on Return Amount
Functions that compute output amounts (swaps, redemptions) but don't validate the output against a minimum:
- `amountOut = amountIn - fee` with no `require(amountOut >= minAmountOut)`

## For each finding:
- State the EXACT line sequence that creates the bug (validate on line X, overwrite on line Y, never re-validated)
- Show BOTH the vulnerable path and the missing fix
- Quantify impact: what rate/amount is actually applied vs what the invariant requires

DO NOT flag:
- View/pure functions
- Intentional fees that are clearly documented and bounded
- Interface-only contracts"""


def run_fee_accounting_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for fee-accounting logic vulnerabilities.

    Strategy:
      1. Find functions with fee-related names or that call fee-computation functions
      2. Find functions with validation/require patterns on financial variables
      3. Detect contracts with dual-record state (original + override mappings)
      4. Find override/setter functions for rate/duration parameters
      5. Ask LLM with full source of all relevant functions
    """
    # ── Step 1: Find fee-computation functions ──────────────────────────────
    fee_keywords = {
        "fee", "tax", "commission", "deduct", "charge", "cost",
        "compute_fee", "computefee", "_computefees", "collectfee",
        "protocol_fee", "protocolFee", "take_fee",
    }
    rate_keywords = {
        "rate", "reward", "amount", "distribute", "campaign",
        "override", "minimum", "min_amount", "minAmount",
    }
    override_keywords = {
        "override", "update", "set", "change", "modify", "amend",
        "adjust", "configure",
    }
    duration_keywords = {
        "duration", "period", "epoch", "window", "timestamp",
        "start", "end", "expire",
    }

    fee_fns: set[str] = set()
    rate_fns: set[str] = set()
    override_fns: set[str] = set()
    validation_fns: set[str] = set()

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        # Fee computation functions
        if any(kw in fn_name for kw in fee_keywords):
            fee_fns.add(fn_id)
        # Rate / amount / campaign functions
        if any(kw in fn_name for kw in rate_keywords):
            rate_fns.add(fn_id)
        # Override / setter functions that touch duration
        if any(ok in fn_name for ok in override_keywords) and \
           any(dk in fn_name for dk in duration_keywords):
            override_fns.add(fn_id)
        # Functions that call fee functions (callers of fee-computation)
        for _, neighbor, edata in sg.G.out_edges(fn_id, data=True):
            if edata.get("edge_type") == CALLS:
                callee_name = sg.G.nodes.get(neighbor, {}).get("name", "").lower()
                if any(kw in callee_name for kw in fee_keywords):
                    fee_fns.add(fn_id)  # this fn calls a fee computation

    # ── Step 2: Detect dual-record state (original + override) ─────────────
    # Look for contracts that have TWO mappings with similar names suggesting
    # original + override semantics
    dual_record_contracts: list[str] = []
    contract_mappings: dict[str, list[str]] = {}  # contract -> [var names]

    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        contract = data.get("contract", "")
        var_name = data.get("name", "").lower()
        var_type = data.get("var_type", "").lower()
        if "mapping" in var_type:
            contract_mappings.setdefault(contract, []).append(var_name)

    override_marker_words = {"override", "amended", "updated", "effective", "snapshot", "base", "original"}
    for contract, var_names in contract_mappings.items():
        # Check if any pair of vars looks like original+override
        for v1 in var_names:
            for v2 in var_names:
                if v1 == v2:
                    continue
                # One has an override-like word and one doesn't
                v1_has_marker = any(m in v1 for m in override_marker_words)
                v2_has_marker = any(m in v2 for m in override_marker_words)
                if v1_has_marker != v2_has_marker:
                    # Likely a dual-record pattern
                    if contract not in dual_record_contracts:
                        dual_record_contracts.append(contract)

    # ── Step 3: Find all functions in dual-record contracts ─────────────────
    dual_record_fns: set[str] = set()
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        contract = data.get("contract", "")
        if contract in dual_record_contracts:
            dual_record_fns.add(fn_id)

    # ── Step 4: Build the context ───────────────────────────────────────────
    context_lines = []

    if fee_fns:
        context_lines.append("# Fee-Related Functions")
        for fn_id in sorted(fee_fns)[:20]:
            data = sg.G.nodes.get(fn_id, {})
            mods = data.get("modifiers", [])
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {mods}] "
                f"[flags: {data.get('flags',[])}]"
            )

    if rate_fns:
        context_lines.append("\n# Rate / Reward / Campaign Functions")
        for fn_id in sorted(rate_fns)[:20]:
            data = sg.G.nodes.get(fn_id, {})
            callee_names = [
                sg.G.nodes.get(n, {}).get("name", "")
                for _, n, ed in sg.G.out_edges(fn_id, data=True)
                if ed.get("edge_type") == CALLS
            ]
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"calls: [{', '.join(callee_names[:6])}]"
            )

    if override_fns:
        context_lines.append("\n# Override / Duration-Setter Functions (WARNING Check Rate Re-Validation)")
        for fn_id in sorted(override_fns):
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {data.get('modifiers',[])}]"
            )

    if dual_record_contracts:
        context_lines.append("\n# WARNING Dual-Record Contracts (Original + Override State)")
        context_lines.append(
            "These contracts store BOTH an original and an override/amended record. "
            "Check if validations use the EFFECTIVE (latest) record or the ORIGINAL."
        )
        for contract in dual_record_contracts:
            vnames = contract_mappings.get(contract, [])
            context_lines.append(f"- Contract: {contract}")
            context_lines.append(f"  Mappings: {', '.join(vnames)}")
            # List functions in this contract that do validation
            contract_fns = [
                fn_id for fn_id, data in sg.get_nodes_by_type(FUNCTION)
                if data.get("contract") == contract
            ]
            context_lines.append(
                f"  Functions: {', '.join(sg.G.nodes.get(f,{}).get('name','') for f in contract_fns[:10])}"
            )

    # Add invariants from Phase 1d if present
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Protocol Invariants (from enrichment)")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines) if context_lines else "No fee-related functions detected."

    # ── Step 5: Get source code ─────────────────────────────────────────────
    # Priority: override functions > rate functions > fee functions > dual-record functions
    priority_order = (
        list(override_fns) +
        list(rate_fns) +
        list(fee_fns) +
        list(dual_record_fns)
    )
    # Deduplicate while preserving order
    seen: set[str] = set()
    all_fns = [fn_id for fn_id in priority_order if not (fn_id in seen or seen.add(fn_id))]

    source = get_source_for_functions(sg, all_fns[:15], max_chars=10_000)

    if not all_fns:
        if verbose:
            print("  ℹ️  FeeAccountingHunter: No fee-related functions found")
        return []

    if verbose:
        print(
            f"   FeeAccountingHunter: {len(fee_fns)} fee fns, "
            f"{len(override_fns)} override fns, "
            f"{len(dual_record_contracts)} dual-record contracts"
        )

    return call_hunter(
        hunter_name="FeeAccountingHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
        include_methodology=True,
        rag_query=(
            "fee validation gross net amount before after deduction "
            "minimum rate check override duration bypass"
        ),
        vulnerability_type="accounting",
    )
