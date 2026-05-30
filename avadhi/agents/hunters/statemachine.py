"""
avadhi/agents/hunters/statemachine.py — State Machine & TOCTOU Hunter.

Hunts for:
  - TOCTOU (Time-Of-Check-Time-Of-Use): state is read for validation, then
    changes before the action executes (or vice versa)
  - Wrong state variable in temporal comparisons: validating against an
    original/base record's timestamp when an amended record exists
  - Enum-based state skip: attacker can call a function out-of-order,
    transitioning from state A directly to state C skipping state B
  - Paused-state bypass: pause check placed AFTER an external call or
    state-modifying action
  - Off-by-one on epoch/window boundaries: `>=` vs `>` logic errors
    on timestamps that allow actions in the wrong period
  - Missing terminal state check: refund/claim allowed after a terminal
    state (cancelled, expired, settled) is reached

ClaraHacks Incident Reference:
  - Merkl M-03: Campaign override validates startTimestamp from the base
    campaignList mapping, not the effective campaignOverrides mapping
    (TOCTOU: checks original, acts on override — wrong temporal anchor)
  - Multiple 2024 incidents: pause bypass because isPaused() was a low-level
    call that could be batched past in a multicall context
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in STATE MACHINE and TOCTOU (Time-Of-Check-Time-Of-Use) vulnerabilities.

You are given a SecurityGraph view showing functions that manage protocol state transitions, time-based guards, epoch/window logic, and lifecycle states, along with their source code.

Your job is to find REAL state machine and TOCTOU vulnerabilities:

## 1. TOCTOU — Wrong State Variable in Validation (CRITICAL)
A function validates against one copy of state (original/base), but then acts on a different copy (effective/override). The validation anchor is wrong.

```solidity
mapping(bytes32 => Campaign) public campaigns;         // original
mapping(bytes32 => Campaign) public campaignOverrides; // effective (override)

function overrideCampaign(bytes32 id, uint newStart) external {
    Campaign memory base = campaigns[id];               // ← reads ORIGINAL
    require(block.timestamp < base.startTimestamp);     // ← validates against ORIGINAL start
    campaignOverrides[id].startTimestamp = newStart;    // ← but action affects OVERRIDE
    // BUG: if override already existed with a different start, the check was on BASE not OVERRIDE
}
```

Hunt for: functions that read from one mapping/struct for validation, but write to a different (parallel) mapping/struct that represents the effective state.

## 2. Enum / State Transition Skip
Protocol enforces a lifecycle (e.g. Created → Active → Settled → Closed), but a function can be called when the state variable is NOT in the expected preceding state.

```solidity
enum Status { Created, Active, Settled, Closed }
Status public status;

// VULNERABLE: settle() can be called even if status == Created (skipping Active)
function settle() external {
    require(status != Status.Closed, "already closed");  // only checks Closed!
    status = Status.Settled;
    // Should have checked: require(status == Status.Active, "must be active first")
}
```

Hunt for: enum or integer state variables where transition functions only check the terminal/invalid states but not the required preceding state.

## 3. Pause / Emergency State Bypass
The pause modifier or check is placed incorrectly — AFTER an external call, or inside a path that can be skipped:

```solidity
// VULNERABLE: external call happens BEFORE pause check
function withdraw(uint amount) external {
    token.transfer(msg.sender, amount);  // ← external call first!
    require(!paused, "paused");          // ← pause check comes AFTER
}
```

Also hunt for:
- Functions that skip the `whenNotPaused` modifier via internal helper
- pause() callable during an operation that's halfway complete
- `paused` flag stored in different contract than the one being called

## 4. Off-By-One / Boundary Timestamp Errors
A function uses `>` instead of `>=` (or vice versa) at epoch/window boundaries:

```solidity
// VULNERABLE: should be >=, allows actions at exactly startTime
require(block.timestamp > campaign.startTimestamp, "not started");
// An action at the exact startTimestamp second is incorrectly blocked/allowed.
```

Hunt for: timestamp comparisons on startTime/endTime/deadline where the boundary condition (inclusive vs exclusive) creates an exploitable window.

## 5. Missing Terminal State Check
Actions remain possible after the protocol has reached a terminal state (expired, cancelled, claimed):

```solidity
// VULNERABLE: no check that campaign hasn't expired
function claim(bytes32 id) external {
    // No: require(block.timestamp <= campaign.endTimestamp);
    _distributeRewards(id, msg.sender);  // can claim from expired campaigns!
}
```

Hunt for: claim/withdraw/redeem functions missing an expiry or terminal-state guard.

## 6. Check-Effects-Interactions with State Transition
State transitions inside CEI violations where the transition itself enables reentrancy:

```solidity
// VULNERABLE: external call before state update — attacker re-enters in wrong state
function redeem() external {
    require(status == Status.Active);
    token.transfer(msg.sender, amount);  // ← external call with status still Active
    status = Status.Settled;             // ← too late
}
```

## For each finding:
- Name the EXACT state variable(s) involved in the TOCTOU or wrong-anchor bug
- Show the EXACT read (validation) and write (action) lines
- Explain what an attacker can do by exploiting the mismatched state
- Estimate severity: can they drain funds, skip cooldowns, bypass governance?

DO NOT flag:
- View/pure functions
- Correctly implemented state machines with proper ordering guards
- Interfaces or abstract contracts with no logic"""


def run_state_machine_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for state machine / TOCTOU vulnerabilities.

    Strategy:
      1. Find enum/integer state variables and their transition functions
      2. Find parallel mappings (original + override pairs) for TOCTOU
      3. Find timestamp/epoch guard functions for off-by-one analysis
      4. Find pause/emergency state variables and their usage
      5. Find claim/redeem functions missing terminal state checks
      6. Ask LLM with focused source code
    """
    # ── Step 1: Find enum / status state variables ─────────────────────────
    state_keywords = {
        "status", "state", "phase", "stage", "lifecycle", "mode",
        "paused", "frozen", "halted", "active", "settled", "closed",
        "pending", "cancelled", "expired",
    }
    temporal_keywords = {
        "timestamp", "deadline", "expiry", "epoch", "window",
        "start", "end", "period", "duration", "cooldown", "lockup",
    }
    transition_keywords = {
        "settle", "cancel", "close", "activate", "pause", "unpause",
        "finalize", "complete", "expire", "redeem", "claim", "withdraw",
        "override", "update", "transition",
    }
    override_map_markers = {
        "override", "amended", "updated", "effective", "snapshot",
        "base", "original", "backup",
    }

    state_vars: list[tuple[str, dict]] = []
    temporal_vars: list[tuple[str, dict]] = []
    transition_fns: set[str] = set()
    claim_fns: set[str] = set()
    pause_fns: set[str] = set()

    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        var_name = data.get("name", "").lower()
        var_type = data.get("var_type", "").lower()

        if any(kw in var_name for kw in state_keywords) or "enum" in var_type:
            state_vars.append((var_id, data))
        if any(kw in var_name for kw in temporal_keywords):
            temporal_vars.append((var_id, data))

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        src = data.get("source", "").lower()

        # Transition functions
        if any(kw in fn_name for kw in transition_keywords):
            transition_fns.add(fn_id)
        # Claim / withdraw functions
        if any(kw in fn_name for kw in {"claim", "claimreward", "withdraw", "redeem", "collect"}):
            claim_fns.add(fn_id)
        # Pause-related functions
        if "pause" in fn_name or "pause" in src or "halted" in src or "frozen" in src:
            pause_fns.add(fn_id)

    # ── Step 2: Find parallel mapping pairs (TOCTOU anchor) ─────────────────
    contract_mappings: dict[str, list[str]] = {}
    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        var_type = data.get("var_type", "").lower()
        contract = data.get("contract", "")
        var_name = data.get("name", "")
        if "mapping" in var_type:
            contract_mappings.setdefault(contract, []).append(var_name)

    dual_record_contracts: list[str] = []
    for contract, var_names in contract_mappings.items():
        for v1 in var_names:
            for v2 in var_names:
                if v1 == v2:
                    continue
                v1_lower, v2_lower = v1.lower(), v2.lower()
                v1_has_marker = any(m in v1_lower for m in override_map_markers)
                v2_has_marker = any(m in v2_lower for m in override_map_markers)
                if v1_has_marker != v2_has_marker:
                    if contract not in dual_record_contracts:
                        dual_record_contracts.append(contract)

    # Functions in dual-record contracts
    dual_record_fns: set[str] = set()
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        if data.get("contract", "") in dual_record_contracts:
            dual_record_fns.add(fn_id)

    # ── Step 3: Build context ─────────────────────────────────────────────
    context_lines: list[str] = []

    if state_vars:
        context_lines.append("# State / Status / Lifecycle Variables")
        context_lines.append("These track protocol lifecycle — check transitions are in correct order:")
        for var_id, data in state_vars[:15]:
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')} "
                f"[type: {data.get('var_type','')}] "
                f"[mutability: {data.get('mutability','mutable')}]"
            )

    if transition_fns:
        context_lines.append("\n# State Transition Functions")
        context_lines.append("WARNING Check that each transition validates the PRECEDING state, not just the terminal/invalid state:")
        for fn_id in sorted(transition_fns)[:15]:
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {data.get('modifiers',[])}] "
                f"[flags: {data.get('flags',[])}]"
            )

    if pause_fns:
        context_lines.append("\n# Pause / Emergency State Functions")
        context_lines.append("WARNING Check that pause guards appear BEFORE any external calls (CEI order):")
        for fn_id in sorted(pause_fns)[:10]:
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {data.get('modifiers',[])}]"
            )

    if temporal_vars:
        context_lines.append("\n# Temporal / Epoch / Deadline Variables")
        context_lines.append("WARNING Check >= vs > boundary conditions, and that timestamp comparisons use the EFFECTIVE record:")
        for var_id, data in temporal_vars[:10]:
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')} "
                f"[type: {data.get('var_type','')}]"
            )

    if dual_record_contracts:
        context_lines.append("\n# WARNING TOCTOU Risk: Dual-Record Contracts")
        context_lines.append(
            "These contracts store BOTH an original AND an override/amended record. "
            "CRITICAL: Verify that validations (especially timestamp checks) use the "
            "EFFECTIVE (override) record, not the ORIGINAL base record."
        )
        for contract in dual_record_contracts:
            vnames = contract_mappings.get(contract, [])
            context_lines.append(f"- Contract: {contract}")
            context_lines.append(f"  Parallel mappings: {', '.join(vnames)}")

    if claim_fns:
        context_lines.append("\n# Claim / Withdraw / Redeem Functions")
        context_lines.append("WARNING Verify these check for expired/cancelled/terminal state BEFORE distributing assets:")
        for fn_id in sorted(claim_fns)[:10]:
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[flags: {data.get('flags',[])}]"
            )

    # Protocol invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Protocol Invariants")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines) if context_lines else "No state machine patterns detected."

    # ── Step 4: Source code ──────────────────────────────────────────────
    priority_order = (
        list(dual_record_fns) +
        list(transition_fns) +
        list(pause_fns) +
        list(claim_fns)
    )
    seen: set[str] = set()
    all_fns = [fn_id for fn_id in priority_order if not (fn_id in seen or seen.add(fn_id))]

    if not all_fns and not state_vars:
        if verbose:
            print("  ℹ️  StateMachineHunter: No state machine patterns found")
        return []

    source = get_source_for_functions(sg, all_fns[:15], max_chars=10_000)

    if verbose:
        print(
            f"   StateMachineHunter: {len(state_vars)} state vars, "
            f"{len(transition_fns)} transition fns, "
            f"{len(dual_record_contracts)} TOCTOU dual-record contracts, "
            f"{len(pause_fns)} pause fns"
        )

    return call_hunter(
        hunter_name="StateMachineHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
        include_methodology=True,
        rag_query=(
            "state machine TOCTOU time-of-check-time-of-use enum transition "
            "lifecycle pause bypass timestamp off-by-one campaign override "
            "original vs effective record wrong state anchor"
        ),
        vulnerability_type="logic",
    )
