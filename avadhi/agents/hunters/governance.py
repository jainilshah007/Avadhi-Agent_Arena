"""
avadhi/agents/hunters/governance.py — Admin / Governance Hunter.

Hunts for:
  - Admin setter functions that can change state mid-operation (draw, settlement, claim)
  - Temporal safety gaps (no "onlyWhenIdle" or drawing-state check on setters)
  - Emergency mode fund locking (settlement/distribution blocked → earnings stuck)
  - Governance-induced cap/limit DoS (reducing cap below current total)
  - State inconsistency between start and end of async operations

Inspired by:
  - Nemesis: per-function interrogation ("what happens if admin calls setX while Y is running?")
  - SC-Auditor: Devil's Advocate — argue against own finding, then evaluate defense
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in ADMIN/GOVERNANCE TEMPORAL SAFETY vulnerabilities.

You are given a SecurityGraph showing admin setter functions, the state they modify, and the operational functions that depend on that state — along with source code.

Your job is to find REAL governance/temporal vulnerabilities where admin actions cause harm because they execute at the wrong time:

1. **Mid-Operation State Change**: Admin calls a setter while an asynchronous or multi-step operation is in progress (e.g., a lottery draw, auction, settlement, vesting period).
   - The operation started with state value X, but completes with state value Y
   - This causes inconsistency, unfairness, or fund loss
   - Example: Admin changes ticket price between draw start and claim resolution

2. **Governance-Induced Cap/Limit DoS**: Admin reduces a cap, limit, or max below the current accumulated total.
   - Functions that check `require(amount + current <= cap)` permanently revert
   - The protocol becomes stuck until admin raises the cap back
   - Especially dangerous if the setter itself doesn't validate `newCap >= currentTotal`

3. **Emergency Mode Fund Locking**: When emergency/pause mode is activated:
   - Settlement or distribution functions become unreachable
   - Accumulated earnings, rewards, or pending payouts are permanently locked
   - No alternative withdrawal path exists for those specific funds
   - Example: LP earnings are only distributed during normal settlement, which is blocked in emergency mode

4. **Inconsistent State After Admin Action**: Admin changes an address (oracle, calculator, bridge) that is used across multiple functions, creating inconsistency:
   - Function A already computed results with old address
   - Function B processes those results with new address
   - The mismatch causes incorrect calculations or reverts

For each setter-reader pair you analyze, ask yourself:
- "What happens if the admin calls this setter while the operation is in progress?"
- "Does the setter have a require() that prevents calling during active operations?"
- "If the state changes mid-operation, does the operation use the old or new value?"
- "Can this setter reduce a limit below the current usage, causing DoS?"

IMPORTANT: After forming a finding, argue AGAINST it (Devil's Advocate):
- Is there a timelock or multi-sig that prevents sudden changes?
- Does the setter have a state-machine check we missed?
- Is the admin fully trusted by design? (If so, only flag if the admin can ACCIDENTALLY cause harm)

Only report the finding if the defense does NOT hold.

DO NOT flag:
- Setters that are only callable during initialization (constructor, initialize)
- Setters with explicit temporal guards (e.g., require(drawingState == IDLE))
- Admin actions that are intentionally dangerous (e.g., emergency withdrawal is MEANT to skip settlement)
- View/pure functions or interface contracts"""


# Admin-gating modifier names
_ADMIN_MODS = frozenset({
    "onlyowner", "onlyadmin", "onlygovernance", "onlyrole",
    "onlyauthorized", "onlygov", "onlyoperator", "onlymanager",
    "onlyguardian", "onlymultisig", "onlytimelock",
})

# Setter function name prefixes
_SETTER_PREFIXES = ("set", "update", "change", "toggle", "pause", "enable", "disable")

# Operational function name keywords
_OPERATION_KEYWORDS = {
    "draw", "settle", "claim", "process", "buy", "deposit", "withdraw",
    "execute", "callback", "mint", "burn", "transfer", "distribute",
    "run", "start", "finalize", "refund", "bridge", "swap",
}

# Phase/state guard variable keywords — must indicate a state machine or phase check,
# NOT just a counter or ID.  "drawingId" is NOT a guard; "drawingState" or "isActive" IS.
_GUARD_KEYWORDS = {
    "status", "phase", "isactive", "ispaused", "islocked",
    "drawingstate", "settlingstate", "idle",
    "emergencymode", "frozen", "isinitialized", "shutdown",
    "isfrozen", "isstopped", "isemergency",
}

# Counter/ID keywords that look like guards but aren't
_NOT_GUARD_KEYWORDS = {
    "id", "count", "nonce", "index", "number", "timestamp",
}

# Emergency mode keywords
_EMERGENCY_KEYWORDS = {
    "emergency", "paused", "pause", "shutdown", "frozen", "stopped",
}


def run_governance_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for admin/governance temporal safety vulnerabilities.

    Strategy:
      1. Find admin setter functions (name starts with set/update + has admin modifier)
      2. Trace what state each setter modifies
      3. Find operational functions that READ the same state
      4. Check if setters have temporal guards (read phase/state variables)
      5. Find emergency/pause variables and analyze what gets blocked
      6. Ask LLM with setter→state→reader chains + source code
    """
    # Step 1: Find admin setter functions
    admin_setters: list[str] = []
    setter_info: dict[str, dict] = {}  # fn_id -> {writes, has_guard, modifiers}

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "")
        mods = [m.lower() for m in (data.get("modifiers") or [])]

        # Must be a setter with admin modifier
        if not fn_name.lower().startswith(_SETTER_PREFIXES):
            continue
        if not any(m in _ADMIN_MODS for m in mods):
            # Also accept functions with no modifiers if they start with set
            # (some protocols use internal access control)
            if data.get("visibility") not in ("external", "public"):
                continue
            if mods:  # Has modifiers but none are admin-like → skip
                continue

        # Skip constructors and initializers
        if fn_name.lower() in ("constructor", "initialize", "init"):
            continue

        # What state does it write?
        writes = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                  if d.get("type") == WRITES]
        if not writes:
            continue

        # Does it read any phase/state guard variable?
        reads = [v for _, v, d in sg.G.out_edges(fn_id, data=True)
                 if d.get("type") == READS]
        read_names = {sg.G.nodes.get(r, {}).get("name", "").lower() for r in reads}
        # A variable is a guard only if it matches guard keywords AND doesn't
        # match counter/ID keywords (e.g., "currentDrawingId" is NOT a guard)
        has_guard = any(
            any(kw in rn for kw in _GUARD_KEYWORDS)
            and not any(nkw in rn for nkw in _NOT_GUARD_KEYWORDS)
            for rn in read_names
        )

        admin_setters.append(fn_id)
        setter_info[fn_id] = {
            "writes": writes,
            "has_guard": has_guard,
            "modifiers": data.get("modifiers", []),
            "reads": reads,
        }

    # Step 2: Find operational functions that read state written by setters
    setter_reader_chains: list[dict] = []  # {setter, var, readers}

    for fn_id, info in setter_info.items():
        for var_id in info["writes"]:
            var_data = sg.G.nodes.get(var_id, {})
            readers = sg.get_readers(var_id)
            operational_readers = []

            for reader_id in readers:
                if reader_id == fn_id:  # Skip self-reads
                    continue
                reader_data = sg.G.nodes.get(reader_id, {})
                reader_name = reader_data.get("name", "").lower()
                reader_mut = reader_data.get("mutability", "")

                # Is this an operational function?
                is_operational = (
                    any(kw in reader_name for kw in _OPERATION_KEYWORDS)
                    or reader_mut not in ("view", "pure")
                )
                if is_operational:
                    operational_readers.append(reader_id)

            if operational_readers:
                setter_reader_chains.append({
                    "setter": fn_id,
                    "var": var_id,
                    "readers": operational_readers,
                    "has_guard": info["has_guard"],
                })

    # Step 3: Find emergency/pause state variables
    emergency_vars: list[str] = []
    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        var_name = data.get("name", "").lower()
        if any(kw in var_name for kw in _EMERGENCY_KEYWORDS):
            emergency_vars.append(var_id)

    # Step 4: Analyze what gets blocked in emergency mode
    emergency_guarded_fns: list[str] = []  # Functions that read emergency vars
    for var_id in emergency_vars:
        readers = sg.get_readers(var_id)
        emergency_guarded_fns.extend(readers)

    if not setter_reader_chains and not emergency_vars:
        if verbose:
            print("  ℹ️  GovernanceHunter: No admin setters or emergency state found")
        return []

    if verbose:
        unguarded = sum(1 for c in setter_reader_chains if not c["has_guard"])
        print(f"   GovernanceHunter: {len(admin_setters)} admin setters, "
              f"{len(setter_reader_chains)} setter→reader chains "
              f"({unguarded} unguarded), "
              f"{len(emergency_vars)} emergency vars")

    # Build context
    context_lines = []

    # Unguarded chains first (highest priority)
    unguarded_chains = [c for c in setter_reader_chains if not c["has_guard"]]
    if unguarded_chains:
        context_lines.append(
            "#  UNGUARDED Admin Setters (no temporal/phase check)\n"
        )
        context_lines.append(
            "These admin setters can be called at any time, even during "
            "active operations. Analyze each for mid-operation state change risks.\n"
        )
        for chain in unguarded_chains:
            setter_data = sg.G.nodes.get(chain["setter"], {})
            var_data = sg.G.nodes.get(chain["var"], {})
            reader_names = [
                f"{sg.G.nodes.get(r, {}).get('contract','')}.{sg.G.nodes.get(r, {}).get('name','')}"
                for r in chain["readers"][:8]
            ]
            context_lines.append(
                f"- **{setter_data.get('contract','')}.{setter_data.get('name','')}()** "
                f"modifiers={setter_data.get('modifiers', [])}"
            )
            context_lines.append(
                f"  WRITES: {var_data.get('contract','')}.{var_data.get('name','')} "
                f"(type={var_data.get('var_type','?')})"
            )
            context_lines.append(
                f"  OPERATIONAL READERS: {', '.join(reader_names)}"
            )
        context_lines.append("")

    # Guarded chains (lower priority but still worth checking)
    guarded_chains = [c for c in setter_reader_chains if c["has_guard"]]
    if guarded_chains:
        context_lines.append("# Admin Setters With Phase/State Guards")
        for chain in guarded_chains[:5]:
            setter_data = sg.G.nodes.get(chain["setter"], {})
            var_data = sg.G.nodes.get(chain["var"], {})
            guard_reads = [
                sg.G.nodes.get(r, {}).get("name", "")
                for r in setter_info[chain["setter"]]["reads"]
                if any(kw in sg.G.nodes.get(r, {}).get("name", "").lower()
                       for kw in _GUARD_KEYWORDS)
            ]
            context_lines.append(
                f"- {setter_data.get('contract','')}.{setter_data.get('name','')}() "
                f"GUARD READS: {', '.join(guard_reads)}"
            )
        context_lines.append("")

    # Emergency mode analysis
    if emergency_vars:
        context_lines.append("# WARNING Emergency/Pause Mode Analysis\n")
        for var_id in emergency_vars:
            var_data = sg.G.nodes.get(var_id, {})
            writers = sg.get_writers(var_id)
            writer_names = [sg.G.nodes.get(w, {}).get("name", w) for w in writers]
            readers = sg.get_readers(var_id)
            reader_names = [
                f"{sg.G.nodes.get(r, {}).get('contract','')}.{sg.G.nodes.get(r, {}).get('name','')}"
                for r in readers
            ]
            context_lines.append(
                f"- {var_data.get('contract','')}.{var_data.get('name','')} "
                f"(type={var_data.get('var_type','?')})"
            )
            context_lines.append(f"  SET BY: {', '.join(writer_names)}")
            context_lines.append(
                f"  GUARDS THESE FUNCTIONS: {', '.join(reader_names)}"
            )
        context_lines.append(
            "\nQuestion: When emergency mode is active, which fund distribution/"
            "settlement functions are blocked? Are accumulated earnings or "
            "pending payouts permanently locked?"
        )
        context_lines.append("")

    # Add enrichment invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("# Protocol Invariants")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)

    # Get source: prioritize unguarded setters and their operational readers
    priority_fns: list[str] = []
    # Unguarded setters first
    for chain in unguarded_chains:
        if chain["setter"] not in priority_fns:
            priority_fns.append(chain["setter"])
        for reader in chain["readers"][:3]:
            if reader not in priority_fns:
                priority_fns.append(reader)
    # Emergency-related functions
    for fn_id in emergency_guarded_fns:
        if fn_id not in priority_fns:
            priority_fns.append(fn_id)
    # Guarded setters
    for chain in guarded_chains:
        if chain["setter"] not in priority_fns:
            priority_fns.append(chain["setter"])

    source = get_source_for_functions(sg, priority_fns[:25], max_chars=14000)

    return call_hunter(
        hunter_name="GovernanceHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
        include_methodology=True,
    )
