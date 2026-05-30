"""
avadhi/agents/hunters/accounting.py — Accounting / Math Hunter.

Hunts for:
  - Invariant violations (balance >= withdrawable, shares ↔ assets consistency)
  - Rounding direction errors (must round against user in protocol's favor)
  - Precision loss from integer division ordering
  - Pool cap / limit enforcement gaps
  - Share price manipulation (first-depositor, donation attacks)
  - Coupled state variables updated in different code paths
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in ACCOUNTING and MATHEMATICAL vulnerabilities.

You are given a SecurityGraph view showing functions that read and write financial state variables, along with the source code.

Your job is to find REAL accounting/math vulnerabilities:

1. **Invariant Violations**: Protocol invariants that can be broken.
   - Example: `totalDeposited >= totalWithdrawn` can be violated if a settlement
     function doesn't enforce caps before updating balances.
   - Example: `shares * pricePerShare == underlyingBalance` breaks after rounding.
   - Look for state variables that represent paired quantities (pool total vs cap,
     deposits vs withdrawals, shares vs assets) and check if ALL code paths maintain
     the relationship.

2. **Rounding Direction Errors**: Integer division rounds DOWN in Solidity.
   - Deposits should round DOWN (user gets fewer shares)
   - Withdrawals should round UP (user gets less underlying)
   - If reversed, an attacker can extract dust per transaction, multiplied across
     many txs or flash-loaned amounts.

3. **Precision Loss**: Division before multiplication loses precision.
   - `(a / b) * c` loses precision vs `(a * c) / b`
   - Especially dangerous with large amounts and small divisors.

4. **Pool Cap / Limit Bypass**: Functions that add to a pool without checking the cap,
   or that check the cap BEFORE adding but not AFTER.

5. **Share Price Manipulation**: First depositor can inflate share price by donating
   to the vault. Subsequent depositors get 0 shares due to rounding.

6. **Coupled Variable Desync**: Two state variables that must stay in sync
   (e.g., `balance` and `checkpoint`) but are updated in different functions or
   different branches of the same function.

7. **Governance-Induced Cap/Limit DoS**: An admin setter reduces a cap or limit
   below the current accumulated total. Functions that check `require(amount + current <= cap)`
   permanently revert. The protocol becomes stuck. Look at the cap analysis below —
   if a cap setter does NOT validate `newCap >= currentTotal`, this is a real issue.

For each finding:
- Specify the EXACT invariant that is violated
- Show the code path that violates it (function A does X, then function B does Y)
- Quantify the impact (how much can be stolen/lost)

DO NOT flag:
- View/pure functions
- Theoretical precision loss that amounts to less than 1 wei
- Interface-only contracts"""


def run_accounting_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for accounting/math vulnerabilities.

    Strategy:
      1. Find state variables that look financial (balance, total, pool, shares, cap, etc.)
      2. Find ALL functions that write to these variables
      3. Look for coupled variables (multiple vars written together vs separately)
      4. Ask LLM with source code of all writers
    """
    # Step 1: Find financial state variables
    financial_keywords = {
        "balance", "total", "pool", "cap", "share", "deposit", "withdraw",
        "reserve", "fee", "earnings", "reward", "stake", "supply",
        "debt", "credit", "price",
        "accumulated", "accumulator", "payout", "vault", "treasury",
    }

    financial_vars: list[str] = []
    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        if data.get("is_constant") or data.get("is_immutable"):
            continue
        var_name = data.get("name", "").lower()
        if any(kw in var_name for kw in financial_keywords):
            financial_vars.append(var_id)

    if not financial_vars:
        if verbose:
            print("  ℹ️  AccountingHunter: No financial state variables found")
        return []

    # Step 2: Find all writers to financial state
    writer_fns: set[str] = set()
    var_writers: dict[str, list[str]] = {}  # var_id -> [fn_ids]
    for var_id in financial_vars:
        writers = sg.get_writers(var_id)
        var_writers[var_id] = writers
        writer_fns.update(writers)

    # Also include functions that READ financial vars (for invariant checking)
    reader_fns: set[str] = set()
    for var_id in financial_vars:
        readers = sg.get_readers(var_id)
        reader_fns.update(readers)

    # Step 3: Identify coupled variables (written together in some functions but not all)
    fn_write_sets: dict[str, set[str]] = {}  # fn_id -> set of var_ids it writes
    for var_id, writers in var_writers.items():
        for fn_id in writers:
            fn_write_sets.setdefault(fn_id, set()).add(var_id)

    if not writer_fns:
        if verbose:
            print("  ℹ️  AccountingHunter: No functions write financial state")
        return []

    if verbose:
        print(f"   AccountingHunter: {len(financial_vars)} financial vars, "
              f"{len(writer_fns)} writer functions")

    # Build context — only show vars that have writers (read-only vars are noise)
    context_lines = ["# Financial State Variables (with writers)\n"]
    for var_id in financial_vars:
        writers = var_writers.get(var_id, [])
        if not writers:
            continue
        data = sg.G.nodes.get(var_id, {})
        writer_names = [sg.G.nodes.get(w, {}).get("name", w) for w in writers]
        context_lines.append(
            f"- {data.get('contract','')}.{data.get('name','')} "
            f"(type={data.get('var_type','?')})"
        )
        context_lines.append(f"  WRITERS: {', '.join(writer_names)}")

    # Show coupled variable groups
    context_lines.append("\n# Functions That Write Multiple Financial Vars")
    for fn_id, var_set in sorted(fn_write_sets.items(), key=lambda x: -len(x[1])):
        if len(var_set) >= 2:
            fn_data = sg.G.nodes.get(fn_id, {})
            var_names = [sg.G.nodes.get(v, {}).get("name", v) for v in var_set]
            context_lines.append(
                f"- {fn_data.get('contract','')}.{fn_data.get('name','')}() "
                f"writes: {', '.join(var_names)}"
            )

    # Highlight cap/limit variables and their enforcement (or lack thereof)
    cap_vars = [v for v in financial_vars
                if any(kw in sg.G.nodes.get(v, {}).get("name", "").lower()
                       for kw in ("cap", "limit", "max", "min", "ceiling", "floor"))]
    if cap_vars:
        context_lines.append("\n# WARNING Cap/Limit Variables (check enforcement)")
        for var_id in cap_vars:
            data = sg.G.nodes.get(var_id, {})
            cap_contract = data.get("contract", "")
            readers = sg.get_readers(var_id)
            reader_names = [sg.G.nodes.get(r, {}).get("name", r) for r in readers]
            writers = sg.get_writers(var_id)
            writer_names = [sg.G.nodes.get(w, {}).get("name", w) for w in writers]
            context_lines.append(
                f"- {cap_contract}.{data.get('name','')} "
                f"(type={data.get('var_type','?')})"
            )
            context_lines.append(f"  SET BY: {', '.join(writer_names)}")
            context_lines.append(f"  CHECKED BY: {', '.join(reader_names)}")
            # Key question: which writers of RELATED pool/total variables in the
            # same contract DON'T read this cap?  (Focused analysis — only look at
            # the contract this cap belongs to, not all contracts.)
            same_contract_vars = [
                v for v in financial_vars
                if sg.G.nodes.get(v, {}).get("contract", "") == cap_contract
                and v != var_id
            ]
            related_writers: set[str] = set()
            for fv in same_contract_vars:
                related_writers.update(sg.get_writers(fv))
            unchecked = related_writers - set(readers)
            if unchecked:
                unchecked_names = [
                    f"{sg.G.nodes.get(u, {}).get('contract','')}.{sg.G.nodes.get(u, {}).get('name', u)}"
                    for u in unchecked
                ]
                context_lines.append(
                    f"  FAILED SAME-CONTRACT WRITERS THAT DON'T CHECK THIS CAP: "
                    f"{', '.join(unchecked_names)}"
                )

    # Add enrichment invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Protocol Invariants (from enrichment)")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines)

    # Get source: prioritize functions most likely to have accounting bugs.
    # Score: multi-var writers get base score; settlement/process/batch names
    # get a boost; functions that write pool-related vars but DON'T read any
    # cap get the highest priority (potential cap bypass).
    cap_reader_set: set[str] = set()
    for var_id in cap_vars:
        cap_reader_set.update(sg.get_readers(var_id))

    settlement_keywords = {
        "settle", "process", "distribute", "batch", "finalize", "draw",
        "claim", "withdraw", "deposit", "transfer", "callback",
    }

    def _fn_priority(fn_id: str) -> int:
        """Higher = more interesting for accounting analysis."""
        node = sg.G.nodes.get(fn_id, {})
        score = len(fn_write_sets.get(fn_id, set()))
        fn_name = node.get("name", "").lower()
        # Boost settlement-type functions
        if any(kw in fn_name for kw in settlement_keywords):
            score += 5
        # Highest priority: writes pool/total vars but doesn't read any cap
        if fn_id not in cap_reader_set and fn_write_sets.get(fn_id):
            written_var_names = {
                sg.G.nodes.get(v, {}).get("name", "").lower()
                for v in fn_write_sets.get(fn_id, set())
            }
            pool_related = {"pool", "total", "accumulator", "balance", "lp"}
            if any(kw in vn for vn in written_var_names for kw in pool_related):
                score += 10
        # Skip constructors (noisy, usually not buggy)
        if fn_name == "constructor":
            score -= 20
        return score

    sorted_fns = sorted(writer_fns, key=_fn_priority, reverse=True)
    # Also include cap readers (to show how cap IS enforced for comparison)
    all_fns = list(dict.fromkeys(sorted_fns + list(cap_reader_set)))
    source = get_source_for_functions(sg, all_fns[:15], max_chars=10000)

    return call_hunter(
        hunter_name="AccountingHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
    )
