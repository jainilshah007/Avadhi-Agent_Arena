"""
avadhi/agents/hunters/metatx.py — Meta-Transaction & EIP-2771 Hunter.

Hunts for:
  - EIP-2771 trusted forwarder spoofing: _msgSender() can be hijacked when
    a contract trusts an attacker-controlled forwarder address
  - Multicall + _msgSender() bypass: batch calls where msg.sender is the
    router/aggregator, not the original caller
  - tx.origin vs msg.sender confusion in access control
  - Forwarder address mutability: if trustedForwarder can be changed, an attacker
    may set it to a contract that injects arbitrary _msgSender values
  - Missing ERC2771Context: contract uses _msgSender() but does not properly
    inherit from a battle-tested ERC2771Context implementation
  - Permit2 / EIP-712 integrations where the relayer can substitute signer

ClaraHacks Incident Reference:
  - 2024: Multiple protocols exploited via EIP-2771 + Multicall combo
    (Gelato relayer, Biconomy forwarder) — $40M+ total losses
  - Root cause: trustedForwarder treated _msgSender() as authenticated sender,
    but attacker could forge the appended bytes via malicious calldata
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, STATE_VAR, WRITES, READS, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in META-TRANSACTION and EIP-2771 vulnerabilities.

You are given a SecurityGraph view showing functions that use _msgSender(), trustedForwarder patterns, meta-transaction relayers, and ERC2771 context, along with their source code.

Your job is to find REAL meta-transaction and sender-spoofing vulnerabilities:

## 1. EIP-2771 Trusted Forwarder Spoofing (CRITICAL)
Contracts using `_msgSender()` instead of `msg.sender` extract the real sender from the LAST 20 bytes of calldata when called by the trustedForwarder. An attacker can:
- Set themselves as the trustedForwarder (if it's mutable without proper access control)
- Craft arbitrary calldata where the last 20 bytes are a victim address
- Call the contract through their malicious "forwarder"
- The contract reads the injected victim address as `_msgSender()`

```solidity
// VULNERABLE: _msgSender returns last 20 bytes when called by trustedForwarder
function withdraw(uint amount) external {
    address user = _msgSender();  // ← can be spoofed!
    balances[user] -= amount;
    token.transfer(user, amount);
}
```

Hunt for:
- Contracts with `trustedForwarder` that can be set by non-privileged users
- `_msgSender()` used in privileged functions (withdraw, claim, transfer ownership)
- `isTrustedForwarder()` or `trustedForwarder` state variable with a mutable setter
- OpenGSN / Biconomy / Gelato relayer integration patterns

## 2. Multicall + msg.sender Confusion
When a contract implements multicall/batch operations, `msg.sender` inside each sub-call is the AGGREGATOR contract, not the original user. If the aggregator is treated as trusted/privileged:

```solidity
// VULNERABLE: multicall makes msg.sender == address(this) for sub-calls
function multicall(bytes[] calldata data) external {
    for (uint i; i < data.length; i++) {
        (bool ok,) = address(this).delegatecall(data[i]);  // ← msg.sender changes!
    }
}
function privilegedAction() internal {
    require(msg.sender == owner);  // ← now msg.sender is the contract itself!
}
```

Hunt for:
- `delegatecall(data[i])` or `address(this).call(data[i])` loops where `msg.sender` inside changes
- Functions that check `msg.sender == address(this)` as an access control
- Patterns where a router/aggregator is added to an allowlist/whitelist implicitly

## 3. tx.origin Misuse
Using `tx.origin` for authentication instead of `msg.sender` allows any contract in the call chain to impersonate the EOA that initiated the transaction:

```solidity
// VULNERABLE
require(tx.origin == owner, "not owner");  // ← any contract owner calls can bypass
```

Hunt for: `tx.origin` used in access control, ownership transfer, or fund movement.

## 4. Mutable Forwarder Without Timelock
If `trustedForwarder` can be updated by owner without timelock, a compromised owner key causes immediate risk of _msgSender spoofing across ALL protected functions.

## For each finding:
- Identify the EXACT call path where _msgSender() / msg.sender can be manipulated
- Show which privileged action becomes accessible to an attacker
- Estimate impact: what can the attacker drain/control?

DO NOT flag:
- View/pure functions (no state change)
- Contracts correctly using immutable trustedForwarder set at construction
- Well-implemented ERC2771Context where forwarder is set once and final
- Properly implemented Multicall3 where msg.sender is passed as context, not implicit"""


def run_metatx_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for meta-transaction / EIP-2771 / msg.sender spoofing vulnerabilities.

    Strategy:
      1. Find all functions using _msgSender() or trustedForwarder patterns
      2. Find mutable forwarder setters
      3. Find multicall/delegatecall batch patterns
      4. Find tx.origin usage in access control
      5. Ask LLM with focused source code
    """
    # ── Step 1: Find _msgSender / trustedForwarder patterns ──────────────────
    metatx_keywords = {
        "_msgsender", "msgsender", "trustedforwarder", "istrustedforwarder",
        "isforwarder", "forwarder", "erc2771", "opengsn", "biconomy",
        "gelato", "relayer", "metatransaction", "meta_transaction",
    }
    multicall_keywords = {
        "multicall", "batch", "aggregate", "execute", "dispatch",
        "delegatecall", "multisend",
    }
    txorigin_keywords = {
        "tx.origin", "txorigin",
    }

    metatx_fns: set[str] = set()
    multicall_fns: set[str] = set()
    forwarder_setter_fns: set[str] = set()
    txorigin_fns: set[str] = set()

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        contract_name = data.get("contract", "").lower()
        src = data.get("source", "").lower()

        # _msgSender or forwarder patterns
        if any(kw in fn_name or kw in src for kw in metatx_keywords):
            metatx_fns.add(fn_id)

        # Multicall / batch / delegatecall patterns
        if any(kw in fn_name for kw in multicall_keywords):
            multicall_fns.add(fn_id)

        # Forwarder setter functions (mutable forwarder is the risk)
        if ("forwarder" in fn_name or "trusted" in fn_name) and \
           any(kw in fn_name for kw in {"set", "update", "change", "setTrusted", "setForwarder"}):
            forwarder_setter_fns.add(fn_id)

        # tx.origin usage
        if "tx.origin" in src or "txorigin" in src:
            txorigin_fns.add(fn_id)

    # ── Step 2: Find state variables for trustedForwarder ───────────────────
    forwarder_vars: list[str] = []
    for var_id, data in sg.get_nodes_by_type(STATE_VAR):
        var_name = data.get("name", "").lower()
        if "forwarder" in var_name or "trusted" in var_name:
            mutability = data.get("mutability", "mutable")
            forwarder_vars.append(
                f"{data.get('contract','')}.{data.get('name','')} "
                f"[mutability: {mutability}] [type: {data.get('var_type','')}]"
            )

    # ── Step 3: Check for contracts inheriting ERC2771Context ───────────────
    erc2771_contracts: list[str] = []
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        contract = data.get("contract", "")
        src = data.get("source", "").lower()
        if "erc2771context" in src or "context" in data.get("contract", "").lower():
            if contract not in erc2771_contracts:
                erc2771_contracts.append(contract)

    # ── Step 4: Build context ─────────────────────────────────────────────
    context_lines: list[str] = []

    if metatx_fns:
        context_lines.append("# Functions Using _msgSender() / Forwarder Pattern")
        context_lines.append("WARNING These functions use _msgSender() instead of msg.sender.")
        context_lines.append("If trustedForwarder can be manipulated, _msgSender() is spoofable.")
        for fn_id in sorted(metatx_fns)[:20]:
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[vis: {data.get('visibility','')}] "
                f"[modifiers: {data.get('modifiers',[])}]"
            )

    if forwarder_setter_fns:
        context_lines.append("\n# WARNING Mutable Forwarder Setters (HIGH RISK)")
        context_lines.append("Functions that can change the trustedForwarder — check for timelock/access control:")
        for fn_id in sorted(forwarder_setter_fns):
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {data.get('modifiers',[])}]"
            )

    if forwarder_vars:
        context_lines.append("\n# TrustedForwarder State Variables")
        for v in forwarder_vars[:10]:
            context_lines.append(f"- {v}")

    if multicall_fns:
        context_lines.append("\n# Multicall / Batch / DelegateCall Functions")
        context_lines.append("WARNING msg.sender changes inside delegatecall — check auth logic:")
        for fn_id in sorted(multicall_fns)[:10]:
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[flags: {data.get('flags',[])}]"
            )

    if txorigin_fns:
        context_lines.append("\n# WARNING tx.origin Usage (Potential Auth Bypass)")
        for fn_id in sorted(txorigin_fns)[:10]:
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[vis: {data.get('visibility','')}]"
            )

    if erc2771_contracts:
        context_lines.append("\n# Contracts Using ERC2771Context")
        for c in erc2771_contracts[:10]:
            context_lines.append(f"- {c}")

    # Invariants from Phase 1d
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Protocol Invariants")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines) if context_lines else "No meta-transaction patterns detected."

    # ── Step 5: Source code ───────────────────────────────────────────────
    priority_order = (
        list(forwarder_setter_fns) +
        list(metatx_fns) +
        list(multicall_fns) +
        list(txorigin_fns)
    )
    seen: set[str] = set()
    all_fns = [fn_id for fn_id in priority_order if not (fn_id in seen or seen.add(fn_id))]

    if not all_fns and not forwarder_vars:
        if verbose:
            print("  ℹ️  MetaTxHunter: No meta-transaction patterns found")
        return []

    source = get_source_for_functions(sg, all_fns[:15], max_chars=10_000)

    if verbose:
        print(
            f"   MetaTxHunter: {len(metatx_fns)} _msgSender fns, "
            f"{len(forwarder_setter_fns)} forwarder setters, "
            f"{len(multicall_fns)} multicall fns, "
            f"{len(txorigin_fns)} tx.origin fns"
        )

    return call_hunter(
        hunter_name="MetaTxHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
        include_methodology=True,
        rag_query=(
            "EIP-2771 meta transaction trusted forwarder _msgSender spoofing "
            "multicall delegatecall msg.sender bypass access control tx.origin"
        ),
        vulnerability_type="access_control",
    )
