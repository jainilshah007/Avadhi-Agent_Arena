"""
avadhi/agents/hunters/callback.py — Callback & Error-Handling Hunter.

Hunts for:
  - try/catch asymmetry: revert INSIDE try-success handler is NOT caught by catch
  - Silent error swallowing: empty catch{} block hides ALL external call failures
  - Incorrect magic-value checking: IClaimRecipient.onClaim selector checked
    inside try (propagates as uncaught revert) instead of inside catch
  - ERC-777 tokensReceived / ERC-1155 onReceived reentrancy paths
  - onClaim / onFlashLoan / onReceive callbacks that can be abused by
    malicious recipients to DoS or reenter the calling contract
  - Missing return value checks on external calls that don't revert on failure
    (e.g. ERC-20 transfer() returns bool, not all tokens revert on false)
"""
from __future__ import annotations

from avadhi.core.graph import SecurityGraph, FUNCTION, CALLS
from avadhi.core.schemas import Hypothesis
from avadhi.agents.hunters.base import call_hunter, get_source_for_functions
from avadhi.utils.logging import AuditLogger


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in CALLBACK and ERROR-HANDLING vulnerabilities.

You are given a SecurityGraph showing functions that make external calls, use try/catch, or implement callback interfaces, along with their source code.

Your job is to find REAL callback and error-handling vulnerabilities. Focus on these specific high-value patterns:

## 1. try/catch Asymmetry (CRITICAL PATTERN — Merkl M-02 class)

In Solidity, `try/catch` ONLY catches reverts from the external call itself.
A revert that happens INSIDE the try-success handler is NOT caught and propagates normally.

```solidity
// VULNERABLE
try recipient.onClaim(msg.sender, amount) returns (bytes4 magic) {
    // ↓ This revert is INSIDE try-success — NOT caught by catch!
    if (magic != IClaimRecipient.onClaim.selector) revert InvalidCallback();
} catch {
    // Only catches external call reverts, NOT the revert above
}
```

**Attack vector**: A malicious `onClaim` implementer can intentionally return a wrong magic value,
causing the `revert InvalidCallback()` to propagate uncaught, atomically reverting the entire
claim batch and undoing all token transfers.

**Conversely**: A reverting `onClaim` is swallowed by `catch {}`, allowing recipients to bypass
post-claim logic (audit hooks, state updates).

Hunt for: any `try {} catch {}` where:
(a) There is a validation (if/require/revert) INSIDE the try-success block, OR
(b) The catch body is empty `{}` — this silently swallows ALL errors from the external call.

## 2. Silent Error Swallowing
```solidity
try externalContract.callback(data) {} catch {}  // EMPTY catch — hides EVERYTHING
```
If the callback is supposed to enforce a post-condition or hook, silently swallowing means
the post-condition is never enforced.

## 3. Callback-Based DoS
An external callback (onClaim, onReceive, onFlashLoan) can be used to create DOS:
- Malicious recipient's callback always reverts → caller cannot process that user
- Malicious recipient's callback runs out of gas → impacts all users in a batch

Hunt for: functions that call external callbacks inside loops or batch operations.
If one callback reverts and is NOT caught, the entire batch fails.

## 4. ERC-777 / ERC-1155 Reentrancy
```solidity
function deposit(uint amount) external {
    token.transferFrom(msg.sender, address(this), amount);  // ← ERC-777 calls tokensReceived
    balances[msg.sender] += amount;  // ← state update AFTER external call → reentrancy
}
```
Hunt for: balance/state updates that happen AFTER a token transfer where the token
could be ERC-777 (has tokensReceived hook).

## 5. Unchecked Return Values
```solidity
token.transfer(recipient, amount);  // ← non-reverting ERC-20 returns false on failure!
```
Some tokens (USDT, BNB) don't revert on failed transfer — they return `false`.
If the return value isn't checked, failed transfers are silently ignored.

## 6. Cross-Contract State Inconsistency via Callback
A callback fired mid-function can observe inconsistent contract state:
```solidity
balances[user] = 0;          // ← state changed
token.transfer(user, amt);    // ← callback fired here can re-enter with stale state
// Other state changes below...
```

## For each finding:
- Show the try/catch structure or callback pattern precisely
- Explain EXACTLY which errors are caught vs. propagated
- Describe the attack: what does a malicious callback implementer do?
- Describe the impact: what gets reverted / bypassed / reentered?

DO NOT flag:
- Calls to trusted protocol-owned contracts (no external recipient)
- View/pure functions
- Interface-only contracts"""


# Callback interface names that indicate external callback patterns
_CALLBACK_INTERFACES = {
    "iclaimrecipient", "iflashloanreceiver", "iuniswapv2callee", "iuniswapv3swapcallback",
    "iaavev3flashloan", "ierc777recipient", "ierc1155receiver", "ierc721receiver",
    "icallback", "ionreceive", "ionclaim", "ionflashloan",
}

_CALLBACK_FUNCTION_NAMES = {
    "onclaim", "onreceive", "onflashloan", "tokensfallback", "tokensreceived",
    "onerc721received", "onerc1155received", "onerc1155batchreceived",
    "uniswapv2call", "uniswapv3swapcallback", "pancakeswapv2call",
    "execute", "callbackfunction",
}

_TRY_CATCH_SIGNALS = {
    "try", "catch",  # Presence in source text
}


def run_callback_hunter(
    sg: SecurityGraph,
    logger: AuditLogger | None = None,
    verbose: bool = False,
    cross_feed_context: str | None = None,
) -> list[Hypothesis]:
    """
    Hunt for callback and error-handling vulnerabilities.

    Strategy:
      1. Find functions that make external calls to external/untrusted recipients
      2. Identify try/catch patterns (from flags or function name heuristics)
      3. Find functions that implement callback interfaces
      4. Find batch/loop functions with external calls
      5. Ask LLM with source of all relevant functions
    """
    # ── Step 1: Find external call functions ────────────────────────────────
    external_call_fns: set[str] = set()
    callback_impl_fns: set[str] = set()
    batch_loop_fns: set[str] = set()
    try_catch_fns: set[str] = set()

    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        flags = [f.lower() for f in data.get("flags", [])]
        contract = data.get("contract", "").lower()

        # Functions that implement callback interfaces
        if any(cb in fn_name for cb in _CALLBACK_FUNCTION_NAMES):
            callback_impl_fns.add(fn_id)

        # Batch / loop functions (high risk: one failing callback kills the batch)
        if any(bk in fn_name for bk in ("batch", "loop", "multi", "bulk", "all", "claim")):
            batch_loop_fns.add(fn_id)

        # External calls: flag-based detection
        if any(f in flags for f in ("external_call", "low_level_call", "send", "transfer")):
            external_call_fns.add(fn_id)

        # Look for functions that call other untrusted functions
        for _, neighbor, edata in sg.G.out_edges(fn_id, data=True):
            if edata.get("edge_type") == CALLS:
                callee = sg.G.nodes.get(neighbor, {})
                callee_name = callee.get("name", "").lower()
                # External callback calls
                if any(cb in callee_name for cb in _CALLBACK_FUNCTION_NAMES):
                    external_call_fns.add(fn_id)
                    try_catch_fns.add(fn_id)  # likely uses try/catch to isolate
                # Transfer / approval calls (potential ERC-777)
                if callee_name in ("transfer", "transferfrom", "safetransfer", "safetransferfrom"):
                    external_call_fns.add(fn_id)

    # Also capture functions with "claim" or "distribute" in name — high value
    claim_fns: set[str] = set()
    for fn_id, data in sg.get_nodes_by_type(FUNCTION):
        fn_name = data.get("name", "").lower()
        if any(kw in fn_name for kw in ("claim", "distribute", "payout", "withdraw", "redeem")):
            claim_fns.add(fn_id)

    # ── Step 2: Build context ────────────────────────────────────────────────
    context_lines = []

    if external_call_fns or try_catch_fns:
        context_lines.append("# External Call / Callback Functions")
        for fn_id in sorted(external_call_fns | try_catch_fns)[:25]:
            data = sg.G.nodes.get(fn_id, {})
            callees = [
                sg.G.nodes.get(n, {}).get("name", "")
                for _, n, ed in sg.G.out_edges(fn_id, data=True)
                if ed.get("edge_type") == CALLS
            ]
            flags = data.get("flags", [])
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"flags={flags} "
                f"calls=[{', '.join(callees[:8])}]"
            )

    if callback_impl_fns:
        context_lines.append("\n# Callback Implementations (onClaim, onReceive, etc.)")
        context_lines.append("These functions are called BY EXTERNAL contracts. Check for reentrancy.")
        for fn_id in sorted(callback_impl_fns):
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {data.get('modifiers',[])}]"
            )

    if batch_loop_fns:
        context_lines.append(
            "\n# WARNING Batch/Loop Functions — Single Callback Failure Can DoS Entire Batch"
        )
        for fn_id in sorted(batch_loop_fns):
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}()"
            )

    if claim_fns:
        context_lines.append("\n# Claim / Distribution Functions")
        context_lines.append(
            "These are the highest-value targets for try/catch asymmetry analysis."
        )
        for fn_id in sorted(claim_fns):
            data = sg.G.nodes.get(fn_id, {})
            context_lines.append(
                f"- {data.get('contract','')}.{data.get('name','')}() "
                f"[modifiers: {data.get('modifiers',[])}]"
            )

    # Add invariants
    invariants = sg.metadata.get("invariants", [])
    if invariants:
        context_lines.append("\n# Protocol Invariants")
        for inv in invariants:
            context_lines.append(f"- {inv}")

    context = "\n".join(context_lines) if context_lines else "No external call / callback functions detected."

    # ── Step 3: Get source code ─────────────────────────────────────────────
    # Priority: claim fns > batch fns > try/catch fns > callback impls > external calls
    priority_order = (
        list(claim_fns) +
        list(batch_loop_fns) +
        list(try_catch_fns) +
        list(callback_impl_fns) +
        list(external_call_fns)
    )
    seen: set[str] = set()
    all_fns = [fn_id for fn_id in priority_order if not (fn_id in seen or seen.add(fn_id))]

    total = len(all_fns)
    if total == 0:
        if verbose:
            print("  ℹ️  CallbackHunter: No callback/external-call functions found")
        return []

    if verbose:
        print(
            f"   CallbackHunter: {len(external_call_fns)} external call fns, "
            f"{len(claim_fns)} claim fns, "
            f"{len(batch_loop_fns)} batch fns, "
            f"{len(callback_impl_fns)} callback impls"
        )

    source = get_source_for_functions(sg, all_fns[:15], max_chars=10_000)

    return call_hunter(
        hunter_name="CallbackHunter",
        system_prompt=SYSTEM_PROMPT,
        context=context,
        source_snippets=source,
        logger=logger,
        verbose=verbose,
        cross_feed_context=cross_feed_context,
        sg=sg,
        include_methodology=True,
        rag_query=(
            "try catch asymmetry external callback onClaim error handling "
            "silent swallow revert inside try success handler magic value selector"
        ),
        vulnerability_type="external_call",
    )
