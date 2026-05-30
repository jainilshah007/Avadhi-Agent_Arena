# Avadhi — Immunefi Bug Bounty Tool Roadmap

> **Goal:** A general-purpose multi-agent system that finds exploitable vulnerabilities
> in arbitrary Solidity codebases at Immunefi-submission quality — meaning each finding
> includes a concrete attack scenario, quantified impact, and a runnable PoC.
>
> The Megapot baseline is a **development benchmark only**. The real target is finding
> Critical/High bugs on live Immunefi protocols that human researchers would submit.

---

## Gap Analysis

### G1: Parser is Wrong Foundation (FIXED partially in Iter 4)

| Problem | Impact |
|---------|--------|
| Regex parser silently drops functions with non-whitelisted modifiers | Miss entire functions (`runJackpot`, etc.) |
| No transitive call graph — writes through internal calls invisible | AccessControlHunter misses delegated state mutators |
| No Slither-first pipeline despite Slither being available | Inferior data quality for all downstream agents |

**Fix:** Slither Python API → SecurityGraph as primary path; regex as fallback only.
Slither gives us: resolved inheritance, transitive state writes, accurate modifier lists,
internal call graph, low/high-level external call extraction.

---

### G2: Only 2 Hunters, Both Incomplete

| Missing Hunter | Immunefi Bug Class | Priority |
|----------------|-------------------|----------|
| `FlashLoanHunter` | Flash loan + price oracle combo attacks | P1 |
| `OracleManipulationHunter` | Spot/TWAP price read w/o validation, single-source oracle | P1 |
| `AccountingHunter` | Share price invariants, rounding direction, dust accumulation | P1 |
| `ReentrancyHunter` (dedicated) | Cross-function, cross-contract reentrancy; CEI violations | P1 |
| `SignatureHunter` | Replay attacks, missing nonces, `abi.encodePacked` collisions | P2 |
| `ProxyHunter` | Storage slot collisions, uninitialized implementation, selfdestruct | P2 |
| `GasHunter` | Unbounded loops, gas-griefing DoS vectors | P2 |
| `MathHunter` | Precision loss, rounding errors, overflow in unchecked blocks | P2 |

---

### G3: No Debate/Critic Agent → Zero Precision

Every hypothesis is auto-confirmed today. On an unknown protocol this means the
report is full of false positives. A security researcher reading 20 findings where
18 are wrong stops trusting the tool entirely.

**Fix:** Critic/Debate agent that challenges each hypothesis and assigns a confidence
verdict (CONFIRMED / CONTESTED / REFUTED). Only CONFIRMED and CONTESTED findings
reach the final report.

---

### G4: No PoC Generation

Immunefi requires a working Foundry test for Critical/High submissions. Without one:
- The finding cannot be submitted as-is
- Manual PoC writing eliminates the tool's value proposition
- Cannot distinguish real bugs from theoretical ones

**Fix:** `PoC Generator` node per finding category — templated Foundry tests that
set up the attack scenario and `assert` the unexpected state change.

---

### G5: Graph is Too Shallow

- No transitive analysis: `buyTickets → _validateReferrals → [writes referralFees]` is invisible
- No cross-contract reasoning: protocol → Uniswap interactions not modeled
- No temporal state tracking: can't reason about invariants across multiple transactions

**Fix:** Slither API gives us call graphs and transitive write sets. Model cross-protocol
interactions via `ExternalTarget` nodes with protocol labels (Uniswap, Aave, etc.)

---

### G6: No Immunefi Output Format

Current output is generic markdown. Immunefi submissions need:
- Severity + impact classification (per Immunefi's severity model)
- Step-by-step attack explanation
- Working PoC (Foundry test)
- Recommended fix

---

## Implementation Plan

### ✅ Iteration 1-4 (Done)
- Foundation, graph visualization, pattern detection, enrichment, 2 hunters, LangGraph pipeline

---

### ✅ Iteration 5 — Slither-First Graph Builder (Done — 2026-04-06)
Slither Python API is now the primary graph builder. Regex parser is fallback.
Edges: 287 → 626 on Megapot. `runJackpot` modifiers/writes now correctly captured.

---

### ✅ Iteration 6 — Critic / Debate Agent (Done — 2026-04-06)
`avadhi/agents/critic.py` challenges each hypothesis. REFUTED findings are dropped.

### ✅ Iteration 6b — Critic Source Code Fix (Done — 2026-04-06)
Root cause fix: Critic now reloads source files from disk in `critic_node`.
Slither stores `file` path on each function node for direct lookup.
AccessControlHunter updated to not flag EIP-712/signature-authenticated functions.
Result: `claimTickets` false positive eliminated. 1/1 precision on Megapot (H-01 matched).

---

### ✅ Iteration 7 — Four New Hunters (Done — 2026-04-06)
Added GasDoSHunter, AccountingHunter, OracleHunter, ReentrancyHunter.
Fixed CLI to run all 6 hunters + Critic end-to-end. Recall: 1/19 → 5/19 (26%).
OracleHunter found M-05/M-06/M-07/M-08. GasDoS and Accounting need source-level analysis.

### ✅ Iteration 7b — Source-Level Analysis for GasDoS & Accounting (Done — 2026-04-06)
Fixed brace-depth function extraction bug (multi-line signatures truncated to 71 chars).
Added nested-loop priority context, expanded financial keywords, smart function ranking.
**Recall: 5/19 → 7/19 (37%). All 3 Highs now detected (100%).**

### ✅ Iteration 8 — Governance Hunter + PoC Generation + Recall Push (Done — 2026-04-06)
New GovernanceHunter for mid-operation admin setter bugs. PoC generator for High/Critical.
Added M-03 cap DoS detection to AccountingHunter. Emergency mode analysis.
**Recall: 7/19 → 9/19 (47%). 3/3 Highs, 6/8 Mediums. 7 PoCs auto-generated.**

---

### Iteration 9 — Cross-Protocol Validation
**Goal:** Test Avadhi on a second protocol (lending, DEX, or staking) to validate generality.

### Iteration 10 — Immunefi Report Format
**Goal:** Output submission-ready reports matching Immunefi's severity model and structure.

Files:
- `avadhi/output/immunefi_report.py` → Immunefi severity model, structured output
- `avadhi/cli.py` → `avadhi submit` command (dry-run, validate format)

---

## Metric: How We Know It's Working

| Phase | Metric | Target |
|-------|--------|--------|
| Parser | Functions captured vs. true count (Slither) | >98% |
| Hunters | Recall on 5 known Immunefi bugs across 3 protocols | >60% |
| Critic | Precision (confirmed findings that are real) | >70% |
| PoC | % of confirmed findings with runnable PoC | >50% |
| End-to-end | Time from `avadhi hunt` to submission-ready report | <5 min |

The Megapot baseline measures **recall on one known audit**.
The real metric is finding **new bugs** on **live Immunefi protocols** we've never seen.
