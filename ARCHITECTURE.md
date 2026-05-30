# Avadhi — Full Architecture & Pipeline Flow

> From raw Solidity code to Immunefi-ready vulnerability report with PoCs.

---

## High-Level Pipeline

```
Code Input
    |
    v
Phase 1a: Structural Recon (Slither API)
    |  -> SecurityGraph: 250+ nodes, 600+ edges
    v
Phase 1b: Pattern Detection (25+ regex patterns)
    |  -> Flags on graph nodes (REENTRANCY_UNSAFE, UNCHECKED_RETURN, etc.)
    v
Phase 1c: LLM Enrichment (1 LLM call)
    |  -> Protocol type, high-level invariants, trust boundaries, dangerous flows
    v
Phase 2a: Semantic Invariant Pre-computation (1 LLM call)         [NEW]
    |  -> Write-site map, mirror variable pairs, conditional writes,
    |     accumulation exposures, semantic invariant targets for hunters
    v
Phase 2: Breadth Hunting (7 hunters, PARALLEL)                    [UPDATED]
    |  -> 8-15 raw Hypothesis objects
    v
Phase 2b: Cross-Feed Pass (top hunters re-run with finding context)
    |  -> Novel composite hypotheses (interaction / chain / amplification)
    v
Phase 2c: Depth Analysis (3 depth agents, PARALLEL)               [NEW]
    |  -> Targeted surgical follow-up on top findings:
    |     depth_edge_case   — boundary values, zero-state, off-by-one
    |     depth_state_trace — mutation order, coupled vars, missing sibling writes
    |     depth_token_flow  — balance invariants, mint/burn, donation attacks
    v
Phase 3: Critic / Debate (1 LLM call per hypothesis)
    |  -> CONFIRMED / CONTESTED / REFUTED verdict per finding
    |  -> Refuted findings dropped (~10% filtered)
    v
Phase 3b: Chain Analysis (1 LLM call)                             [NEW]
    |  -> Postcondition-to-precondition matching across findings
    |  -> Produces CHAIN-XXX compound exploit hypotheses
    v
Phase 3c: Confidence Scoring (fast batched pass)                  [NEW]
    |  -> 4-axis float score per finding:
    |     Evidence × 0.25 + Analysis × 0.30 + Consensus × 0.25 + Critic × 0.20
    v
Phase 4: PoC Generation (1 LLM call per High/Critical)
    |  -> Foundry test .sol files
    v
Report: Markdown + PoC files
```

**Total LLM calls per run (new):** ~30-40  
**Total time (new):** ~150-200 seconds (parallel Phase 2 cuts 280s → ~50s)  
**Cost:** ~$3-6 per audit (gpt-5.4)

---

## Phase 1a: Structural Recon

**Entry:** `avadhi/recon/runner.py` → `run_recon(target_path)`

### Slither Python API (Primary)
**File:** `avadhi/recon/slither.py` → `build_graph_from_slither_api()`

1. Slither compiles and analyzes the Solidity project
2. For each in-scope contract (filters out vendor via `_VENDOR_MARKERS`):
   - Adds contract node with inheritance, interface/library flags
   - Adds all state variables with types, constant/immutable flags
   - Adds all functions with visibility, mutability, modifiers, params, line ranges
   - Stores source file path on each function node
3. Second pass wires edges:
   - **WRITES**: direct + transitive (through internal calls) state variable writes
   - **READS**: state variable reads
   - **CALLS**: internal call graph
   - **EXTERNAL_CALL**: low-level `.call()` / `.delegatecall()` with taint labels
   - **TOKEN_FLOW**: high-level `transfer()`, `transferFrom()`, `approve()` calls

### Regex Parser (Fallback)
**File:** `avadhi/recon/parser.py` → `discover_sol_files()`, `parse_solidity_file()`

Used when Slither fails (uncompilable code). Also always used for `discover_sol_files()` which loads raw source text into `sg.metadata["source_files"]`.

### SecurityGraph
**File:** `avadhi/core/graph.py`

NetworkX DiGraph with typed nodes and edges:

```
Node Types:
  Contract      — name, file, sloc, inheritance, is_interface, is_library
  Function      — contract, name, visibility, mutability, modifiers, params, line_start/end, file
  StateVariable — contract, name, var_type, is_constant, is_immutable
  Modifier      — contract, name
  ExternalTarget — target address/contract
  Token         — token contract name

Edge Types:
  WRITES        — function → state variable
  READS         — function → state variable
  CALLS         — function → function (internal)
  EXTERNAL_CALL — function → external target (with taint, call_type)
  TOKEN_FLOW    — function → token (transfer/approve)
  GUARDED_BY    — function → modifier

Node ID Conventions:
  fn:Contract.functionName
  var:Contract.variableName
  contract:ContractName
  ext:target_address
  token:TokenName
  mod:Contract.modifierName

Taint Labels:
  TAINT_USER_INPUT — derived from function parameters (attacker-controlled)
  TAINT_STATE      — derived from state variables
  TAINT_CONSTANT   — derived from constants/immutables
  TAINT_COMPUTED   — derived from computation
```

**Key Query Methods:**
- `get_entry_points()` → external/public functions
- `get_unrestricted_entry_points()` → entry points with no modifiers
- `get_external_calls()` → all EXTERNAL_CALL edges
- `get_user_controlled_calls()` → external calls with USER_INPUT taint
- `get_writers(var_id)` → all functions that write to a state variable
- `get_readers(var_id)` → all functions that read a state variable
- `get_flags_for(node_id)` → pattern flags on a node
- `get_token_flows()` → all TOKEN_FLOW edges

---

## Phase 1b: Pattern Detection

**File:** `avadhi/recon/patterns.py`

25+ regex patterns scanned over source code, results attached as flags on SecurityGraph nodes:
- `REENTRANCY_UNSAFE` — external call before state update
- `UNCHECKED_RETURN` — low-level call without success check
- `DELEGATECALL` — delegatecall usage
- `SELFDESTRUCT` — selfdestruct usage
- `TX_ORIGIN` — tx.origin for auth
- And more...

---

## Phase 1c: LLM Enrichment

**File:** `avadhi/recon/enrichment.py` → `run_enrichment(sg)`

Single LLM call that reads the graph context string and returns:

```json
{
  "protocol_type": "lottery",
  "protocol_purpose": "A cross-chain jackpot lottery with...",
  "invariants": [
    {"id": "INV-001", "description": "...", "severity_if_broken": "Critical"}
  ],
  "trust_boundaries": [
    {"name": "Owner", "trust_level": "SEMI_TRUSTED", "description": "..."}
  ],
  "dangerous_flows": [...],
  "attack_surface_notes": [...]
}
```

This metadata is persisted back into the SecurityGraph and available to all hunters.

---

## Phase 2a: Semantic Invariant Pre-computation  *(NEW)*

**File:** `avadhi/agents/invariant_precompute.py` → `run_invariant_precompute(sg, enrichment_data)`

Runs **before** the breadth hunters to give them precise, code-grounded invariant targets rather than relying only on the high-level enrichment invariants.

Single LLM call that analyzes the SecurityGraph write-site map:

```json
{
  "write_sites": {
    "var:JackpotPool.totalPayout": ["fn:Pool.settle", "fn:Pool.emergencyWithdraw"]
  },
  "mirror_pairs": [
    {
      "var_a": "var:Pool.totalAssets",
      "var_b": "sum(balances)",
      "relationship": "eq",
      "risk": "Desync if a write path updates one but not the other"
    }
  ],
  "conditional_writes": [
    "fn:Pool.updateRewardRate writes rewardRate ONLY inside if(currentEpochComplete)"
  ],
  "accumulation_exposures": [
    "var:Pool.totalPayout only ever increases — no reset path exists"
  ],
  "semantic_invariants": [
    {
      "id": "SI-001",
      "description": "totalAssets must equal sum of all balances after any deposit/withdrawal",
      "write_sites": ["fn:Pool.deposit", "fn:Pool.withdraw"],
      "severity_if_broken": "Critical"
    }
  ]
}
```

This data is merged into `sg.metadata["semantic_invariants"]` and injected into every hunter's context string, dramatically improving signal-to-noise on accounting and governance findings.

---

## Phase 2b: Advanced RAG Subsystem (Context Grounding)  *(NEW)*

**Files:** `avadhi/rag/*.py` 

Before a hunter agent formulates a bug hypothesis, it dynamically queries the pgvector database containing heavily processed technical audit reports and web3 concepts. Avadhi uses a highly tuned 4-stage retrieval pipeline:

1. **HyDE Expansion (`hyde.py`)**: Uses a domain-specific prompt to expand a short query (e.g. "oracle price skew") into a 250-word synthetic exploit document, dramatically improving spatial intersection in the vector database.
2. **Hybrid Retrieval (`retriever.py`)**: Multi-channel retrieval utilizing `voyage-code-3` (1024d) and `text-embedding-3-small` (1536d) HNSW indexes, plus TSVector BM25, fused together via **Reciprocal Rank Fusion (RRF)**.
3. **Metadata Scoring & Dedup (`scoring.py`)**: Adds heuristic boosts based on tags (`bug_pattern`, code presence) and strips near-identical window overlap using word-level 3-shingle Jaccard deduplication.
4. **Cross-Encoder Reranking (`reranker.py`)**: Precisely scores the top candidates using `voyage-rerank-2` for rigorous token-level relevance before truncating to the final Top-K chunks.

---

## Phase 2c: Breadth Hunting  *(PARALLEL)*

**Files:** `avadhi/agents/hunters/*.py`

All 7 hunters now execute **in parallel** via `ThreadPoolExecutor(max_workers=7)`.
Each is independent (read-only access to `sg`) — thread-safe by design.

All hunters follow the same pattern defined in `avadhi/agents/hunters/base.py`:

```python
def run_<name>_hunter(sg: SecurityGraph, logger, verbose) -> list[Hypothesis]:
    # 1. Query graph for relevant nodes/edges
    # 2. Build context string (graph data + semantic invariants from Phase 2a)
    # 3. Extract source code snippets
    # 4. call_hunter(name, system_prompt, context, source) → list[Hypothesis]
```

`call_hunter()` sends SystemMessage + HumanMessage to the LLM, parses JSON response into `Hypothesis` objects with fields: id, title, severity, category, description, location, attack_scenario, preconditions, impact, evidence.

### Hunter 1: AccessControlHunter
**File:** `access_control.py`  
**Hunts:** Missing auth on state-changing functions, unrestricted entry points  
**Graph Query:** `sg.get_unrestricted_entry_points()` → functions with no modifiers that write state or make external calls  
**Special:** Knows to NOT flag EIP-712/ECDSA.recover patterns

### Hunter 2: ExternalCallHunter
**File:** `external_call.py`  
**Hunts:** Arbitrary calls, approval+call combos, user-controlled call targets  
**Graph Query:** `sg.get_external_calls()` + `sg.get_user_controlled_calls()` → taint-tracked external calls

### Hunter 3: GasDoSHunter
**File:** `gas_dos.py`  
**Hunts:** Unbounded loops, nested loops, external calls in loops, state machine deadlocks  
**Graph Query:** Source-level regex scan for `for`/`while` loops + graph fan-out/write analysis  
**Special:**
- `_scan_source_for_loops()` — regex scanner that finds loops, tracks function boundaries, counts nesting
- Sorts by loop count descending so nested-loop functions get priority
- Brace-depth extraction with `found_open` flag for multi-line Solidity signatures
- "HIGHEST PRIORITY" context section for nested-loop functions

### Hunter 4: AccountingHunter
**File:** `accounting.py`  
**Hunts:** Invariant violations, rounding errors, precision loss, pool cap bypasses, share price manipulation, coupled variable desync, governance-induced cap DoS  
**Graph Query:** Finds financial state variables (30+ keywords), traces writers, identifies coupled groups, analyzes cap/limit enforcement  
**Special:**
- Expanded keywords: balance, total, pool, cap, share, accumulator, lp, vault, treasury, payout...
- Same-contract cap analysis (not all-contracts — reduces noise)
- Function priority scoring: settlement +5, pool-writers-without-cap-read +10, constructors -20
- Now receives **semantic invariants** from Phase 2a (mirror pairs, conditional writes) as additional context

### Hunter 5: OracleHunter
**File:** `oracle.py`  
**Hunts:** Oracle manipulation, single-source oracle, stale data, randomness manipulation, admin-changeable data sources mid-operation, flash loan + oracle attacks  
**Graph Query:** Finds oracle/entropy/VRF state vars, traces readers/writers, identifies admin setter functions for oracle addresses

### Hunter 6: ReentrancyHunter
**File:** `reentrancy.py`  
**Hunts:** CEI violations, cross-function reentrancy, cross-contract reentrancy, read-only reentrancy, ERC-721/777 callback reentrancy  
**Graph Query:** Finds functions with external calls, maps their state writes, identifies cross-function pairs (A has ext call + writes var, B reads same var), checks for nonReentrant guards

### Hunter 7: GovernanceHunter
**File:** `governance.py`  
**Hunts:** Admin setters that change state mid-operation, emergency mode fund locking, governance-induced cap/limit DoS, async callback inconsistency  
**Graph Query:**
- Finds admin setters (set*/update*/change* + onlyOwner/onlyAdmin)
- Traces what state each setter modifies
- Finds operational functions that READ the same state
- Checks for temporal guards (strict: `currentDrawingId` is NOT a guard, `drawingState` IS)
- Emergency mode analysis: what gets blocked? are funds locked?

**Special:** Nemesis-style per-function interrogation + SC-Auditor Devil's Advocate in system prompt

---

## Phase 2b: Cross-Feed Pass

**File:** `avadhi/agents/hunters/crossfeed.py` → `summarize_for_crossfeed()`, `select_hunters_for_pass2()`

Top hunters re-run with a summary of ALL Pass 1 findings in their context. They look for:
- **INTERACTION**: Finding X + Finding Y from different domains = worse combined attack
- **CHAIN**: Multi-step exploit path across multiple findings
- **AMPLIFICATION**: A finding that makes another finding's impact significantly worse
- **MISSED ANGLES**: Vulnerabilities in the same functions Pass 1 overlooked

Deduplication: Pass 2 findings that match a Pass 1 finding by `(location, category)` are dropped.
Novel findings get their `id` prefixed with `XF-` and `iteration = 2`.

---

## Phase 2c: Depth Analysis  *(NEW)*

**Files:** `avadhi/agents/hunters/depth_edge_case.py`, `depth_state_trace.py`, `depth_token_flow.py`

After breadth + cross-feed, the top-N findings (by severity, configurable via `DEPTH_TOP_N`) are sent to 3 specialized depth agents running **in parallel**. Each agent receives its specific target hypotheses and performs surgical, code-grounded follow-up.

### DepthEdgeCaseAgent
**File:** `depth_edge_case.py`  
**Targets:** Accounting, oracle, and governance hypotheses with boundary conditions  
**Analysis:**
- **Zero-State**: What exchange rate/behavior at `totalSupply == 0`? Can first depositor exploit donation attack?
- **Return-to-Zero**: Can all users exit? Are residual assets (fees, dust) exploitable by the next depositor?
- **Threshold States**: `totalSupply == 1`, max-value overflow, cap-exactly-full
- **Off-by-One**: Systematically tests `<` vs `<=` in all setter functions, supply cap enforcement, loop bounds
- **Real Constant Substitution**: Extracts actual fee BPS, min deposit, cap values from source and substitutes into every calculation — no variables, concrete numbers only

**Output IDs:** `DE-NNN`  
**Verdict per target:** `CONFIRMED` / `REFINED` / `REFUTED` / `CONTESTED`

### DepthStateTraceAgent
**File:** `depth_state_trace.py`  
**Targets:** Hypotheses involving state mutation, CEI violations, coupled variables  
**Analysis:**
- Maps ALL write sites for every state variable touched by the finding
- Verifies mutation order relative to external calls (CEI enforcement)
- Detects coupled variables that MUST update together (e.g. `totalAssets` + `balances[user]`)
- Flags missing sibling writes: function updates `totalPayout` but not `lastSettledEpoch`
- Cross-function mutation: function A sets flag → function B reads flag without re-checking preconditions

**Output IDs:** `DS-NNN`

### DepthTokenFlowAgent
**File:** `depth_token_flow.py`  
**Targets:** Hypotheses involving token transfers, mint/burn, reward accounting  
**Analysis:**
- Verifies balance invariants hold across all `deposit` / `withdraw` / `claim` call paths
- Checks for fee-on-transfer / rebasing token assumptions baked into accounting logic
- Tests donation attack: attacker directly transfers tokens to contract bypassing `deposit()` accounting
- Mint/burn symmetry: can total minted ever exceed total burnable?
- Reward accumulation: is `accumulatedReward` updated before `rewardRate` changes?

**Output IDs:** `DT-NNN`

---

## Phase 3: Critic / Debate

**File:** `avadhi/agents/critic.py` → `run_critic(hypotheses, sg)`

For each hypothesis (breadth + cross-feed + depth findings):
1. Extracts relevant source code for the finding's location
2. Sends to Critic LLM with system prompt: "You are a skeptical security researcher. Steelman the DEFENSE."
3. Critic returns: verdict (CONFIRMED/CONTESTED/REFUTED), challenge text, counter-evidence
4. REFUTED findings are dropped entirely
5. CONTESTED/CONFIRMED findings continue with confidence label

**System Prompt Strategy:**
- "Find the on-chain guard that PREVENTS this exploit"
- "Check if modifiers, require() statements, or architecture make this impossible"
- "If you can't find a defense, confirm the finding"

---

## Phase 3b: Chain Analysis  *(NEW)*

**File:** `avadhi/agents/chain_analysis.py` → `run_chain_analysis(hypotheses, sg)`

Single LLM call that receives ALL surviving hypotheses and detects compound exploit paths by matching findings as a directed graph:

```
For each pair (Finding A, Finding B):
  - A's attack_scenario puts the protocol in state X  (postcondition)
  - B's preconditions require state X                 (precondition)
  → A + B = compound exploit chain → CHAIN-NNN hypothesis
```

**Example chain:** AccessControl miss (attacker can call `setOracleAddress`) + OracleManipulation (stale oracle exploited) = one chained Critical where A enables B. Neither finding alone is Critical; together they are.

**Output:** New `CHAIN-NNN` hypotheses appended to find list, then passed through PoC generation.

---

## Phase 3c: Confidence Scoring  *(NEW)*

**File:** `avadhi/agents/confidence_scorer.py` → `score_confidence(hypotheses, challenges)`

Fast batched pass (uses `FAST_MODEL`) that assigns a `confidence_score: float` (0.0–1.0) to every surviving hypothesis using a 4-axis model:

| Axis | Weight | What it measures |
|------|--------|-----------------|
| **Evidence Quality** | 0.25 | Specific line numbers, constants, function names cited in evidence |
| **Analysis Quality** | 0.30 | Attack scenario is step-by-step, concrete, uses real values |
| **Cross-Hunter Consensus** | 0.25 | 2+ hunters or depth agents independently flagged the same pattern |
| **Critic Resistance** | 0.20 | Critic confirmed decisively vs. just couldn't find a refutation |

`confidence_score = E×0.25 + A×0.30 + C×0.25 + CR×0.20`

Stored on the `Hypothesis` object. Used in the report to sort findings within the same severity tier — a CONFIRMED 0.95 appears before a CONFIRMED 0.61.

---

## Phase 4: PoC Generation

**File:** `avadhi/agents/poc_gen.py` → `generate_pocs(hypotheses, sg)`

Only runs for High/Critical findings (including `CHAIN-NNN` hypotheses). For each:
1. Selects category-specific hint (gas, access, accounting, oracle, governance, reentrancy, external, chain)
2. Extracts relevant source code from SecurityGraph
3. LLM generates complete Foundry test using Tier of Thought:
   - Tier 1: What invariant is violated?
   - Tier 2: What transaction sequence triggers it?
   - Tier 3: What assertions prove it?
4. Output: `.sol` files in `.avadhi_output/pocs/`

---

## Output

### Report: `.avadhi_output/hunt_results.md`
- Protocol context + enrichment invariants + semantic invariants (Phase 2a)
- Findings sorted by severity then `confidence_score` (descending)
- Each finding: description, attack scenario, impact, evidence, confidence score, critic debate log
- Chain findings (CHAIN-NNN) shown with their component finding IDs
- PoC code embedded in `<details>` blocks

### PoC Files: `.avadhi_output/pocs/<ID>_test.sol`
- Individual Foundry test files per High/Critical finding
- Ready to drop into a Foundry project

### Graph: `.avadhi_output/security_graph.json` + `graph.html`
- Full SecurityGraph as JSON
- Interactive HTML visualization

### Logs: `.avadhi_output/audit_log_<timestamp>.jsonl`
- Every LLM call with tokens, latency, phase

---

## Data Models

**File:** `avadhi/core/schemas.py`

```
Hypothesis        — Hunter output
                    id, title, severity, category, description,
                    location, attack_scenario, preconditions, impact, evidence,
                    hunter_agent, iteration,
                    confidence_score: float = 0.0          ← NEW
                    depth_finding_ids: list[str] = []      ← NEW (DE/DS/DT refs)

ChainHypothesis   — Chain analysis output                  ← NEW
                    id ("CHAIN-NNN"), component_ids: list[str],
                    chain_description, combined_severity, attack_sequence

CriticChallenge   — Critic output
                    hypothesis_id, challenge, verdict, reasoning, counter_evidence

VerifiedFinding   — Final output
                    (extends Hypothesis with: proof_of_concept, recommendation, debate_log)

Severity          — Critical | High | Medium | Low | Info
Confidence        — Confirmed | Contested | Refuted | Uncertain
```

---

## Pipeline Orchestration

**File:** `avadhi/cli.py` → `hunt` command

```
Phase 1a+b:  run_recon()
Phase 1c:    run_enrichment()
Phase 2a:    run_invariant_precompute()                       ← NEW
Phase 2:     ThreadPoolExecutor(max_workers=7) → 7 hunters    ← UPDATED (parallel)
Phase 2b:    cross-feed pass (top hunters re-run)
Phase 2c:    ThreadPoolExecutor(max_workers=3) → depth agents ← NEW (parallel)
Phase 3:     run_critic()
Phase 3b:    run_chain_analysis()                             ← NEW
Phase 3c:    score_confidence()                               ← NEW
Phase 4:     generate_pocs()
Report:      _write_hunt_report()
```

---

## Configuration

**File:** `avadhi/config.py`

```python
MODEL       = os.getenv("AVADHI_MODEL", "gpt-5.4")
FAST_MODEL  = os.getenv("AVADHI_FAST_MODEL", "gpt-4o-mini")  # depth agents + confidence scorer
SKIP_DIRS   = frozenset({"node_modules", "forge-std", "openzeppelin-contracts",
                          "test", "tests", "mock", "mocks", ...})
MAX_FILE_SIZE_KB    = 500
SOLIDITY_EXTENSIONS = frozenset({".sol"})
DEPTH_TOP_N         = 10    # max findings sent to depth agents
PARALLEL_HUNTERS    = True  # set False to debug sequentially
```

---

## Performance Targets

| Metric | Iteration 8 (current) | Target (after) |
|--------|----------------------|----------------|
| Total findings (Megapot Code4rena) | 19 (3H, 8M, 8L) | — |
| Detected | 9/19 (47%) | >12/19 (>63%) |
| Highs detected | 3/3 (100%) | 3/3 (100%) |
| Mediums detected | 6/8 (75%) | 7-8/8 (88-100%) |
| Precision | ~90% | ~88% |
| PoCs generated | 7 | 8-10 |
| Pipeline wall time | ~413s | ~180s |
| Phase 2 wall time | ~280s (sequential) | ~50s (parallel) |
| LLM calls | ~18 | ~35-40 |
