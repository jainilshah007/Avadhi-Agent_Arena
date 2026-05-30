# The Hybrid Play: Avadhi × Claude Code

> Stop competing on "finding bugs." Start competing on "proving bugs."

---

## The Problem With Everyone Right Now

Plamen, Pashov, and current Avadhi all do the same thing at the end of the day:

```
Code → LLM → "I think there's a bug" → Markdown report
```

Nobody **proves** anything. Plamen generates 100 findings with 100 agents. Avadhi generates 48 findings with 7 hunters. Pashov generates 15-20 findings. But how many of those actually work? How many are real?

**Nobody knows. Nobody executes. Nobody verifies mathematically.**

The client gets a markdown file full of "we believe this could be exploited if..." and has to manually verify each one. That's the bottleneck. That's where you win.

---

## The Idea: Avadhi Proves, Not Guesses

### What No One Else Does

| Tool | Finds bugs | Generates PoC | Executes PoC | Formal proof |
|:---|:---:|:---:|:---:|:---:|
| Plamen | ✅ | ✅ | ❌ | ❌ |
| Pashov | ✅ | ❌ | ❌ | ❌ |
| Avadhi (current) | ✅ | ✅ | ❌ | ❌ |
| **Avadhi Hybrid** | ✅ | ✅ | **✅** | **✅** |

The gap in the market is the last two columns. Nobody fills them.

---

## Architecture: The Three-Layer Hybrid

```
┌─────────────────────────────────────────────────────────┐
│  LAYER 1: Avadhi Pipeline (your Python, ~$3-6)          │
│                                                         │
│  SecurityGraph → Hunters → Cross-feed → Hypotheses      │
│  RAG → Semantic Invariants → Confidence Scoring         │
│                                                         │
│  Output: 15-50 ranked hypotheses with evidence          │
└──────────────────────┬──────────────────────────────────┘
                       │ hypotheses.json
                       ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 2: Claude Code Prover (Claude Max plan)          │
│                                                         │
│  For each hypothesis:                                   │
│   ├─ Read actual source files (full context, no loss)   │
│   ├─ Generate Foundry PoC test                          │
│   ├─ Run `forge test` ← ACTUALLY EXECUTE IT             │
│   ├─ If test fails: iterate fix (3 attempts)            │
│   ├─ If test passes: ✅ PROVEN — tag as verified        │
│   ├─ If all attempts fail: ⚠️ UNVERIFIED               │
│   └─ Generate Certora CVL spec (for Critical findings)  │
│                                                         │
│  Output: Proven findings with execution traces          │
└──────────────────────┬──────────────────────────────────┘
                       │ verified_findings.json
                       ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 3: Report + Evidence Package                     │
│                                                         │
│  Each finding has:                                      │
│   • SecurityGraph evidence (line numbers, data flow)    │
│   • RAG match (similar historical exploits)             │
│   • Executable PoC (.sol) that PASSED forge test        │
│   • Execution trace / console output as proof           │
│   • (Optional) Certora formal spec                      │
│                                                         │
│  Client gets: "This bug exists. Here's the proof.       │
│  Run `forge test test/PoC_EXT001.t.sol` yourself."      │
└─────────────────────────────────────────────────────────┘
```

### Why This Is Different From Just "Using Claude Code"

Plamen uses Claude Code as the **brain**. You use it as the **hands**.

```
Plamen:  Claude Code thinks → Claude Code finds → Claude Code writes report
Avadhi:  Avadhi thinks (cheap, structured) → Claude Code verifies (expensive, but targeted)
```

You only send Claude Code the top 10-15 hypotheses. Plamen sends it everything and hopes. Your Claude Max tokens go toward proving, not guessing. Way more efficient.

---

## Three Out-of-the-Box Ideas That Neither Competitor Has

### Idea 1: PropertyGPT-Style Invariant Mining

Research from NDSS 2026: **PropertyGPT** uses RAG to generate formal invariants from historical audit data, then verifies them with symbolic execution.

You already have the best RAG pipeline in the space. Use it differently:

```
Current:  RAG → "here's a similar past exploit" → hunter context
New:      RAG → "here's a formal invariant that was violated in a similar protocol" 
          → LLM generates Certora CVL spec for THIS protocol
          → Certora Prover runs and finds violations automatically
```

This means Avadhi doesn't just find bugs — it **mines mathematical properties** your protocol should satisfy and **proves when they're violated**. Nobody else does this. Not Plamen. Not Pashov. Not any open-source tool.

**Concrete implementation:**
1. Your RAG already has 10,000+ audit findings. Add a new index: extract formal properties/invariants from those findings
2. For each audit, retrieve relevant invariants from similar protocols
3. Use Claude to translate them into Certora CVL (or just Foundry assertion tests)
4. Execute them. Violations = bugs found with proof.

### Idea 2: Differential SecurityGraph Auditing

Nobody does this. It's perfect for CI/CD.

```
PR opened → 
  Build SecurityGraph(main branch) 
  Build SecurityGraph(PR branch) 
  Diff the graphs:
    - New edges (new external calls, new state writes)
    - Removed guards (modifier removed from a function)
    - Changed data flow (function now reads a var it didn't before)
    - New entry points (new public/external functions)
  Only hunt for bugs in the DELTA
```

Why this matters:
- **10x faster** — you're scanning 5% of the code, not 100%
- **10x cheaper** — fewer LLM calls
- **Zero noise** — findings are directly tied to what changed
- **CI/CD native** — runs on every PR, ~$0.50 per run
- **Plamen can't do this** — they have no graph to diff. They scan everything every time.

This is the "cheap continuous security" product. $0.50 per PR. Every team can afford it.

### Idea 3: Cross-Model Adversarial Verification

You already run Claude + GPT. Take it further:

```
Step 1: GPT-5.4 finds bugs ($3-6, fast)
Step 2: Claude Opus tries to REFUTE each finding (adversarial)
Step 3: Only findings that survive adversarial challenge get reported
Step 4: For survivors, Claude generates PoC + runs it
```

This is like having a prosecutor (GPT) and defense attorney (Claude) argue each finding. The ones that survive both models are MUCH higher quality than either model alone.

You could also flip it:
```
Run A: Claude finds bugs
Run B: GPT finds bugs
Union: merge both finding sets
Adversarial: each model tries to refute the other's findings
Survivors: verified findings only
```

**Nobody else has this.** Plamen is Claude-only. Pashov is IDE-dependent. You're the only tool that can pit two frontier models against each other.

---

## What This Looks Like to a Client

### Current pitch (weak):
> "We found 48 potential vulnerabilities. Here's a markdown report."

### New pitch (strong):
> "We found 48 potential vulnerabilities. 12 of them have executable proofs that we ran on a local fork. Here are the transaction traces. Run them yourself: `forge test --match-path test/avadhi_pocs/`"

### Even stronger pitch:
> "We also generated 8 formal invariants your protocol should satisfy. 3 of them have counterexamples — meaning your protocol provably violates its own accounting rules. Here are the Certora specs."

---

## Concrete Next Steps (In Order)

| # | What | Why | Effort |
|:--|:--|:--|:--|
| 1 | **Build the Claude Code verification layer** — take Avadhi hypotheses, generate PoC in Claude Code, run `forge test`, capture result | This is your entire moat. "Proven bugs" vs "guessed bugs" | 1 week |
| 2 | **Differential SecurityGraph** — graph diff between two commit SHAs, hunt only in delta | Opens CI/CD market at $0.50/run. Nobody else can do this. | 3-5 days |
| 3 | **Cross-model adversarial** — GPT hunts, Claude refutes (or vice versa) | Higher precision, lower false positives. Unique capability. | 2-3 days |
| 4 | **Invariant mining from RAG** — extract formal properties from historical audits, generate Foundry assertion tests | "We mine mathematical properties" — nuclear pitch material | 1-2 weeks |
| 5 | **MCP server** — expose as `avadhi_scan`, `avadhi_diff`, `avadhi_prove` tools | IDE integration without giving up your pipeline | 2-3 days |

---

## The One-Liner

**Plamen tells you what might be wrong. Avadhi proves what IS wrong.**

Every finding ships with an executable proof. That's not a feature — that's a different category of product.
