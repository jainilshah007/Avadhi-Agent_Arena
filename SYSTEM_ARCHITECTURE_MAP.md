# Avadhi Deep-Dive: System Flow Map

Here is a comprehensive map of exactly how code flows through the Avadhi pipeline from the moment it is ingested to the final security report, including the new **Advanced RAG (Retrieval-Augmented Generation)** subsystem.

When you provide a smart contract system to Avadhi, it kicks off a **Four-Phase Orchestration** involving multiple specialized AI agents working together in a specific sequence.

> [!NOTE]  
> The entire architecture is predicated on the idea that LLMs hallucinate less when they have explicitly grounded graph/vector contextual data over raw token scraping.

```mermaid
flowchart TD
    %% Input
    Input[fa:fa-file-code Raw Source Code] --> Phase1
    
    %% Database 
    DB[(fa:fa-database Neon pgvector\n490k Embedded Chunks)]
    
    %% RAG Subsystem
    subgraph RAG [Advanced RAG Subsystem]
        direction TB
        R1[A. HyDE Expansion\nShort Query → Synthetic Exploit Doc] --> R2
        R2[B. Hybrid Retrieval\nHNSW (Code + Prose) + BM25 FTS] --> R3
        R3[C. Scoring & Dedup\nMetadata Boosts + Jaccard Deduplication] --> R4
        R4[D. Cross-Encoder Rerank\nvoyage-rerank-2 Token-Level Scoring]
    end
    DB -.-> |Vector Search| R2

    %% Phase 1: Recon & Enrichment
    subgraph Phase1 [Phase 1: Recon & Context Building]
        direction TB
        P1A[1a. Structural Recon\nSlither API builds AST & SecurityGraph] --> P1B
        P1B[1b. Regex Pattern Scan\nFlags graph nodes natively] --> P1C
        P1C[1c. LLM Enrichment\nExtracts Trust Boundaries & Intent]
    end

    %% Phase 2: Hunting Floor
    Phase1 --> Phase2
    subgraph Phase2 [Phase 2: Hunter Floor]
        direction TB
        P2A[2a. Semantic Invariant Precompute\nMaps variables into Mirror Pairs & Rules] --> P2B
        
        P2B[2b. Breadth Hunting]
        P2A --> |Security Graph Context| P2B
        RAG ==> |Injects Formatted Grounding Context| P2B
        
        %% Parallel Hunters
        P2B --> H1(Accounting Agent)
        P2B --> H2(Gas DoS Agent)
        P2B --> H3(Reentrancy Agent)
        P2B --> H4(Oracle Agent)
        P2B --> H5(Governance Agent)
        P2B --> H6(Access Control Agent)
        P2B --> H7(External Call Agent)

        %% Aggregation
        H1 --> Agg(Central Pool)
        H2 --> Agg
        H3 --> Agg
        H4 --> Agg
        H5 --> Agg
        H6 --> Agg
        H7 --> Agg
        
        Agg --> P2C[2c. Cross-Feed Pass\nHunters review each other's work]
        P2C --> P2D[2d. Depth Agents\nTarget zero-states & offsets surgically]
    end

    %% Phase 3: Debate & Vetting
    Phase2 --> Phase3
    subgraph Phase3 [Phase 3: The Critic Layer]
        direction TB
        P3A[3a. The Critic\nActively attempts to refute/debunk all findings] --> P3B
        RAG -.-> |Counter-Evidence Retrieval| P3A
        P3B[3b. Chain Analysis\nLooks for A + B = C compound exploits] --> P3C
        P3C[3c. Confidence Scorer\nScores survivors from 0.0 to 1.0]
    end

    %% Phase 4: Output
    Phase3 --> Phase4
    subgraph Phase4 [Phase 4: Synthesis]
        direction TB
        P4A[4. PoC Generator\nWrites Foundry tests for High/Critical] --> Out
    end

    Out[fa:fa-file-flag Final Output:\nAudit Markdown + Foundry PoC files]

    style Input fill:#2d3748,stroke:#cbd5e0,color:#fff
    style Out fill:#e53e3e,stroke:#fc8181,color:#fff
    style RAG fill:#2f855a,stroke:#48bb78,color:#fff
```

---

## Technical Phase Breakdown
When you submit code to `avadhi/cli.py`, the orchestration triggers the following lifecycle:

### Phase 1: Recon & Context Building (The Foundation)
Instead of just blindly tossing code files at an LLM, Avadhi first builds a localized code brain. 

* **Slither API** analyzes the code structurally and outputs a heavily interconnected `SecurityGraph`. This tracks precisely what functions read/write which state variables.
* **LLM Enrichment** then looks at the global structure and establishes what the "protocol's intent" is.

> [!IMPORTANT]  
> If the Enrichment agent decides the protocol is an "AMM DEX", the subsequent Hunters will automatically tune their detection models to prioritize rounding errors and LP share math.

### Advanced RAG Integration (Grounding)
Whenever a Hunter formulates a hypothesis, it dynamically queries the Neon vector database using a 4-stage pipeline:
1. **HyDE**: The query is expanded into a technical synthetic exploit document.
2. **Hybrid**: Reciprocal Rank Fusion combines dual vector similarities (`voyage-code-3` + `text-embedding-3-small`) with BM25 full-text keyword matching.
3. **Boost & Dedup**: Shingle-based Jaccard deduplication strips redundant overlaps.
4. **Cross-Encoder**: `voyage-rerank-2` aligns query and document tokens for maximum relevance scoring.

### Phase 2: The Hunter Floor (The Workers)
This is where the actual bug hunting happens. 

* Avadhi first generates **Semantic Invariants** (e.g. `totalAssets` should always equal `sum(userBalances)`). 
* It then spawns 7 highly specialized LLM "Hunters" simultaneously in parallel (`AccountingHunter`, `OracleHunter`, `ReentrancyHunter`, etc.). 
* Because each Hunter receives the rigorous localized **Security Graph** *and* real-world vulnerability context drawn from **RAG**, they output highly accurate raw `Hypothesis` objects.
* **Depth Agents** dive surgically into the most promising hypotheses looking specifically at boundary rules.

> [!TIP]  
> Parallelizing the 7 Hunters explicitly drops the pipeline's runtime from nearly 5 minutes down to ~50 seconds per audit run.

### Phase 3: The Critic Layer (The Filter)
LLMs generate a lot of false positives. To combat this, Avadhi employs adversarial networking:

* Every hypothesis from Phase 2 is fed to a specialized `Critic` Agent. Its entire system prompt is to play "Devil's Advocate". It explicitly hunts for modifiers, `require()` checks, or external state flags that would mathematically prevent the proposed attack.
* If it successfully refutes the exploit, the finding is silently stripped and discarded. 
* Surviving findings are subsequently grouped into a Chain Analysis module to see if they can be inextricably linked (e.g., a low-level access control bug enables a critical oracle manipulation).

### Phase 4: Synthesis (The Deliverables)
All findings that survive the Critic natively are passed to a final LLM orchestrator. 

If a finding is deemed **High** or **Critical**, Avadhi generates a raw `Foundry` implementation (`.sol` file) attempting to mathematically prove the vulnerability in a local environment. Everything is bundled into a neatly organized `.md` report.
