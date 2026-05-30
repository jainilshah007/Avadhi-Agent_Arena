# Avadhi — Autonomous Smart Contract Auditing Pipeline

Avadhi is a high-performance, multi-agent autonomous auditing system designed to identify complex, exploitable vulnerabilities in Solidity codebases. It orchestrates specialized agents to move from raw code ingestion to verified findings with proof-of-concepts (PoCs).

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.9+
- [Slither](https://github.com/crytic/slither) (for static analysis enrichment)
- [Node.js](https://nodejs.org/) (for Hardhat/Foundry project compilation)

### 2. Installation
```bash
# Clone the repository
git clone <your-repo-url>
cd Avadhi

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` and add your API keys:
```bash
cp .env.example .env
```
Key requirements:
- `ANTHROPIC_API_KEY`: For the primary auditing agents (Claude 3.5 Sonnet recommended).
- `OPENAI_API_KEY`: For auxiliary analysis or alternative models.

### 4. Running an Audit
To start a full multi-agent hunt on a local directory:
```bash
python3 -m avadhi hunt <path_to_contracts> --verbose
```
The pipeline will execute:
1. **Structural Recon**: Builds a security graph of the project.
2. **Multi-Agent Hunting**: 18+ specialized hunters scan for vulnerabilities.
3. **Critic/Debate**: Findings are challenged and refined to reduce false positives.
4. **PoC Generation**: Runnable Foundry/Hardhat tests are generated for verified findings.

### 5. Knowledge Base (RAG)
To ingest new security reports or documentation into the knowledge base:
```bash
python3 run_ingest.py
```

## 🛠 Architecture
Avadhi uses a four-phase orchestration:
- **Phase 1: Recon**: Invariant extraction and graph building.
- **Phase 2: Hunting**: Parallel execution of hunters (Access Control, Oracle, Cross-Chain, etc.).
- **Phase 3: Validation**: Multi-agent debate and depth analysis.
- **Phase 4: Evidence**: PoC generation and final report assembly.

## 📁 Project Structure
- `avadhi/`: Core audit logic and agent implementations.
- `ingestion/`: RAG pipeline for processing security knowledge.
- `scripts/`: Utility scripts for project management.
- `tests/`: System test suite.

---
