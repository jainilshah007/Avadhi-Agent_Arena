"""
avadhi/utils/logging.py — Structured audit logging.

Every agent invocation, LLM call, and pipeline step produces a
structured log entry. These logs enable:
  - Debugging agent behavior
  - Comparing runs (version A vs version B)
  - Cost tracking
  - Building evaluation datasets
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only structured logger for audit runs."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = f"run_{int(time.time())}"
        self.log_file = self.output_dir / f"{self.run_id}.jsonl"
        self._entries: list[dict] = []

    def log(self, phase: str, agent: str, action: str, **kwargs: Any):
        """Log a structured entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "phase": phase,
            "agent": agent,
            "action": action,
            **kwargs,
        }
        self._entries.append(entry)
        # Append to file immediately
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def log_llm_call(self, agent: str, model: str, *,
                     prompt_tokens: int = 0, completion_tokens: int = 0,
                     cost_usd: float = 0, latency_ms: int = 0,
                     phase: str = "", **kwargs):
        """Log an LLM API call with cost tracking."""
        self.log(
            phase=phase, agent=agent, action="llm_call",
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            **kwargs,
        )

    def log_phase(self, phase: str, status: str, **kwargs):
        """Log phase start/end."""
        self.log(phase=phase, agent="orchestrator", action=f"phase_{status}",
                 **kwargs)

    def get_summary(self) -> dict:
        """Summarize the run."""
        total_cost = sum(e.get("cost_usd", 0) for e in self._entries)
        total_tokens = sum(e.get("prompt_tokens", 0) + e.get("completion_tokens", 0)
                          for e in self._entries)
        llm_calls = sum(1 for e in self._entries if e.get("action") == "llm_call")
        return {
            "run_id": self.run_id,
            "total_entries": len(self._entries),
            "llm_calls": llm_calls,
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 4),
            "log_file": str(self.log_file),
        }
