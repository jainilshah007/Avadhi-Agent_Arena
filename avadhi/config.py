"""
avadhi/config.py — Global settings and environment setup.

Single source of truth for all configuration.
Validates at import time so errors surface early.
"""
import os
import shutil
import warnings
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
OUTPUT_DIR = ROOT / ".avadhi_output"

# ── API Keys ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ── LLM ──────────────────────────────────────────────────────────────────────
# MODEL = os.getenv("AVADHI_MODEL", "claude-sonnet-4-6")
MODEL = os.getenv("AVADHI_MODEL", "gpt-4o")

# Validate model name has a reasonable format
_KNOWN_PREFIXES = ("claude", "anthropic", "gpt-", "o1", "o3")
if MODEL and not any(MODEL.startswith(p) for p in _KNOWN_PREFIXES):
    warnings.warn(
        f"AVADHI_MODEL='{MODEL}' doesn't match known providers ({', '.join(_KNOWN_PREFIXES)}). "
        "If this is intentional, ignore this warning.",
        RuntimeWarning,
        stacklevel=1,
    )

# ── Rate Limits ──────────────────────────────────────────────────────────────
IS_OPENAI = not (MODEL.startswith("claude") or MODEL.startswith("anthropic"))

if IS_OPENAI:
    _def_rpm, _def_itpm, _def_otpm = 500, 500_000, 150_000
else:
    # Anthropic Tier 1: 50 RPM, 30,000 ITPM, 8,000 OTPM
    _def_rpm, _def_itpm, _def_otpm = 50, 30_000, 8_000

try:
    RATE_LIMIT_RPM = int(os.getenv("AVADHI_RPM", _def_rpm))
    RATE_LIMIT_ITPM = int(os.getenv("AVADHI_ITPM", _def_itpm))
    RATE_LIMIT_OTPM = int(os.getenv("AVADHI_OTPM", _def_otpm))
except ValueError as e:
    raise ValueError(f"Invalid rate limit configuration (must be integers): {e}") from e

if RATE_LIMIT_RPM <= 0 or RATE_LIMIT_ITPM <= 0 or RATE_LIMIT_OTPM <= 0:
    raise ValueError("Rate limits must be positive integers")

# ── Concurrency ──────────────────────────────────────────────────────────────
if IS_OPENAI:
    _def_concurrency, _def_depth_critic = 20, 10
else:
    _def_concurrency, _def_depth_critic = 8, 4

HUNTER_CONCURRENCY = int(os.getenv("AVADHI_CONCURRENCY", _def_concurrency))
DEPTH_CONCURRENCY = int(os.getenv("AVADHI_DEPTH_CONCURRENCY", _def_depth_critic))
CRITIC_CONCURRENCY = int(os.getenv("AVADHI_CRITIC_CONCURRENCY", _def_depth_critic))

# Hard caps on each prompt section (in chars ~ tokens * 3.5).
MAX_CONTEXT_CHARS = int(os.getenv("AVADHI_MAX_CONTEXT_CHARS", "6000"))
MAX_SOURCE_CHARS = int(os.getenv("AVADHI_MAX_SOURCE_CHARS", "8000"))
MAX_RAG_CHARS = int(os.getenv("AVADHI_MAX_RAG_CHARS", "2500"))

# ── Tool Paths ───────────────────────────────────────────────────────────────

def _find_tool(name: str, env_var: str) -> str:
    """Locate a CLI tool, with environment override. Returns path or name."""
    env_path = os.getenv(env_var)
    if env_path:
        if Path(env_path).exists():
            return env_path
        warnings.warn(f"{env_var}='{env_path}' not found on disk, falling back to PATH",
                      RuntimeWarning, stacklevel=2)
    found = shutil.which(name)
    if found:
        return found
    return name  # Return name as-is; will error when actually used


SLITHER_PATH = _find_tool("slither", "SLITHER_PATH")
FORGE_PATH = _find_tool("forge", "FORGE_PATH")

# Check if tools are actually available (warn, don't fail)
if not shutil.which(SLITHER_PATH):
    warnings.warn(
        f"slither not found in PATH (set SLITHER_PATH env var). "
        "Recon will fall back to regex parser.",
        RuntimeWarning, stacklevel=1,
    )

# ── Scanner Settings ─────────────────────────────────────────────────────────
SKIP_DIRS = frozenset({
    "node_modules", "forge-std", "openzeppelin-contracts",
    "test", "tests", "mock", "mocks",
    ".git", "artifacts", "cache", "out", "build", "script",
})

MAX_FILE_SIZE_KB = 500
SOLIDITY_EXTENSIONS = frozenset({".sol"})

# ── Slither Timeout ──────────────────────────────────────────────────────────
SLITHER_TIMEOUT = int(os.getenv("AVADHI_SLITHER_TIMEOUT", "180"))

# ── Database (RAG) ───────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "")

# ── Agent Arena ──────────────────────────────────────────────────────────────
AGENTARENA_API_KEY = os.getenv("AGENTARENA_API_KEY", "")
WEBHOOK_AUTH_TOKEN = os.getenv("WEBHOOK_AUTH_TOKEN", "")
