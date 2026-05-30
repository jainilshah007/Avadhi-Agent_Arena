"""Recon phase — structural analysis, pattern detection, and LLM enrichment."""
from avadhi.recon.parser import parse_solidity, discover_sol_files
from avadhi.recon.slither import try_slither, parse_slither_findings
from avadhi.recon.patterns import run_patterns
from avadhi.recon.enrichment import run_enrichment
from avadhi.recon.runner import run_recon

__all__ = [
    "parse_solidity", "discover_sol_files",
    "try_slither", "parse_slither_findings",
    "run_patterns", "run_enrichment", "run_recon",
]
