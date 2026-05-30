"""
avadhi/recon/patterns.py — Phase 1b: Security pattern grep.

Scans source code for 25+ security-relevant patterns and attaches
flags to SecurityGraph nodes. Zero LLM cost, pure regex.
"""
from __future__ import annotations

import re
from avadhi.core.graph import SecurityGraph


# ═══════════════════════════════════════════════════════════════════════════════
# Pattern Definitions: (flag, description, regex)
# ═══════════════════════════════════════════════════════════════════════════════
PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("ORACLE", "Oracle price feed",
     re.compile(r"oracle|latestRoundData|TWAP|chainlink|priceFeed|getPrice", re.I)),
    ("RANDOMNESS_WEAK", "Weak randomness",
     re.compile(r"keccak256.*block|prevrandao|block\.timestamp.*random|block\.difficulty", re.I)),
    ("RANDOMNESS_VRF", "VRF/entropy provider",
     re.compile(r"VRF|entropy|requestRandom|fulfillRandom|IEntropy", re.I)),
    ("FLASH_LOAN", "Flash loan patterns",
     re.compile(r"flashLoan|flash\s*loan|onFlashLoan|executeOperation|flashCallback")),
    ("DEX_INTERACTION", "DEX/AMM interaction",
     re.compile(r"IUniswap|IBalancer|swap.*token|addLiquidity|removeLiquidity|getReserves")),
    ("BALANCE_DEPENDENT", "Direct balance query",
     re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)|\.balance\b")),
    ("ERC4626", "Vault/share pattern",
     re.compile(r"ERC4626|deposit.*shares|withdraw.*assets|convertToShares|convertToAssets")),
    ("MULTI_TOKEN", "Multi-token standard",
     re.compile(r"ERC1155|ERC6909|onERC1155Received")),
    ("SEMI_TRUSTED_ROLE", "Bot/keeper/operator",
     re.compile(r"onlyBot|onlyOperator|onlyKeeper|BOT_ROLE|KEEPER_ROLE|OPERATOR_ROLE")),
    ("PROXY_UPGRADEABLE", "Proxy/upgradeable",
     re.compile(r"proxy|upgradeable|Initializable|reinitializ|delegatecall")),
    ("CROSS_CHAIN", "Bridge/cross-chain",
     re.compile(r"bridge|L1|L2|lzReceive|ccipReceive|crossChain|messenger", re.I)),
    ("TEMPORAL", "Time-dependent logic",
     re.compile(r"block\.timestamp|interval|epoch|period|duration|deadline")),
    ("HAS_SIGNATURES", "Signature verification",
     re.compile(r"ecrecover|ECDSA\.recover|isValidSignature|EIP712|permit\(")),
    ("STAKING", "Staking/delegation",
     re.compile(r"stake|unstake|delegation|validator|claimReward|compound", re.I)),
    ("GOVERNANCE", "Governance/voting",
     re.compile(r"vote|propose|timelock|quorum|Governor")),
    ("MIXED_DECIMALS", "Mixed decimal math",
     re.compile(r"mulDiv|mulWad|divWad|1e6|1e8|1e18|decimals\(\)|10\s*\*\*")),
    ("CALLBACK", "Callback hooks",
     re.compile(r"onERC721Received|onERC1155Received|tokensReceived|beforeSwap|afterSwap")),
    ("LOW_LEVEL_CALL", "Low-level calls",
     re.compile(r"\.call\{|\.call\(|\.delegatecall\(|assembly\s*\{")),
    ("REENTRANCY_GUARD", "Reentrancy protection",
     re.compile(r"nonReentrant|ReentrancyGuard|_status|_locked")),
    ("SHARE_ALLOCATION", "Share distribution",
     re.compile(r"shares|allocation|distribute|pro.rata|proportional|vest")),
    ("MIGRATION", "Migration/upgrade",
     re.compile(r"reinitializer|V2|V3|_deprecated|migrat|upgrade|legacy")),
    ("LENDING", "Lending protocol",
     re.compile(r"borrow|lend|collateral|liquidat|healthFactor|LTV", re.I)),
    ("LOTTERY", "Lottery/raffle",
     re.compile(r"lottery|jackpot|raffle|drawing|winner|ticket|prize", re.I)),
]


def run_patterns(sg: SecurityGraph) -> dict[str, list[str]]:
    """
    Scan source files for security-relevant patterns.
    Attaches flags to function-level AND global-level graph nodes.
    Returns {flag_name: [file:line locations]}.
    """
    source_files = sg.metadata.get("source_files", {})
    if not source_files:
        return {}

    results: dict[str, list[str]] = {}

    for flag_name, _, regex in PATTERNS:
        matches: list[str] = []
        for file_path, content in source_files.items():
            for match in regex.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                matches.append(f"{file_path}:{line_num}")

                # Attribute to enclosing function
                preceding = content[:match.start()]
                fn_matches = list(re.finditer(r"function\s+(\w+)", preceding))
                contract_matches = list(re.finditer(
                    r"(?:contract|library|interface)\s+(\w+)", preceding))
                if fn_matches and contract_matches:
                    fn_name = fn_matches[-1].group(1)
                    contract_name = contract_matches[-1].group(1)
                    sg.add_flag(f"fn:{contract_name}.{fn_name}", flag_name)

        if matches:
            results[flag_name] = matches
            sg.add_global_flag(flag_name)

    return results
