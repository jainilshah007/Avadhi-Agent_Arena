#!/usr/bin/env python3
"""
Fetch protocol documentation sites and key explainer articles.
Only fetches index/overview pages (not full mirror — that would be excessive).
"""

import os
import time
import json
import requests
from pathlib import Path

BASE_DIR = Path("/Users/jainilshah/codenstuff/Avadhi/data/protocols")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Protocol Docs: key overview/intro pages (not full site mirrors)
PROTOCOL_DOC_PAGES = {
    # AMMs
    "uniswap_v3_docs": "https://docs.uniswap.org/contracts/v3/overview",
    "uniswap_v4_docs": "https://docs.uniswap.org/contracts/v4/overview",
    "uniswapx_docs": "https://docs.uniswap.org/contracts/uniswapx/overview",
    "uniswapx_arch": "https://docs.uniswap.org/contracts/uniswapx/architecture",
    "curve_docs": "https://docs.curve.finance",
    "balancer_v2_docs": "https://docs-v2.balancer.fi/",
    "cow_docs": "https://docs.cow.fi/",
    
    # Lending
    "aave_v3_docs": "https://aave.com/docs/aave-v3/overview",
    "morpho_docs": "https://docs.morpho.org/",
    "compound_docs": "https://docs.compound.finance/",
    "euler_docs": "https://docs.euler.finance/",
    "euler_lite_paper": "https://docs.euler.finance/lite-paper/",
    "gearbox_docs": "https://docs.gearbox.finance/",
    "maple_docs": "https://maplefinance.gitbook.io/maple/",
    
    # Stablecoins / CDP
    "makerdao_docs": "https://docs.makerdao.com/",
    "ethena_docs": "https://docs.ethena.fi",
    "frax_docs": "https://docs.frax.com/",
    
    # LST / Restaking
    "lido_docs": "https://docs.lido.fi/",
    "eigenlayer_docs": "https://docs.eigencloud.xyz/",
    "etherfi_docs": "https://etherfi.gitbook.io/etherfi/",
    "pendle_docs": "https://docs.pendle.finance/",
    
    # Perps
    "gmx_docs": "https://docs.gmx.io/docs/intro/",
    "synthetix_docs": "https://docs.synthetix.io/",
    
    # Bridges / Cross-chain
    "layerzero_docs": "https://docs.layerzero.network/v2",
    "across_docs": "https://docs.across.to/",
    "chainlink_ccip_docs": "https://docs.chain.link/ccip",
    
    # Infra / Oracle
    "chainlink_docs": "https://docs.chain.link",
    "chainlink_data_feeds": "https://docs.chain.link/data-feeds",
    
    # Yield / Vaults
    "yearn_docs": "https://docs.yearn.fi",
    
    # Prediction Markets
    "polymarket_docs": "https://docs.polymarket.com",
    
    # Insurance
    "nexus_mutual_docs": "https://docs.nexusmutual.io",
    
    # DEX Infra
    "1inch_docs": "https://docs.1inch.io/",
    "permit2_docs": "https://docs.uniswap.org/contracts/permit2/overview",
    
    # Wallet Infra
    "safe_docs": "https://docs.safe.global",
    
    # Token Streaming
    "sablier_docs": "https://docs.sablier.com/",
    
    # RWA + ALM
    "centrifuge_docs": "https://docs.centrifuge.io",
    "arrakis_docs": "https://docs.arrakis.finance/",
}

# Key explainer articles
EXPLAINER_ARTICLES = {
    # AMM mechanics
    "uniswap_v3_deep_dive": "https://trapdoortech.medium.com/uniswap-deep-dive-into-v3-technical-white-paper-2fe2b5c90d2",
    "curve_deep_dive": "https://www.zealynx.io/blogs/curve-finance-core-mechanics",
    "balancer_v2_intro": "https://medium.com/balancer-protocol/balancer-v2-generalizing-amms-16343c4563ff",
    "cow_mixbytes": "https://mixbytes.io/blog/modern-dex-es-how-they-re-made-cow-protocol",
    "uniswap_v4_explained": "https://threesigma.xyz/blog/defi/uniswap-v4-features-dynamic-fees-hooks-gas-saving",
    
    # Lending mechanics
    "aave_v3_mixbytes": "https://mixbytes.io/blog/modern-defi-lending-protocols-how-its-made-aave-v3",
    "morpho_blog": "https://morpho.org/blog/morpho-blue-and-how-it-enables-our-vision-for-defi-lending/",
    "morpho_cantina": "https://cantina.xyz/blog/case-study-morpho",
    "compound_v3_rareskills": "https://rareskills.io/post/compound-v3-contracts-tutorial",
    "euler_v2_mixbytes": "https://mixbytes.io/blog/modern-defi-lending-protocols-how-its-made-euler-v2",
    
    # Stablecoins
    "ethena_usde": "https://coinmetrics.io/state-of-the-network/ethena-usde/",
    
    # LST / Restaking
    "steth_mechanics": "https://blog.lido.fi/steth-the-mechanics-of-steth/",
    "eigenlayer_consensys": "https://consensys.io/blog/eigenlayer-a-restaking-primitive",
    "pendle_v2_foundation": "https://medium.com/pendle/pendle-v2-part-1-3-foundation-6e1773a1d2f4",
    
    # Perps
    "gmx_v2_changes": "https://ld-capital.medium.com/changes-and-impacts-of-gmx-v2-6ed0e4c10f93",
    "synthetix_v3_blog": "https://blog.synthetix.io/what-is-synthetix-v3/",
    
    # Cross-chain
    "layerzero_v2_deep_dive": "https://medium.com/layerzero-official/layerzero-v2-deep-dive-869f93e09850",
    "across_v3_intents": "https://medium.com/across-protocol/across-v3-introducing-the-first-intents-based-interoperability-protocol-5a54eb03bc18",
    "ccip_intro": "https://blog.chain.link/introducing-the-cross-chain-interoperability-protocol-ccip/",
    
    # 1inch
    "1inch_fusion": "https://blog.1inch.com/a-deep-dive-into-1inch-fusion/",
    "1inch_mixbytes": "https://mixbytes.io/blog/modern-dex-es-how-they-re-made-1inch-limit-order-protocols",
    
    # Others
    "permit2_blog": "https://blog.uniswap.org/permit2-and-universal-router",
    "yearn_v3_blog": "https://medium.com/iearn/yearn-vaults-v3-36ce7c468ca0",
    "polymarket_explained": "https://rocknblock.io/blog/how-polymarket-works-the-tech-behind-prediction-markets",
    "safe_concepts": "https://docs.safe.global/advanced/smart-account-concepts",
    "sablier_cyfrin": "https://www.cyfrin.io/case-studies/hardening-sabliers-v2-2-codebase",
    "flash_loans_paper": "https://arxiv.org/pdf/2010.12252",
    "chainlink_audit_how": "https://chain.link/education-hub/how-to-audit-smart-contract",
    "oz_audit_lessons": "https://www.openzeppelin.com/news/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits",
}


def fetch_url(url, output_path, is_binary=False):
    """Fetch a URL and save to file."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        mode = "wb" if is_binary else "w"
        enc = {} if is_binary else {"encoding": "utf-8"}
        with open(output_path, mode, **enc) as f:
            f.write(resp.content if is_binary else resp.text)
        print(f"  ✅ {os.path.basename(output_path)} ({len(resp.content):,} bytes)")
        return True
    except Exception as e:
        print(f"  ❌ {os.path.basename(output_path)}: {e}")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path + ".error", "w") as f:
            f.write(f"URL: {url}\nError: {str(e)}\n")
        return False


def main():
    success = 0
    failed = 0
    
    print("=" * 60)
    print("PROTOCOL DOCS & ARTICLES SCRAPER")
    print("=" * 60)
    
    # 1. Protocol doc pages
    print(f"\n📚 Protocol Documentation ({len(PROTOCOL_DOC_PAGES)} pages)")
    for name, url in PROTOCOL_DOC_PAGES.items():
        out = str(BASE_DIR / "static_pages" / f"{name}.html")
        if os.path.exists(out):
            print(f"  SKIP: {name}")
            continue
        if fetch_url(url, out):
            success += 1
        else:
            failed += 1
        time.sleep(0.3)
    
    # 2. Explainer articles
    print(f"\n📝 Explainer Articles ({len(EXPLAINER_ARTICLES)} articles)")
    for name, url in EXPLAINER_ARTICLES.items():
        is_pdf = url.endswith(".pdf")
        ext = ".pdf" if is_pdf else ".html"
        out = str(BASE_DIR / "articles" / f"{name}{ext}")
        if os.path.exists(out):
            print(f"  SKIP: {name}")
            continue
        if fetch_url(url, out, is_binary=is_pdf):
            success += 1
        else:
            failed += 1
        time.sleep(0.3)
    
    print(f"\n{'=' * 60}")
    print(f"DONE: ✅ {success} fetched | ❌ {failed} failed")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
