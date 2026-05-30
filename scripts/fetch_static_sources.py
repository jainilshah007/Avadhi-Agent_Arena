#!/usr/bin/env python3
"""
Fetch static pages, Substack articles, and direct downloads for all categories.
Uses requests + basic HTML-to-text conversion (no JS rendering).
"""

import os
import json
import time
import hashlib
import requests
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path("/Users/jainilshah/codenstuff/Avadhi/data")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ============================================
# SOURCES TO FETCH
# ============================================

WEB3_BASICS_DOWNLOADS = {
    "solidity_changelog": "https://raw.githubusercontent.com/ethereum/solidity/develop/Changelog.md",
    "solidity_bugs_json": "https://raw.githubusercontent.com/ethereum/solidity/develop/docs/bugs.json",
    "solidity_bugs_by_version": "https://raw.githubusercontent.com/ethereum/solidity/develop/docs/bugs_by_version.json",
    "yellow_paper_pdf": "https://ethereum.github.io/yellowpaper/paper.pdf",
    "ethervm_io": "https://ethervm.io/",
}

WEB3_BASICS_PAGES = {
    "ethereum_org_erc20": "https://ethereum.org/en/developers/docs/standards/tokens/erc-20/",
    "ethereum_org_erc721": "https://ethereum.org/en/developers/docs/standards/tokens/erc-721/",
    "ethereum_org_erc1155": "https://ethereum.org/en/developers/docs/standards/tokens/erc-1155/",
    "ethereum_org_erc4626": "https://ethereum.org/en/developers/docs/standards/tokens/erc-4626/",
    "dacian_yul_vulns": "https://dacian.me/solidity-inline-assembly-vulnerabilities",
}

BUG_PATTERN_PAGES = {
    "owasp_sctop10": "https://scs.owasp.org/sctop10/",
    "owasp_checklists": "https://scs.owasp.org/checklists/",
    "ethereum_security": "https://ethereum.org/en/developers/docs/smart-contracts/security/",
    "quillaudits_defi_vectors": "https://quillaudits.com/blog/web3-security/defi-attack-vectors-security-risks",
    "ethtrust_spec": "https://entethalliance.org/specs/ethtrust-sl/",
}

BUG_PATTERN_SUBSTACK = {
    "secureum_pitfalls_101": "https://secureum.substack.com/p/security-pitfalls-and-best-practices-101",
    "secureum_pitfalls_201": "https://secureum.substack.com/p/security-pitfalls-and-best-practices-201",
    "secureum_solidity_101": "https://secureum.substack.com/p/solidity-101",
    "secureum_solidity_201": "https://secureum.substack.com/p/solidity-201",
    "secureum_ethereum_101": "https://secureum.substack.com/p/ethereum-101",
}

AUDIT_METHODOLOGY_PAGES = {
    "dravee_3_prompts": "https://justdravee.github.io/posts/the-3-prompts-of-spec-thinking/",
    "dravee_state_machine": "https://justdravee.github.io/posts/thread-state-machine/",
    "dravee_categories": "https://justdravee.github.io/categories/",
    "samczsun_immunefi": "https://immunefi.com/blog/whitehat-spotlight/the-u-up-files-with-samczsun/",
    "samczsun_dark_forest": "https://samczsun.com/escaping-the-dark-forest/",
    "samczsun_all_posts": "https://samczsun.com/author/samczsun/",
    "consensys_security_mindset": "https://consensys.io/blog/the-smart-contract-security-mindset",
    "cyfrin_10_steps": "https://cyfrin.io/blog/10-steps-to-systematically-approach-a-smart-contract-audit",
    "hacken_bug_bounties": "https://hacken.io/discover/how-to-smart-contracts-bug-hunting/",
    "chainlink_bug_hunting": "https://blog.chain.link/smart-contract-bug-hunting/",
    "sm4rty_methodology": "https://sm4rty.medium.com/smart-contract-audit-methodology-tips-6e529a3f3435",
    "cyfrin_tincho_first_audit": "https://updraft.cyfrin.io/courses/security/first-audit/process-tincho",
    "cyfrin_tincho_manual_review": "https://updraft.cyfrin.io/courses/advanced-foundry/security/smart-contract-manual-review",
}

AUDIT_METHODOLOGY_SUBSTACK = {
    "secureum_audit_techniques": "https://secureum.substack.com/p/audit-techniques-and-tools-101",
    "secureum_audit_findings_101": "https://secureum.substack.com/p/audit-findings-101",
    "secureum_audit_findings_201": "https://secureum.substack.com/p/audit-findings-201",
}

PROTOCOL_LLMS_TXT = {
    "uniswap_v4_llms": "https://docs.uniswap.org/v4-llms.txt",
    "uniswap_v4_llms_full": "https://docs.uniswap.org/v4-llms-full.txt",
    "morpho_llms": "https://docs.morpho.org/llms.txt",
    "morpho_llms_full": "https://docs.morpho.org/llms-full.txt",
}

PROTOCOL_WHITEPAPERS = {
    "uniswap_v3_wp": "https://app.uniswap.org/whitepaper-v3.pdf",
    "uniswap_v4_wp": "https://app.uniswap.org/whitepaper-v4.pdf",
    "uniswapx_wp": "https://app.uniswap.org/whitepaper-uniswapx.pdf",
    "curve_stableswap_wp": "https://resources.curve.finance/pdf/curve-stableswap.pdf",
    "balancer_wp": "https://docs.balancer.fi/whitepaper.pdf",
    "aave_v3_techpaper": "https://github.com/aave/aave-v3-core/raw/master/techpaper/Aave_V3_Technical_Paper.pdf",
    "morpho_blue_wp": "https://github.com/morpho-org/morpho-blue/raw/main/morpho-blue-whitepaper.pdf",
    "compound_wp": "https://compound.finance/documents/Compound.Whitepaper.pdf",
    "makerdao_wp": "https://makerdao.com/en/whitepaper/",
    "eigenlayer_wp": "https://docs.eigencloud.xyz/assets/files/EigenLayer_WhitePaper-88c47923ca0319870c611decd6e562ad.pdf",
    "layerzero_v2_wp": "https://layerzero.network/publications/LayerZero_Whitepaper_V2.1.1.pdf",
    "nexus_mutual_wp": "https://nexusmutual.io/assets/docs/nmx_white_paperv2_3.pdf",
    "chainlink_v1_wp": "https://research.chain.link/whitepaper-v1.pdf",
    "chainlink_v2_wp": "https://research.chain.link/whitepaper-v2.pdf",
    "1inch_security_wp": "https://1inch.io/assets/1inch-security-white-paper.pdf",
}


def fetch_url(url, output_path, is_binary=False):
    """Fetch a URL and save to file."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        if is_binary:
            with open(output_path, "wb") as f:
                f.write(resp.content)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(resp.text)
        
        size = len(resp.content)
        print(f"  ✅ {os.path.basename(output_path)} ({size:,} bytes)")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {url} — {e}")
        # Save error info
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path + ".error", "w") as f:
            f.write(f"URL: {url}\nError: {str(e)}\n")
        return False


def fetch_batch(sources: dict, output_dir: str, is_binary=False, ext=None):
    """Fetch a batch of URLs."""
    results = {"success": 0, "failed": 0, "skipped": 0}
    
    for name, url in sources.items():
        if ext:
            out_file = os.path.join(output_dir, f"{name}{ext}")
        elif url.endswith(".pdf"):
            out_file = os.path.join(output_dir, f"{name}.pdf")
        elif url.endswith(".json"):
            out_file = os.path.join(output_dir, f"{name}.json")
        elif url.endswith(".md"):
            out_file = os.path.join(output_dir, f"{name}.md")
        elif url.endswith(".txt"):
            out_file = os.path.join(output_dir, f"{name}.txt")
        else:
            out_file = os.path.join(output_dir, f"{name}.html")
        
        if os.path.exists(out_file):
            print(f"  SKIP: {name} already exists")
            results["skipped"] += 1
            continue
        
        is_pdf = url.endswith(".pdf") or is_binary
        if fetch_url(url, out_file, is_binary=is_pdf):
            results["success"] += 1
        else:
            results["failed"] += 1
        
        time.sleep(0.5)  # polite delay
    
    return results


def main():
    print("=" * 60)
    print("AVADHI DATA SCRAPER — Static Pages & Downloads")
    print("=" * 60)
    
    total_success = 0
    total_failed = 0
    total_skipped = 0
    
    # 1. Web3 Basics — Direct Downloads
    print("\n📥 Web3 Basics — Direct Downloads")
    r = fetch_batch(WEB3_BASICS_DOWNLOADS, str(BASE_DIR / "web3_basics/static_pages"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 2. Web3 Basics — Static Pages
    print("\n📄 Web3 Basics — Static Pages")
    r = fetch_batch(WEB3_BASICS_PAGES, str(BASE_DIR / "web3_basics/static_pages"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 3. Bug Patterns — Static Pages
    print("\n🐛 Bug Patterns — Static Pages")
    r = fetch_batch(BUG_PATTERN_PAGES, str(BASE_DIR / "bug_patterns/static_pages"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 4. Bug Patterns — Substack
    print("\n📰 Bug Patterns — Substack Articles")
    r = fetch_batch(BUG_PATTERN_SUBSTACK, str(BASE_DIR / "bug_patterns/substack"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 5. Audit Methodology — Static Pages
    print("\n📋 Audit Methodology — Static Pages")
    r = fetch_batch(AUDIT_METHODOLOGY_PAGES, str(BASE_DIR / "audit_methodology/static_pages"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 6. Audit Methodology — Substack
    print("\n📰 Audit Methodology — Substack Articles")
    r = fetch_batch(AUDIT_METHODOLOGY_SUBSTACK, str(BASE_DIR / "audit_methodology/substack"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 7. Protocol — LLM-optimized docs
    print("\n🤖 Protocol — LLM-optimized docs (llms.txt)")
    r = fetch_batch(PROTOCOL_LLMS_TXT, str(BASE_DIR / "protocols/llms_txt"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # 8. Protocol — Whitepapers
    print("\n📄 Protocol — Whitepapers (PDFs)")
    r = fetch_batch(PROTOCOL_WHITEPAPERS, str(BASE_DIR / "protocols/pdfs"))
    total_success += r["success"]; total_failed += r["failed"]; total_skipped += r["skipped"]
    
    # Summary
    print("\n" + "=" * 60)
    print(f"SUMMARY: ✅ {total_success} fetched | ❌ {total_failed} failed | ⏭️  {total_skipped} skipped")
    print("=" * 60)
    
    # Save manifest
    manifest = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_success": total_success,
        "total_failed": total_failed,
        "total_skipped": total_skipped,
    }
    with open(str(BASE_DIR / "fetch_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()
