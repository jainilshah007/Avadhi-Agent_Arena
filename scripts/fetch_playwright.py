#!/usr/bin/env python3
"""
Playwright-based scraper for pages that blocked regular requests.
Handles: Medium 403s, JS-rendered sites, SSL errors, rate limits.
"""

import asyncio
import os
import time
import json
from pathlib import Path
from playwright.async_api import async_playwright

BASE_DIR = Path("/Users/jainilshah/codenstuff/Avadhi/data")

# ============================================
# ALL FAILED SOURCES
# ============================================

FAILED_PAGES = {
    # Medium 403s — Audit Methodology
    "audit_methodology/static_pages/sm4rty_methodology": 
        "https://sm4rty.medium.com/smart-contract-audit-methodology-tips-6e529a3f3435",
    
    # Medium 403s — Protocol Articles
    "protocols/articles/uniswap_v3_deep_dive":
        "https://trapdoortech.medium.com/uniswap-deep-dive-into-v3-technical-white-paper-2fe2b5c90d2",
    "protocols/articles/balancer_v2_intro":
        "https://medium.com/balancer-protocol/balancer-v2-generalizing-amms-16343c4563ff",
    "protocols/articles/pendle_v2_foundation":
        "https://medium.com/pendle/pendle-v2-part-1-3-foundation-6e1773a1d2f4",
    "protocols/articles/gmx_v2_changes":
        "https://ld-capital.medium.com/changes-and-impacts-of-gmx-v2-6ed0e4c10f93",
    "protocols/articles/layerzero_v2_deep_dive":
        "https://medium.com/layerzero-official/layerzero-v2-deep-dive-869f93e09850",
    "protocols/articles/across_v3_intents":
        "https://medium.com/across-protocol/across-v3-introducing-the-first-intents-based-interoperability-protocol-5a54eb03bc18",
    "protocols/articles/yearn_v3_blog":
        "https://medium.com/iearn/yearn-vaults-v3-36ce7c468ca0",
    
    # SSL / Rate Limit / Blocked
    "audit_methodology/static_pages/hacken_bug_bounties":
        "https://hacken.io/discover/how-to-smart-contracts-bug-hunting/",
    "web3_basics/static_pages/dacian_yul_vulns":
        "https://dacian.me/solidity-inline-assembly-vulnerabilities",
    
    # Blocked docs sites
    "protocols/static_pages/eigenlayer_docs":
        "https://docs.eigencloud.xyz/",
    
    # Playwright-needed methodology pages
    "audit_methodology/static_pages/huw_grano_methodology":
        "https://coinsbench.com/developing-a-smart-contract-audit-methodology-8a29ebe25513",
    "audit_methodology/static_pages/samczsun_consensys_interview":
        "https://consensys.net/diligence/blog/2020/01/interview-with-samczsun/",
}


async def scrape_page(page, name, url, output_dir):
    """Scrape a single page with Playwright."""
    output_path = os.path.join(str(output_dir), f"{os.path.basename(name)}.html")
    
    # Skip if already fetched
    if os.path.exists(output_path) and os.path.getsize(output_path) > 100:
        print(f"  SKIP: {os.path.basename(name)} (already exists)")
        return "skipped"
    
    try:
        # Navigate with extended timeout
        response = await page.goto(url, wait_until="networkidle", timeout=30000)
        
        # Wait for content to render
        await page.wait_for_timeout(2000)
        
        # For Medium, try to dismiss popups
        if "medium.com" in url:
            try:
                await page.wait_for_timeout(1000)
                # Try closing paywall/login overlays
                for sel in ['button[aria-label="close"]', '[data-testid="close-button"]', 
                           'button:has-text("Continue reading")', '[aria-label="Close"]']:
                    try:
                        btn = page.locator(sel).first
                        if await btn.is_visible(timeout=1000):
                            await btn.click()
                            await page.wait_for_timeout(500)
                    except:
                        pass
            except:
                pass
        
        # Get full page HTML
        html_content = await page.content()
        
        # Also extract clean text for easier processing
        text_content = await page.evaluate("""() => {
            // Try to get article content specifically
            const article = document.querySelector('article') || 
                           document.querySelector('[role="main"]') ||
                           document.querySelector('main') ||
                           document.querySelector('.post-content') ||
                           document.querySelector('.article-content');
            if (article) return article.innerText;
            return document.body.innerText;
        }""")
        
        # Ensure output dir exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save HTML
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        # Save clean text version too
        text_path = output_path.replace(".html", ".txt")
        with open(text_path, "w", encoding="utf-8") as f:
            f.write(text_content)
        
        size = len(html_content)
        text_size = len(text_content)
        print(f"  ✅ {os.path.basename(name)} ({size:,} bytes HTML, {text_size:,} bytes text)")
        return "success"
        
    except Exception as e:
        print(f"  ❌ {os.path.basename(name)}: {e}")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path + ".error", "w") as f:
            f.write(f"URL: {url}\nError: {str(e)}\n")
        return "failed"


async def scrape_evmresearch(page, output_dir):
    """
    Crawl evmresearch.io — Obsidian Publish site with 400+ notes.
    Navigates the sidebar tree and extracts each section.
    """
    base_url = "https://evmresearch.io"
    evm_dir = os.path.join(str(output_dir), "evmresearch")
    os.makedirs(evm_dir, exist_ok=True)
    
    # Check if already crawled
    existing = len([f for f in os.listdir(evm_dir) if f.endswith('.txt')]) if os.path.exists(evm_dir) else 0
    if existing > 50:
        print(f"  SKIP: evmresearch.io ({existing} pages already crawled)")
        return "skipped"
    
    print(f"\n  🕸️  Crawling evmresearch.io (Obsidian Publish — this will take a few minutes)...")
    
    # Key section URLs to crawl
    sections = [
        "vulnerability-patterns/vulnerability-patterns",
        "evm-internals/evm-internals",
        "solidity-behaviors/solidity-behaviors",
        "protocol-mechanics/protocol-mechanics",
        "exploit-analyses/exploit-analyses",
        "security-patterns/security-patterns",
    ]
    
    total_pages = 0
    
    try:
        for section in sections:
            section_url = f"{base_url}/{section}"
            section_name = section.split("/")[0]
            section_dir = os.path.join(evm_dir, section_name)
            os.makedirs(section_dir, exist_ok=True)
            
            try:
                await page.goto(section_url, wait_until="networkidle", timeout=30000)
                await page.wait_for_timeout(3000)
                
                # Get all internal links from the page
                links = await page.evaluate("""() => {
                    const links = [];
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.getAttribute('href');
                        if (href && !href.startsWith('http') && !href.startsWith('#') && !href.startsWith('mailto:')) {
                            links.push({href: href, text: a.innerText.trim()});
                        }
                    });
                    // Also get links from the navigation/sidebar
                    document.querySelectorAll('.tree-item-inner, .nav-file-title-content').forEach(el => {
                        const a = el.closest('a') || el.querySelector('a');
                        if (a && a.href) {
                            links.push({href: a.href, text: el.innerText.trim()});
                        }
                    });
                    return [...new Map(links.map(l => [l.href, l])).values()];
                }""")
                
                # Get the main page content
                content = await page.evaluate("() => document.querySelector('.markdown-preview-view, .publish-article-container, article, main')?.innerText || document.body.innerText")
                
                fname = f"{section_name}_index.txt"
                with open(os.path.join(section_dir, fname), "w", encoding="utf-8") as f:
                    f.write(content)
                total_pages += 1
                
                # Follow internal links within this section
                for link in links[:50]:  # Cap at 50 per section
                    href = link["href"]
                    if section_name in href or href.startswith("/"):
                        full_url = href if href.startswith("http") else f"{base_url}/{href.lstrip('/')}"
                        link_name = link["text"].replace("/", "-").replace(" ", "_")[:60] or href.split("/")[-1]
                        out_file = os.path.join(section_dir, f"{link_name}.txt")
                        
                        if os.path.exists(out_file):
                            continue
                        
                        try:
                            await page.goto(full_url, wait_until="networkidle", timeout=15000)
                            await page.wait_for_timeout(1000)
                            
                            sub_content = await page.evaluate("""() => {
                                const el = document.querySelector('.markdown-preview-view, .publish-article-container, article, main');
                                return el ? el.innerText : document.body.innerText;
                            }""")
                            
                            if len(sub_content) > 100:
                                with open(out_file, "w", encoding="utf-8") as f:
                                    f.write(sub_content)
                                total_pages += 1
                        except Exception as e:
                            pass  # Skip failed sub-pages silently
                        
                        await page.wait_for_timeout(300)  # rate limit
                
                print(f"    📂 {section_name}: done")
                
            except Exception as e:
                print(f"    ❌ {section_name}: {e}")
        
        print(f"  ✅ evmresearch.io: {total_pages} pages crawled")
        return "success"
        
    except Exception as e:
        print(f"  ❌ evmresearch.io crawl failed: {e}")
        return "failed"


async def main():
    print("=" * 60)
    print("PLAYWRIGHT SCRAPER — Failed & JS-Rendered Pages")
    print("=" * 60)
    
    success = 0
    failed = 0
    skipped = 0
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800},
        )
        page = await context.new_page()
        
        # 1. Scrape all failed pages
        print(f"\n📄 Scraping {len(FAILED_PAGES)} failed pages...")
        for name, url in FAILED_PAGES.items():
            output_dir = os.path.dirname(os.path.join(str(BASE_DIR), name))
            result = await scrape_page(page, name, url, BASE_DIR)
            if result == "success":
                success += 1
            elif result == "failed":
                failed += 1
            else:
                skipped += 1
            await page.wait_for_timeout(1000)  # polite delay
        
        # 2. Crawl evmresearch.io
        print(f"\n🕸️  Crawling evmresearch.io (JS-rendered Obsidian Publish)...")
        evm_result = await scrape_evmresearch(page, BASE_DIR / "bug_patterns" / "static_pages")
        if evm_result == "success":
            success += 1
        elif evm_result == "failed":
            failed += 1
        else:
            skipped += 1
        
        await browser.close()
    
    print(f"\n{'=' * 60}")
    print(f"DONE: ✅ {success} scraped | ❌ {failed} failed | ⏭️  {skipped} skipped")
    print(f"{'=' * 60}")
    
    # Update manifest
    manifest_path = str(BASE_DIR / "playwright_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump({
            "scraped_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "success": success,
            "failed": failed,
            "skipped": skipped,
        }, f, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
