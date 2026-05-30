"""
avadhi/tools/bulk_scrape_clarahacks.py
─────────────────────────────────────────────────────────────────────────────
Bulk Scraper for ClaraHacks Incidents
─────────────────────────────────────────────────────────────────────────────
Scrapes ALL incidents (1-618+) from ClaraHacks and saves them beautifully
into a single Markdown file.

Usage:
    export CLARA_COOKIE="<your_entire_cookie_string>"
    python -m avadhi.tools.bulk_scrape_clarahacks
"""

import asyncio
import os
import re
from datetime import datetime
try:
    import httpx
    from bs4 import BeautifulSoup
except ImportError:
    print("Please install requirements: pip install httpx beautifulsoup4")
    exit(1)

BASE_URL = "https://www.clarahacks.com"
OUTPUT_FILE = "clarahacks_all_reports.md"


def get_headers():
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    cookie = os.environ.get("CLARA_COOKIE")
    if cookie:
        headers["Cookie"] = cookie
    return headers


async def fetch_page_incidents(client: httpx.AsyncClient, page: int) -> list[dict]:
    """Fetch a single page of the dashboard and extract incident metadata via Regex."""
    url = f"{BASE_URL}/?page={page}"
    try:
        r = await client.get(url, headers=get_headers(), follow_redirects=True, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"⚠️ Failed to fetch page {page}: {e}")
        return []

    # Next.js App Router embeds JSON strings in the HTML for Server Components.
    # We can extract the incident objects via regex.
    pattern = r'\\"public_incident_id\\":\\"(.*?)\\",\\"title\\":\\"(.*?)\\",\\"incident_time\\":\\"(.*?)\\",.*?\\"usd_loss_label\\":\\"(.*?)\\"'
    matches = re.findall(pattern, r.text)
    
    incidents = []
    for slug, title, date, loss in matches:
        incidents.append({
            "slug": slug,
            "title": title.replace('\\\\', ''),
            "date": date.split("T")[0],
            "loss": loss.replace('\\\\', '').replace('$$', '$')
        })
        
    return incidents


async def fetch_incident_detail(client: httpx.AsyncClient, slug: str) -> str:
    """Fetch the full report for a specific incident and extract readable text."""
    url = f"{BASE_URL}/incidents/{slug}"
    try:
        r = await client.get(url, headers=get_headers(), follow_redirects=True, timeout=30)
        r.raise_for_status()
    except Exception:
        return "*(Failed to load report or access denied)*"

    soup = BeautifulSoup(r.text, "html.parser")
    
    # Remove navigation, scripts, and footers
    for tag in soup(["script", "style", "nav", "footer", "header", "button"]):
        tag.decompose()
        
    # Extract visible text. ClaraHacks renders the Markdown directly into the HTML.
    text = soup.get_text("\n", strip=True)
    
    # Basic cleanup
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    
    # Try to find the start of the report
    start_idx = 0
    for i, line in enumerate(lines):
        if "Root Cause Analysis" in line or "1. Incident Overview" in line:
            start_idx = i
            break
            
    content = "\n\n".join(lines[start_idx:])
    
    if len(content) < 100:
        return "*(Report content is locked, empty, or requires subscription unlock)*"
        
    return content


async def run():
    print("🚀 Starting ClaraHacks Bulk Scraper...")
    if not os.environ.get("CLARA_COOKIE"):
        print("⚠️ WARNING: CLARA_COOKIE not set. Subscriber-only incidents will be locked.")
        print("   Set it via: export CLARA_COOKIE=\"your_cookie\"\n")

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=5)) as client:
        all_incidents = []
        total_pages = 13 # ClaraHacks currently has ~13 pages of incidents
        
        print(f"📥 Collecting incident list (Pages 1 to {total_pages})...")
        for p in range(1, total_pages + 1):
            page_data = await fetch_page_incidents(client, p)
            if not page_data:
                # Reached the end early
                if p > 5:
                    break
            all_incidents.extend(page_data)
            await asyncio.sleep(0.5)
            
        OUTPUT_DIR = "data/clarahacks_reports"
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"\n✅ Found {len(all_incidents)} total incidents. Fetching and saving individually to {OUTPUT_DIR}/...\n")
            
        success_count = 0
        
        for i, inc in enumerate(all_incidents, 1):
            slug = inc["slug"]
            title = inc["title"]
            print(f"[{i}/{len(all_incidents)}] Fetching: {title}...")
            
            detail_text = await fetch_incident_detail(client, slug)
            
            md = f"## 🚨 {title}\n\n"
            md += f"**Date:** {inc['date']}  |  **Loss:** {inc['loss']}\n"
            md += f"**Link:** [{BASE_URL}/incidents/{slug}]({BASE_URL}/incidents/{slug})\n\n"
            md += f"### Report Content\n\n{detail_text}\n\n"
            
            # Create a safe filename
            safe_title = "".join([c if c.isalnum() or c in " -_" else "_" for c in title])
            safe_date = inc['date'].split("T")[0]
            filename = f"{safe_date}_{safe_title[:50]}.md".replace(" ", "_").lower()
            filepath = os.path.join(OUTPUT_DIR, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md)
                
            success_count += 1
            await asyncio.sleep(0.2) # Polite rate limiting

    print(f"\n🎉 Done! Successfully scraped {success_count} reports.")
    print(f"📁 Output saved as individual files in: {os.path.abspath(OUTPUT_DIR)}")


if __name__ == "__main__":
    asyncio.run(run())

