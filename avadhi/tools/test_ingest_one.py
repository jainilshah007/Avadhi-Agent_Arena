import asyncio
import json
import os
import re
from pathlib import Path

import asyncpg
import openai
import voyageai

# ── Configuration ─────────────────────────────────────────────────────────────
REPORTS_DIR = Path("data/clarahacks_reports")
VOYAGE_MODEL = "voyage-code-3"
OPENAI_MODEL = "text-embedding-3-small"
BASE_TAGS = ["clarahacks", "real_world_incident", "high_priority", "priority_10"]

SECTION_MAP = {
    "Root Cause Analysis":       ("root_cause_analysis",  ["root_cause"]),
    "Code Analysis":              ("code_analysis",        ["code_analysis", "vulnerability"]),
    "Execution Trace":            ("execution_trace",      ["execution_trace", "attack_flow"]),
}

def parse_report(filepath: Path):
    content = filepath.read_text(encoding="utf-8")
    title_m = re.search(r"## 🚨 (.+)", content)
    title = title_m.group(1).strip() if title_m else filepath.stem
    
    header_end = content.find("### Report Content\n")
    body = content[header_end:].strip() if header_end > 0 else content
    
    parts = re.split(r'\n(?=#{1,4} )', body)
    sections = []
    for part in parts:
        lines = part.strip().split("\n", 1)
        header = lines[0].lstrip("#").strip()
        text = lines[1].strip() if len(lines) > 1 else ""
        if text:
            sections.append((header, text))
            
    return title, sections

async def main():
    print("🔌 Connecting to DB...")
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
    
    openai_client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    voyage_client = voyageai.Client(api_key=os.environ["VOYAGE_API_KEY"])
    
    # Pick the first report
    files = list(REPORTS_DIR.glob("*.md"))
    if not files:
        print("No reports found.")
        return
        
    test_file = files[0]
    print(f"📄 Testing with: {test_file.name}")
    
    title, sections = parse_report(test_file)
    print(f"Title: {title}")
    print(f"Found {len(sections)} sections.")
    
    async with pool.acquire() as conn:
        # Check table
        val = await conn.fetchval("SELECT COUNT(*) FROM document_embeddings")
        print(f"📊 Current chunks in DB: {val}")
        
        # Ensure source exists
        source_row = await conn.fetchrow("SELECT id FROM data_sources WHERE name = 'clarahacks_incidents'")
        if source_row:
            source_id = source_row['id']
        else:
            source_row = await conn.fetchrow("""
                INSERT INTO data_sources (id, name, category, source_type, metadata) 
                VALUES (gen_random_uuid(), 'clarahacks_incidents', 'bug_pattern', 'incident_tracker', '{}'::jsonb)
                RETURNING id
            """)
            source_id = source_row['id']
            
        print(f"Source ID: {source_id}")
        
        # Only process first section to test
        if not sections:
            print("No sections to process.")
            return
            
        header, text = sections[0]
        print(f"\nProcessing Section: {header}")
        
        print("Embedding text (OpenAI)...")
        text_vec = openai_client.embeddings.create(model=OPENAI_MODEL, input=text[:8000]).data[0].embedding
        print("Embedding code (Voyage)...")
        code_vec = voyage_client.embed([text[:16000]], model=VOYAGE_MODEL, input_type="document").embeddings[0]
        
        print("Inserting document_embeddings...")
        try:
            await conn.execute("""
                INSERT INTO document_embeddings (
                    id, chunk_index, chunk_text, chunk_tokens,
                    category, subcategory, tags, has_code, embed_model,
                    embedding_code, embedding_text
                ) VALUES (
                    gen_random_uuid(), 0, $1, $2,
                    'bug_pattern', 'test', $3, false, $4,
                    $5::vector, $6::vector
                )
            """, 
                text, len(text.split()), BASE_TAGS, f"{VOYAGE_MODEL}+{OPENAI_MODEL}",
                json.dumps(code_vec), json.dumps(text_vec)
            )
            print("✅ Successfully inserted test embedding!")
        except Exception as e:
            print(f"❌ Error inserting: {e}")
            
    await pool.close()

if __name__ == "__main__":
    asyncio.run(main())
