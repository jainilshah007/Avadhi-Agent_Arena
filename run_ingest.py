import asyncio, json, os, re, sys
from pathlib import Path

try:
    import asyncpg, openai, voyageai
except ImportError as e:
    print(f"Missing: {e}. Run: pip install asyncpg openai voyageai")
    sys.exit(1)

REPORTS_DIR = Path("data/clarahacks_reports")
VOYAGE_MODEL = "voyage-code-3"
OPENAI_MODEL = "text-embedding-3-small"
BASE_TAGS = ["clarahacks", "real_world_incident", "high_priority", "priority_10"]

def parse_report(filepath):
    try:
        content = filepath.read_text("utf-8")
    except:
        return None
    if "Incident Locked" in content or len(content) < 300:
        return None
    
    title_m = re.search(r"## 🚨 (.+)", content)
    date_m  = re.search(r"\*\*Date:\*\* (.+?)  \|", content)
    loss_m  = re.search(r"\*\*Loss:\*\* (.+)", content)
    link_m  = re.search(r"\*\*Link:\*\* \[.+?\]\((.+?)\)", content)
    
    title = title_m.group(1).strip() if title_m else filepath.stem
    date  = date_m.group(1).strip() if date_m else "unknown"
    loss  = loss_m.group(1).strip() if loss_m else "unknown"
    link  = link_m.group(1).strip() if link_m else ""
    
    # Split by markdown headers
    parts = re.split(r'\n(?=#{1,4} )', content)
    sections = []
    for part in parts:
        lines = part.strip().split("\n", 1)
        hdr = lines[0].lstrip("#").strip()
        body = lines[1].strip() if len(lines) > 1 else ""
        if body and len(body) > 50:
            has_code = bool(re.search(r"function |mapping\(|require\(|uint\d+", body))
            sections.append({"hdr": hdr, "text": f"# {title}\n## {hdr}\n\n{body[:3500]}", "has_code": has_code})
    
    return {"filename": filepath.name, "title": title, "date": date, "loss": loss, "link": link, "sections": sections}

async def get_or_create_source(conn):
    row = await conn.fetchrow("SELECT id FROM data_sources WHERE name = 'clarahacks_incidents'")
    if row: return str(row["id"])
    row = await conn.fetchrow("""
        INSERT INTO data_sources (id, name, category, source_type, metadata)
        VALUES (gen_random_uuid(), 'clarahacks_incidents', 'bug_pattern', 'incident_tracker', '{}'::jsonb)
        RETURNING id
    """)
    return str(row["id"])

async def ingest_report(pool, oc, vc, report, source_id):
    file_path = f"clarahacks://{report['filename']}"
    
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM raw_documents WHERE source_id=$1::uuid AND file_path=$2", source_id, file_path)
        if existing:
            doc_id = str(existing["id"])
        else:
            all_text = "\n\n".join(s["text"] for s in report["sections"])
            row = await conn.fetchrow("""
                INSERT INTO raw_documents (id, source_id, file_path, title, content_raw, doc_type, language, word_count, char_count, metadata)
                VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, 'incident_report', 'en', $5, $6, $7::jsonb) RETURNING id
            """, source_id, file_path, report["title"], all_text, len(all_text.split()), len(all_text),
                json.dumps({"date": report["date"], "loss": report["loss"], "link": report["link"]}))
            doc_id = str(row["id"])

    inserted = 0
    for i, s in enumerate(report["sections"]):
        try:
            cv = vc.embed([s["text"][:16000]], model=VOYAGE_MODEL, input_type="document").embeddings[0]
            tv = oc.embeddings.create(model=OPENAI_MODEL, input=s["text"][:8000]).data[0].embedding
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO document_embeddings
                    (id, source_doc_id, chunk_index, chunk_text, chunk_tokens, category, subcategory,
                     tags, has_code, code_language, embed_model, embedding_code, embedding_text)
                    VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, 'bug_pattern', 'root_cause_analysis',
                            $5, $6, 'solidity', $7, $8::vector, $9::vector) ON CONFLICT DO NOTHING
                """, doc_id, i, s["text"], len(s["text"].split()), BASE_TAGS, s["has_code"],
                    f"{VOYAGE_MODEL}+{OPENAI_MODEL}", json.dumps(cv), json.dumps(tv))
            inserted += 1
        except Exception as e:
            pass
    return inserted

async def main():
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=2, max_size=6)
    oc = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    vc = voyageai.Client(api_key=os.environ["VOYAGE_API_KEY"])

    async with pool.acquire() as conn:
        source_id = await get_or_create_source(conn)
        before = await conn.fetchval("SELECT COUNT(*) FROM document_embeddings")

    files = sorted(REPORTS_DIR.glob("*.md"))
    total_files = len(files)
    total_inserted = 0
    skipped = 0

    print(f"\n{'='*60}")
    print(f" ClaraHacks Ingestion — {total_files} reports")
    print(f"{'='*60}\n")

    for idx, filepath in enumerate(files, 1):
        report = parse_report(filepath)
        if not report:
            skipped += 1
            pct = int((idx / total_files) * 40)
            bar = "█" * pct + "░" * (40 - pct)
            print(f"\r[{bar}] {idx}/{total_files} | ✔ {total_inserted} chunks | ⏭ {skipped} skipped", end="", flush=True)
            continue

        n = await ingest_report(pool, oc, vc, report, source_id)
        total_inserted += n
        pct = int((idx / total_files) * 40)
        bar = "█" * pct + "░" * (40 - pct)
        print(f"\r[{bar}] {idx}/{total_files} | ✔ {total_inserted} chunks | ⏭ {skipped} skipped | 📄 {report['title'][:35]}", end="", flush=True)
        await asyncio.sleep(0.05)

    async with pool.acquire() as conn:
        after = await conn.fetchval("SELECT COUNT(*) FROM document_embeddings")
    await pool.close()

    print(f"\n\n{'='*60}")
    print(f" ✅ Ingestion Complete!")
    print(f"   Reports processed : {total_files - skipped}")
    print(f"   Skipped (locked)  : {skipped}")
    print(f"   Chunks inserted   : {total_inserted}")
    print(f"   DB before         : {before:,}")
    print(f"   DB after          : {after:,}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    asyncio.run(main())
