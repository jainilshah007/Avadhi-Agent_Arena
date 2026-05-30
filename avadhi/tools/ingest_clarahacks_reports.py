"""
avadhi/tools/ingest_clarahacks_reports.py
─────────────────────────────────────────────────────────────────────────────
High-Quality Ingestion: 618 ClaraHacks Incident Reports → RAG Database
─────────────────────────────────────────────────────────────────────────────

Strategy
────────
1. SEMANTIC SECTION CHUNKING — rather than splitting by character count, we
   split each report by its natural sections (Root Cause Analysis, Code
   Analysis, Adversary Flow Analysis, Impact, etc.). Each section becomes its
   own chunk. This means every embedding is semantically self-contained and
   the retriever won't return half a thought.

2. DUAL-MODEL EMBEDDING — identical to the rest of the DB:
   • embedding_text  → text-embedding-3-small (OpenAI, 1536-dim) — prose
   • embedding_code  → voyage-code-3          (Voyage, 1024-dim)  — code

3. MAXIMUM PRIORITY TAGGING — these are ground-truth real-world exploits.
   Tags include:
   • "clarahacks", "real_world_incident", "high_priority", "priority_10"

4. IDEMPOTENT — checks raw_documents to avoid unique constraint errors.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import asyncpg
except ImportError:
    sys.exit(1)

try:
    import openai
except ImportError:
    sys.exit(1)

try:
    import voyageai
except ImportError:
    sys.exit(1)

REPORTS_DIR = Path("data/clarahacks_reports")
VOYAGE_MODEL = "voyage-code-3"
OPENAI_MODEL = "text-embedding-3-small"
MAX_SECTION_CHARS = 3500

BASE_TAGS = ["clarahacks", "real_world_incident", "high_priority", "priority_10"]

SECTION_MAP = {
    "Root Cause Analysis":       ("root_cause_analysis",  ["root_cause"]),
    "1. Incident Overview":       ("incident_overview",    ["incident_summary"]),
    "2. Key Background":          ("key_background",       ["protocol_context"]),
    "3. Vulnerability Analysis":  ("vuln_analysis",        ["vulnerability"]),
    "4. Detailed Root Cause":     ("detailed_root_cause",  ["root_cause", "vulnerability"]),
    "5. Adversary Flow":          ("adversary_flow",       ["attack_flow", "exploit_path"]),
    "6. Impact":                  ("impact",               ["impact_assessment"]),
    "7. References":              ("references",           ["references"]),
    "Code Analysis":              ("code_analysis",        ["code_analysis", "vulnerability"]),
    "Execution Trace":            ("execution_trace",      ["execution_trace", "attack_flow"]),
    "Report Content":             ("full_report",          ["full_report"]),
}

VULN_PATTERNS = [
    (re.compile(r"reentrancy|reentrant|CEI pattern", re.I),         "reentrancy"),
    (re.compile(r"flash.?loan|flash.?swap",           re.I),         "flash_loan"),
    (re.compile(r"oracle|price.?manipulat|TWAP",      re.I),         "oracle"),
    (re.compile(r"access.?control|onlyOwner|role",    re.I),         "access_control"),
]

@dataclass
class ReportSection:
    header: str
    text: str
    subcategory: str
    section_tags: list[str]
    has_code: bool
    vuln_tags: list[str] = field(default_factory=list)

    @property
    def all_tags(self) -> list[str]:
        return list(dict.fromkeys(BASE_TAGS + self.section_tags + self.vuln_tags))

@dataclass
class ParsedReport:
    filename: str
    title: str
    date: str
    loss: str
    link: str
    sections: list[ReportSection]

def _detect_vuln_tags(text: str) -> list[str]:
    return [tag for pattern, tag in VULN_PATTERNS if pattern.search(text)]

def _split_sections(content: str) -> list[tuple[str, str]]:
    parts = re.split(r'\n(?=#{1,4} )', content)
    if len(parts) > 1:
        result = []
        for part in parts:
            lines = part.strip().split("\n", 1)
            if len(lines) > 1 and lines[1].strip():
                result.append((lines[0].lstrip("#").strip(), lines[1].strip()))
        return result

    section_names = list(SECTION_MAP.keys())
    pattern = r'(?m)^(' + '|'.join(re.escape(s) for s in section_names) + r')'
    parts = re.split(pattern, content)
    if len(parts) <= 1:
        return [("Report Content", content.strip())]

    result = []
    i = 1
    while i < len(parts) - 1:
        header = parts[i].strip()
        body = parts[i + 1].strip() if i + 1 < len(parts) else ""
        if body:
            result.append((header, body))
        i += 2
    return result or [("Report Content", content.strip())]

def parse_report(filepath: Path) -> ParsedReport | None:
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return None

    title_m = re.search(r"## 🚨 (.+)", content)
    date_m  = re.search(r"\*\*Date:\*\* (.+?)  \|", content)
    loss_m  = re.search(r"\*\*Loss:\*\* (.+)", content)
    link_m  = re.search(r"\*\*Link:\*\* \[.+?\]\((.+?)\)", content)

    title = title_m.group(1).strip() if title_m else filepath.stem
    date  = date_m.group(1).strip()  if date_m  else "unknown"
    loss  = loss_m.group(1).strip()  if loss_m  else "unknown"
    link  = link_m.group(1).strip()  if link_m  else ""

    header_end = content.find("### Report Content\n")
    if header_end == -1:
        header_end = content.find("\n\n", content.find("**Link:**") or 0)
    body = content[header_end:].strip() if header_end > 0 else content

    if len(body) < 200 or "Incident Locked" in body:
        return None

    sections = []
    for header, text in _split_sections(body):
        chunks = [text] if len(text) <= MAX_SECTION_CHARS else [p.strip() for p in re.split(r'\n{2,}', text) if p.strip()]
        
        subcat, stags = "general", []
        for key, (sc, st) in SECTION_MAP.items():
            if key.lower() in header.lower():
                subcat, stags = sc, st
                break

        for chunk in chunks:
            if not chunk: continue
            sections.append(ReportSection(
                header=header,
                text=f"# {title}\n## {header}\n\n{chunk}",
                subcategory=subcat,
                section_tags=stags,
                has_code=bool(re.search(r"(function |mapping\(|require\(|emit |\.sol)", chunk)),
                vuln_tags=_detect_vuln_tags(chunk),
            ))

    return ParsedReport(filepath.name, title, date, loss, link, sections)

class DualEmbedder:
    def __init__(self):
        self._openai = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._voyage = voyageai.Client(api_key=os.environ["VOYAGE_API_KEY"])

    def embed_both(self, text: str):
        cv = self._voyage.embed([text[:16000]], model=VOYAGE_MODEL, input_type="document").embeddings[0]
        tv = self._openai.embeddings.create(model=OPENAI_MODEL, input=text[:8000]).data[0].embedding
        return cv, tv

async def _ensure_source(conn):
    row = await conn.fetchrow("SELECT id FROM data_sources WHERE name = 'clarahacks_incidents'")
    if row: return str(row["id"])
    row = await conn.fetchrow("""
        INSERT INTO data_sources (id, name, category, source_type, metadata) 
        VALUES (gen_random_uuid(), 'clarahacks_incidents', 'bug_pattern', 'incident_tracker', '{}'::jsonb) RETURNING id
    """)
    return str(row["id"])

async def ingest_report(pool, embedder, report, verbose=False):
    if not report.sections: return 0

    async with pool.acquire() as conn:
        source_id = await _ensure_source(conn)
        file_path = f"clarahacks://{report.filename}"

        doc_row = await conn.fetchrow("SELECT id FROM raw_documents WHERE source_id = $1::uuid AND file_path = $2", source_id, file_path)
        if doc_row:
            doc_id = str(doc_row["id"])
        else:
            doc_row = await conn.fetchrow("""
                INSERT INTO raw_documents (id, source_id, file_path, title, content_raw, doc_type, language, word_count, char_count, metadata) 
                VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, 'incident_report', 'en', $5, $6, $7::jsonb) RETURNING id
            """, source_id, file_path, report.title, "\n\n".join(s.text for s in report.sections), sum(len(s.text.split()) for s in report.sections), sum(len(s.text) for s in report.sections), json.dumps({"date": report.date, "loss": report.loss, "link": report.link}))
            doc_id = str(doc_row["id"])

    inserted = 0
    for i, section in enumerate(report.sections):
        try:
            cv, tv = embedder.embed_both(section.text)
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO document_embeddings (id, source_doc_id, chunk_index, chunk_text, chunk_tokens, category, subcategory, tags, has_code, code_language, embed_model, embedding_code, embedding_text) 
                    VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, 'bug_pattern', $5, $6, $7, 'solidity', $8, $9::vector, $10::vector) ON CONFLICT DO NOTHING
                """, doc_id, i, section.text, len(section.text.split()), section.subcategory, section.all_tags, section.has_code, f"{VOYAGE_MODEL}+{OPENAI_MODEL}", json.dumps(cv), json.dumps(tv))
                inserted += 1
        except Exception as e:
            if verbose: print(f"      ⚠️  Error on section {i}: {e}")

    if verbose and inserted:
        print(f"    ✔  '{report.title}' — {inserted}/{len(report.sections)} sections ingested")
    return inserted

async def main(verbose=False, limit=None):
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=2, max_size=6)
    embedder = DualEmbedder()
    files = sorted(REPORTS_DIR.glob("*.md"))[:limit] if limit else sorted(REPORTS_DIR.glob("*.md"))
    
    total = 0
    for idx, filepath in enumerate(files, 1):
        report = parse_report(filepath)
        if report:
            if verbose: print(f"[{idx}/{len(files)}] Processing: {report.title}")
            total += await ingest_report(pool, embedder, report, verbose)
            await asyncio.sleep(0.1)
    await pool.close()
    print(f"\n🎉 Done! Total chunks inserted: {total}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    asyncio.run(main(verbose=args.verbose, limit=args.limit))
