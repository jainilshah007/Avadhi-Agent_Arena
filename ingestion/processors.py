"""
ingestion/processors.py
────────────────────────────────────────────────────────────────────────────
Per-file-type content loaders and cleaners.
Each function accepts a file Path and returns:
  (content_raw: str, content_clean: str, title: str | None, metadata: dict)

The pipeline calls these before chunking. Chunkers only receive clean text.
"""
from __future__ import annotations

import re
import logging
from pathlib import Path

import chardet

logger = logging.getLogger(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_file(path: Path) -> str:
    """Read a text file with automatic encoding detection."""
    raw_bytes = path.read_bytes()
    detected = chardet.detect(raw_bytes)
    encoding = detected.get("encoding") or "utf-8"
    try:
        text = raw_bytes.decode(encoding, errors="replace")
    except (UnicodeDecodeError, LookupError):
        text = raw_bytes.decode("utf-8", errors="replace")
    # PostgreSQL strictly prevents inserting null bytes (\x00) into TEXT fields.
    return text.replace("\x00", "")


def _basic_clean(text: str) -> str:
    """Remove control characters, normalize whitespace."""
    # Remove null bytes and other non-printable control chars
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Normalize consecutive blank lines to max 2
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def _extract_title_from_markdown(content: str) -> str | None:
    """Return first H1 heading from markdown content."""
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    return match.group(1).strip() if match else None


def _extract_title_from_html(content: str) -> str | None:
    """Return <title> or first <h1> tag value."""
    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
    if title_match:
        return re.sub(r'<[^>]+>', '', title_match.group(1)).strip()
    h1_match = re.search(r'<h1[^>]*>(.*?)</h1>', content, re.IGNORECASE | re.DOTALL)
    if h1_match:
        return re.sub(r'<[^>]+>', '', h1_match.group(1)).strip()
    return None


# ── Per-type processors ───────────────────────────────────────────────────────

def process_solidity(path: Path) -> tuple[str, str, str | None, dict]:
    """Load and minimally clean a Solidity source file."""
    raw = _read_file(path)
    clean = _basic_clean(raw)

    # Extract contract name from file
    title = path.stem  # e.g., "UniswapV3Pool"

    # Extract metadata
    pragma_match = re.search(r'pragma solidity ([^;]+);', raw)
    contract_names = re.findall(r'\bcontract\s+(\w+)', raw)
    imports = re.findall(r'import\s+["\']([^"\']+)["\']', raw)
    has_delegatecall = "delegatecall" in raw.lower()
    has_assembly = "assembly" in raw.lower()
    has_external_call = bool(re.search(r'\.call\s*[\(\{]', raw, re.IGNORECASE))

    metadata = {
        "sol_version": pragma_match.group(1).strip() if pragma_match else None,
        "contract_names": contract_names,
        "loc": len(raw.splitlines()),
        "imports": imports[:30],  # cap at 30
        "has_delegatecall": has_delegatecall,
        "has_assembly": has_assembly,
        "has_external_calls": has_external_call,
    }
    return raw, clean, title, metadata


def process_markdown(path: Path) -> tuple[str, str, str | None, dict]:
    """Load and clean a Markdown file."""
    raw = _read_file(path)
    clean = _basic_clean(raw)
    title = _extract_title_from_markdown(clean) or path.stem
    return raw, clean, title, {"loc": len(raw.splitlines())}


def process_html(path: Path) -> tuple[str, str, str | None, dict]:
    """Load HTML, extract clean text via BeautifulSoup."""
    from bs4 import BeautifulSoup
    from markdownify import markdownify as md

    raw = _read_file(path)
    title = _extract_title_from_html(raw)

    soup = BeautifulSoup(raw, "html.parser")
    for tag in soup(["nav", "footer", "header", "script", "style",
                     "aside", "form", "button"]):
        tag.decompose()

    main = soup.find("main") or soup.find("article") or soup.find("body") or soup
    markdown_text = md(str(main), heading_style="ATX", strip=["img", "a"])
    clean = _basic_clean(markdown_text)

    return raw, clean, title or path.stem, {}


def process_pdf(path: Path) -> tuple[str, str, str | None, dict]:
    """Extract text from PDF using PyMuPDF (fitz)."""
    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise ImportError("PyMuPDF not installed. Run: pip install PyMuPDF")

    doc = fitz.open(str(path))
    pages_text: list[str] = []

    for page_num, page in enumerate(doc):
        text = page.get_text("text")
        if text.strip():
            pages_text.append(f"[Page {page_num + 1}]\n{text}")

    doc.close()

    raw = "\n\n".join(pages_text)
    clean = _basic_clean(raw)
    # Try to get PDF title from metadata
    doc2 = fitz.open(str(path))
    pdf_meta = doc2.metadata
    doc2.close()

    title = pdf_meta.get("title") or path.stem
    metadata = {
        "page_count": len(pages_text),
        "pdf_author": pdf_meta.get("author"),
        "pdf_subject": pdf_meta.get("subject"),
    }
    return raw, clean, title, metadata


def process_plain_text(path: Path) -> tuple[str, str, str | None, dict]:
    """Load a plain text file (.txt, substack export, manual paste)."""
    raw = _read_file(path)
    clean = _basic_clean(raw)

    # Try to extract a title from the first non-empty line
    lines = [l.strip() for l in clean.splitlines() if l.strip()]
    title = lines[0][:120] if lines else path.stem

    # For manual paste files, the second line is often "Source: <url>"
    source_url = None
    for line in lines[:5]:
        if line.lower().startswith("source:"):
            source_url = line.split(":", 1)[1].strip()
            break

    return raw, clean, title, {"source_url": source_url}


def process_rst(path: Path) -> tuple[str, str, str | None, dict]:
    """Load an RST file (Solidity docs, Sphinx documentation)."""
    raw = _read_file(path)
    clean = _basic_clean(raw)
    # First RST title is underlined with === or ---
    lines = clean.splitlines()
    title = None
    for i, line in enumerate(lines):
        if i + 1 < len(lines) and re.match(r'^[=\-~^"]{3,}$', lines[i + 1]):
            title = line.strip()
            break
    return raw, clean, title or path.stem, {}


# ── Dispatch ──────────────────────────────────────────────────────────────────

def process_file(path: Path, doc_type: str) -> tuple[str, str, str | None, dict]:
    """
    Route to the correct processor based on doc_type.
    Returns (content_raw, content_clean, title, metadata).
    """
    raw, clean, title, metadata = "", "", path.stem, {}
    try:
        if doc_type == "solidity":
            raw, clean, title, metadata = process_solidity(path)
        elif doc_type in ("vyper", "yul"):
            raw = _read_file(path)
            clean = _basic_clean(raw)
            title, metadata = path.stem, {"loc": len(raw.splitlines())}
        elif doc_type == "markdown":
            raw, clean, title, metadata = process_markdown(path)
        elif doc_type == "html":
            raw, clean, title, metadata = process_html(path)
        elif doc_type == "pdf":
            raw, clean, title, metadata = process_pdf(path)
        elif doc_type == "rst":
            raw, clean, title, metadata = process_rst(path)
        else:  # plain_text, json, unknown
            raw, clean, title, metadata = process_plain_text(path)
    except Exception as e:
        logger.error("Failed to process %s: %s", path, e)
        try:
            raw = _read_file(path)
        except Exception:
            pass
        metadata = {"processing_error": str(e)}

    # Globally strip PostgreSQL-breaking null bytes no matter which processor handled it
    raw = raw.replace("\x00", "")
    clean = clean.replace("\x00", "")
    
    return raw, clean, title, metadata
