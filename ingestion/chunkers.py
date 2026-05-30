"""
ingestion/chunkers.py
────────────────────────────────────────────────────────────────────────────
Chunking strategies for every document type.
Returns a list of Chunk dataclasses — each chunk is a self-contained unit
ready for embedding.

Design rules:
  • Solidity / code  → function-level via LangChain Language.SOL splitter
  • Markdown         → header-aware split, code fences detected per chunk
  • HTML             → convert to markdown first, then split
  • PDF              → page-aware split
  • Plain text       → recursive character split
  • Each Chunk carries has_code + code_language so the embedder routes it
    to the right model column.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from langchain_text_splitters import (
    Language,
    MarkdownTextSplitter,
    RecursiveCharacterTextSplitter,
)

from ingestion.config import CHUNK_SIZES

# ── Chunk dataclass ──────────────────────────────────────────────────────────

@dataclass
class Chunk:
    text: str
    chunk_index: int
    has_code: bool
    code_language: str | None = None
    subcategory: str | None = None
    tags: list[str] = field(default_factory=list)

    @property
    def token_estimate(self) -> int:
        """Rough token count (1 token ≈ 4 chars for English/Solidity)."""
        return max(1, len(self.text) // 4)


# ── Solidity chunker ─────────────────────────────────────────────────────────

_SOL_PREAMBLE_PATTERN = re.compile(
    r'^((?:\/\/.*\n|\/\*.*?\*\/\s*|pragma\s+\S+[^;]*;\s*|import\s+[^;]+;\s*|'
    r'\/\/\s*SPDX.*\n)*)',
    re.MULTILINE | re.DOTALL,
)

def chunk_solidity(content: str, file_path: str) -> list[Chunk]:
    """
    Use LangChain's Solidity-aware splitter (splits on contract/function/modifier
    boundaries). Prepends a preamble (pragma + imports) to every chunk so each
    chunk is self-contained and the model understands the context.
    """
    cfg = CHUNK_SIZES["solidity"]
    splitter = RecursiveCharacterTextSplitter.from_language(
        language=Language.SOL,
        chunk_size=cfg["size"],
        chunk_overlap=cfg["overlap"],
    )

    # Extract preamble (SPDX + pragma + imports)
    preamble_match = _SOL_PREAMBLE_PATTERN.match(content)
    preamble = preamble_match.group(0).strip() if preamble_match else ""

    raw_chunks = splitter.split_text(content)
    chunks: list[Chunk] = []

    for i, text in enumerate(raw_chunks):
        if len(text.strip()) < 30:    # skip trivial fragments
            continue
        # Prepend preamble if it's not already there
        if preamble and not text.startswith("// SPDX") and "pragma" not in text[:100]:
            full_text = preamble + "\n\n" + text
        else:
            full_text = text

        chunks.append(Chunk(
            text=full_text,
            chunk_index=i,
            has_code=True,
            code_language="solidity",
            tags=_extract_solidity_tags(text),
        ))
    return chunks


def _extract_solidity_tags(code: str) -> list[str]:
    """Quick heuristic tag extraction from Solidity code."""
    tags = []
    lower = code.lower()
    patterns = {
        "delegatecall": "delegatecall",
        "call{value": "low_level_call",
        "assembly": "assembly",
        "selfdestruct": "selfdestruct",
        "tx.origin": "tx_origin",
        "block.timestamp": "timestamp_dependency",
        ".call(": "external_call",
        "reentrancyguard": "reentrancy_guard",
        "flashloan": "flash_loan",
        "erc20": "erc20",
        "erc721": "erc721",
        "erc4626": "erc4626",
        "proxy": "proxy_pattern",
        "upgradeable": "upgradeable",
        "initialize": "initializer",
        "onlyowner": "access_control",
        "transferfrom": "token_transfer",
    }
    for keyword, tag in patterns.items():
        if keyword in lower:
            tags.append(tag)
    return tags


# ── Markdown chunker ─────────────────────────────────────────────────────────

_CODE_FENCE_RE = re.compile(r'```(\w*)\n(.*?)```', re.DOTALL)

def chunk_markdown(content: str) -> list[Chunk]:
    """
    Split markdown by headers first. Then detect per-chunk whether the chunk
    contains a code block — those get has_code=True and the code language.
    """
    cfg = CHUNK_SIZES["markdown"]
    splitter = MarkdownTextSplitter(
        chunk_size=cfg["size"],
        chunk_overlap=cfg["overlap"],
    )
    raw_chunks = splitter.split_text(content)
    chunks: list[Chunk] = []

    for i, text in enumerate(raw_chunks):
        if len(text.strip()) < 50:
            continue
        has_code, code_lang = _detect_code_in_markdown(text)
        chunks.append(Chunk(
            text=text,
            chunk_index=i,
            has_code=has_code,
            code_language=code_lang,
        ))
    return chunks


def _detect_code_in_markdown(text: str) -> tuple[bool, str | None]:
    """Return (has_code, language) by inspecting fenced code blocks."""
    matches = _CODE_FENCE_RE.findall(text)
    if not matches:
        return False, None
    # Use the first detected language
    for lang, _ in matches:
        lang = lang.strip().lower()
        if lang in ("sol", "solidity"):
            return True, "solidity"
        if lang in ("vyper", "vy"):
            return True, "vyper"
        if lang in ("yul", "assembly"):
            return True, "yul"
        if lang in ("py", "python", "js", "javascript", "ts", "typescript",
                    "rust", "go", "bash", "sh", "json"):
            return True, lang or "unknown"
    return True, "unknown"


# ── HTML chunker ──────────────────────────────────────────────────────────────

def chunk_html(content: str) -> list[Chunk]:
    """
    Convert HTML → Markdown (strips nav/footer boilerplate) then split.
    """
    from bs4 import BeautifulSoup
    from markdownify import markdownify as md

    # Remove boilerplate elements
    soup = BeautifulSoup(content, "html.parser")
    for tag in soup(["nav", "footer", "header", "script", "style",
                     "aside", "advertisement"]):
        tag.decompose()

    # Keep main content
    main = soup.find("main") or soup.find("article") or soup.find("body") or soup
    clean_html = str(main)
    markdown_text = md(clean_html, heading_style="ATX", strip=["img"])

    return chunk_markdown(markdown_text)


# ── PDF chunker ───────────────────────────────────────────────────────────────

def chunk_pdf(content: str) -> list[Chunk]:
    """Split extracted PDF text. PDFs are always prose (has_code=False),
    but may contain code snippets — we rely on the markdown detector for those."""
    cfg = CHUNK_SIZES["pdf"]
    splitter = RecursiveCharacterTextSplitter(
        separators=["\n\n", "\n", ". ", " ", ""],
        chunk_size=cfg["size"],
        chunk_overlap=cfg["overlap"],
    )
    raw_chunks = splitter.split_text(content)
    chunks: list[Chunk] = []
    for i, text in enumerate(raw_chunks):
        if len(text.strip()) < 80:
            continue
        has_code, code_lang = _detect_code_in_markdown(text)
        chunks.append(Chunk(
            text=text,
            chunk_index=i,
            has_code=has_code,
            code_language=code_lang,
        ))
    return chunks


# ── Plain-text chunker ────────────────────────────────────────────────────────

def chunk_plain_text(content: str) -> list[Chunk]:
    """For .txt files (manual paste articles, substack exports)."""
    cfg = CHUNK_SIZES["plain_text"]
    splitter = RecursiveCharacterTextSplitter(
        separators=["\n\n", "\n", ". ", " ", ""],
        chunk_size=cfg["size"],
        chunk_overlap=cfg["overlap"],
    )
    raw_chunks = splitter.split_text(content)
    chunks: list[Chunk] = []
    for i, text in enumerate(raw_chunks):
        if len(text.strip()) < 60:
            continue
        has_code, code_lang = _detect_code_in_markdown(text)
        chunks.append(Chunk(
            text=text,
            chunk_index=i,
            has_code=has_code,
            code_language=code_lang,
        ))
    return chunks


# ── RST chunker ───────────────────────────────────────────────────────────────

def chunk_rst(content: str) -> list[Chunk]:
    """For .rst files (Solidity docs, Sphinx docs)."""
    cfg = CHUNK_SIZES["rst"]
    splitter = RecursiveCharacterTextSplitter(
        separators=["\n\n\n", "\n\n", "\n", " "],
        chunk_size=cfg["size"],
        chunk_overlap=cfg["overlap"],
    )
    raw_chunks = splitter.split_text(content)
    chunks: list[Chunk] = []
    for i, text in enumerate(raw_chunks):
        if len(text.strip()) < 60:
            continue
        # RST code blocks use :: or .. code-block::
        has_code = "::" in text or "code-block" in text
        chunks.append(Chunk(
            text=text,
            chunk_index=i,
            has_code=has_code,
            code_language="solidity" if has_code else None,
        ))
    return chunks


# ── Dispatch ──────────────────────────────────────────────────────────────────

def chunk_document(content: str, doc_type: str, file_path: str = "") -> list[Chunk]:
    """
    Main entry point. Routes to the correct chunker based on doc_type.
    Returns [] if content is too short to chunk.
    """
    if not content or len(content.strip()) < 50:
        return []

    if doc_type == "solidity":
        return chunk_solidity(content, file_path)
    elif doc_type in ("vyper", "yul"):
        # Same strategy as Solidity for now (Language.SOL is close enough)
        chunks = chunk_solidity(content, file_path)
        for c in chunks:
            c.code_language = doc_type
        return chunks
    elif doc_type == "markdown":
        return chunk_markdown(content)
    elif doc_type == "html":
        return chunk_html(content)
    elif doc_type == "pdf":
        return chunk_pdf(content)
    elif doc_type == "rst":
        return chunk_rst(content)
    else:  # plain_text, unknown, json headers, etc.
        return chunk_plain_text(content)
