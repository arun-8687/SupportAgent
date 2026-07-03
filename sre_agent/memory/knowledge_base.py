"""
Knowledge base — uploaded reference documents.

Operators drop runbooks, architecture guides, on-call playbooks, and team
procedures (Markdown `.md` or plain text `.txt`) into the knowledge-base
directory; the agent searches them automatically when relevant and cites
the source document in its answers.
"""
import logging
import re
from pathlib import Path
from typing import List, Optional

from sre_agent.config import get_settings
from sre_agent.models import MemorySearchResult

logger = logging.getLogger(__name__)

SUPPORTED_SUFFIXES = {".md", ".txt"}


class KnowledgeBase:
    """Directory of uploaded docs with keyword search + citations."""

    def __init__(self, directory: Optional[Path] = None) -> None:
        self.directory = directory or get_settings().knowledge_base_dir

    def list_documents(self) -> List[str]:
        if not self.directory.exists():
            return []
        return sorted(
            p.name for p in self.directory.iterdir()
            if p.suffix.lower() in SUPPORTED_SUFFIXES
        )

    def add_document(self, name: str, content: str) -> Path:
        """Upload a document (programmatic equivalent of the portal upload)."""
        if Path(name).suffix.lower() not in SUPPORTED_SUFFIXES:
            raise ValueError(f"Unsupported format: {name} (use .md or .txt)")
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / Path(name).name
        path.write_text(content, encoding="utf-8")
        logger.info("Knowledge base document added: %s", path.name)
        return path

    def search(self, query: str, top_k: int = 3) -> List[MemorySearchResult]:
        """Rank documents by term overlap; return excerpts with citations."""
        terms = {t for t in re.findall(r"[a-z0-9]+", query.lower()) if len(t) > 2}
        if not terms:
            return []
        scored = []
        for name in self.list_documents():
            content = (self.directory / name).read_text(encoding="utf-8")
            lowered = f"{name.lower()} {content.lower()}"
            hits = sum(1 for term in terms if term in lowered)
            if hits:
                scored.append((hits / len(terms), name, content))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [
            MemorySearchResult(
                source="knowledge_base",
                citation=name,
                title=name,
                content=content[:1200],
                similarity=round(min(1.0, score), 3),
            )
            for score, name, content in scored[:top_k]
        ]
