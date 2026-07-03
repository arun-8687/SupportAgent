"""
Institutional knowledge store — "knowledge that never leaves".

Every investigation writes a record (root cause, mitigations, outcome);
triage reads similar past records back so investigations get faster and
more consistent over time. The default backend is an append-only JSONL
file with keyword similarity; swap in a vector store (pgvector / Azure AI
Search, both already used elsewhere in this repo) for production.
"""
import json
import logging
import re
import uuid
from pathlib import Path
from typing import List, Optional

from sre_agent.config import get_settings
from sre_agent.models import KnowledgeMatch, KnowledgeRecord

logger = logging.getLogger(__name__)

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set:
    return set(_WORD_RE.findall(text.lower()))


class KnowledgeStore:
    """Append-only knowledge base with lightweight similarity search."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or get_settings().knowledge_path

    def save(self, record: KnowledgeRecord) -> KnowledgeRecord:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
        logger.info("Knowledge captured: %s (%s)", record.record_id, record.title)
        return record

    def load_all(self) -> List[KnowledgeRecord]:
        if not self.path.exists():
            return []
        records = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(KnowledgeRecord.model_validate_json(line))
                except Exception:
                    logger.warning("Skipping malformed knowledge record")
        return records

    def search(self, query: str, service_name: Optional[str] = None, top_k: int = 3) -> List[KnowledgeMatch]:
        """Keyword-overlap similarity search over past investigations."""
        query_tokens = _tokens(query)
        if not query_tokens:
            return []

        scored = []
        for record in self.load_all():
            corpus = _tokens(
                " ".join([record.title, record.root_cause, record.category, *record.tags])
            )
            if not corpus:
                continue
            overlap = len(query_tokens & corpus) / len(query_tokens | corpus)
            if service_name and record.service_name == service_name:
                overlap = min(1.0, overlap + 0.2)  # same-service boost
            if overlap > 0.05:
                scored.append((overlap, record))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [
            KnowledgeMatch(
                record_id=record.record_id,
                title=record.title,
                root_cause=record.root_cause,
                resolution="; ".join(record.mitigations),
                similarity=round(score, 3),
            )
            for score, record in scored[:top_k]
        ]

    @staticmethod
    def new_record_id() -> str:
        return f"kb-{uuid.uuid4().hex[:10]}"
