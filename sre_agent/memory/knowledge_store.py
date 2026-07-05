"""
Institutional knowledge store — "knowledge that never leaves".

Every investigation writes a record (root cause, mitigations, outcome);
triage reads similar past records back so investigations get faster and
more consistent over time. The default backend is an append-only JSONL
file with keyword similarity; swap in a vector store (pgvector / Azure AI
Search, both already used elsewhere in this repo) for production.
"""
import logging
import uuid
from pathlib import Path
from typing import List, Optional, Set, Tuple

from sre_agent.config import get_settings
from sre_agent.locking import file_lock
from sre_agent.models import KnowledgeMatch, KnowledgeRecord
from sre_agent.textsearch import jaccard, tokens

logger = logging.getLogger(__name__)


class KnowledgeStore:
    """Append-only knowledge base with lightweight similarity search.

    Parsed records (with pre-computed token sets) are cached and
    invalidated by the file's (mtime_ns, size) — search runs on every
    triage, so re-reading and re-validating the whole JSONL per query
    would make intake O(history) during alert storms.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or get_settings().knowledge_path
        self._cache_key: Optional[Tuple[int, int]] = None
        self._cache: List[Tuple[KnowledgeRecord, Set[str]]] = []

    def save(self, record: KnowledgeRecord) -> KnowledgeRecord:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(self.path), self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
        logger.info("Knowledge captured: %s (%s)", record.record_id, record.title)
        return record

    def _load_indexed(self) -> List[Tuple[KnowledgeRecord, Set[str]]]:
        """Records + token sets, re-parsed only when the file changed."""
        if not self.path.exists():
            self._cache_key, self._cache = None, []
            return self._cache
        stat = self.path.stat()
        key = (stat.st_mtime_ns, stat.st_size)
        if key == self._cache_key:
            return self._cache

        indexed = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = KnowledgeRecord.model_validate_json(line)
                except Exception:
                    logger.warning("Skipping malformed knowledge record")
                    continue
                corpus = tokens(
                    " ".join([record.title, record.root_cause, record.category, *record.tags])
                )
                indexed.append((record, corpus))
        self._cache_key, self._cache = key, indexed
        return self._cache

    def load_all(self) -> List[KnowledgeRecord]:
        return [record for record, _ in self._load_indexed()]

    def search(self, query: str, service_name: Optional[str] = None, top_k: int = 3) -> List[KnowledgeMatch]:
        """Keyword-overlap similarity search over past investigations."""
        query_tokens = tokens(query)
        if not query_tokens:
            return []

        scored = []
        for record, corpus in self._load_indexed():
            if not corpus:
                continue
            overlap = jaccard(query_tokens, corpus)
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
