"""
User memories — discrete facts saved on request.

Mirrors the #remember / #retrieve / #forget chat commands: individual,
searchable facts kept in a store separate from synthesized knowledge
files ("Production uses 3 AKS clusters in West US 2").
"""
import json
import logging
import re
import uuid
from pathlib import Path
from typing import List, Optional

from sre_agent.config import get_settings
from sre_agent.locking import file_lock
from sre_agent.models import UserMemory

logger = logging.getLogger(__name__)

_WORD_RE = re.compile(r"[a-z0-9]+")


class UserMemoryStore:
    """JSONL-backed store of user-saved facts."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or get_settings().memories_dir / "user_memories.jsonl"

    def remember(self, fact: str, saved_by: str = "user") -> UserMemory:
        """#remember <fact>"""
        memory = UserMemory(
            memory_id=f"mem-{uuid.uuid4().hex[:10]}", fact=fact.strip(), saved_by=saved_by
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(self.path), self.path.open("a", encoding="utf-8") as fh:
            fh.write(memory.model_dump_json() + "\n")
        return memory

    def retrieve(self, query: str, top_k: int = 3) -> List[UserMemory]:
        """#retrieve <question> — keyword-overlap search over saved facts."""
        query_tokens = set(_WORD_RE.findall(query.lower()))
        if not query_tokens:
            return []
        scored = []
        for memory in self.load_all():
            fact_tokens = set(_WORD_RE.findall(memory.fact.lower()))
            overlap = len(query_tokens & fact_tokens)
            if overlap:
                scored.append((overlap, memory.created_at, memory))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [memory for _, _, memory in scored[:top_k]]

    def forget(self, query: str) -> int:
        """#forget <description> — remove matching memories; returns count."""
        with file_lock(self.path):
            keep, removed = [], 0
            query_tokens = set(_WORD_RE.findall(query.lower()))
            for memory in self.load_all():
                fact_tokens = set(_WORD_RE.findall(memory.fact.lower()))
                # Forget when most of the query matches the fact.
                if query_tokens and len(query_tokens & fact_tokens) >= max(1, len(query_tokens) // 2):
                    removed += 1
                else:
                    keep.append(memory)
            if removed:
                with self.path.open("w", encoding="utf-8") as fh:
                    for memory in keep:
                        fh.write(memory.model_dump_json() + "\n")
            return removed

    def load_all(self) -> List[UserMemory]:
        if not self.path.exists():
            return []
        memories = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    memories.append(UserMemory.model_validate_json(line))
                except Exception:
                    logger.warning("Skipping malformed user memory")
        return memories
