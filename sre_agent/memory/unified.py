"""
Unified memory search — one query across every knowledge source.

When the agent needs context it searches all sources simultaneously and
returns grounded results with citations:

  past incidents      -> "how did we fix this before?"
  user memories       -> facts saved via #remember
  knowledge base      -> uploaded runbooks and docs
  synthesized files   -> markdown notes the agent wrote itself

Also generates session insights (symptoms / resolution steps / root
cause / pitfalls) after each incident thread completes, and persists
them into both the insight log and the synthesized knowledge files.
"""
import json
import logging
import uuid
from pathlib import Path
from typing import List, Optional

from sre_agent.config import get_settings
from sre_agent.memory.knowledge_base import KnowledgeBase
from sre_agent.memory.knowledge_store import KnowledgeStore
from sre_agent.memory.synthesized import SynthesizedKnowledge
from sre_agent.memory.user_memories import UserMemoryStore
from sre_agent.models import MemorySearchResult, SessionInsight

logger = logging.getLogger(__name__)


class AgentMemory:
    """Facade over all memory sources: unified search + insight capture."""

    def __init__(
        self,
        incidents: Optional[KnowledgeStore] = None,
        user_memories: Optional[UserMemoryStore] = None,
        knowledge_base: Optional[KnowledgeBase] = None,
        synthesized: Optional[SynthesizedKnowledge] = None,
        insights_path: Optional[Path] = None,
    ) -> None:
        self.incidents = incidents or KnowledgeStore()
        self.user_memories = user_memories or UserMemoryStore()
        self.knowledge_base = knowledge_base or KnowledgeBase()
        self.synthesized = synthesized or SynthesizedKnowledge()
        self.insights_path = insights_path or get_settings().memories_dir / "session_insights.jsonl"

    # -- unified search ---------------------------------------------------- #

    def search(
        self, query: str, service_name: Optional[str] = None, top_k: int = 3
    ) -> List[MemorySearchResult]:
        """Search every source; same-resource past incidents rank first."""
        results: List[MemorySearchResult] = []

        for match in self.incidents.search(query, service_name=service_name, top_k=top_k):
            results.append(
                MemorySearchResult(
                    source="past_incident",
                    citation=match.record_id,
                    title=match.title,
                    content=(
                        f"Root cause: {match.root_cause or 'n/a'}. "
                        f"Resolution: {match.resolution or 'n/a'}"
                    ),
                    similarity=match.similarity,
                )
            )

        for memory in self.user_memories.retrieve(query, top_k=top_k):
            results.append(
                MemorySearchResult(
                    source="user_memory",
                    citation=memory.memory_id,
                    title="User memory",
                    content=memory.fact,
                    similarity=0.5,
                )
            )

        results.extend(self.knowledge_base.search(query, top_k=top_k))

        for filename, excerpt in self.synthesized.search(query).items():
            results.append(
                MemorySearchResult(
                    source="synthesized",
                    citation=f"memories/synthesizedKnowledge/{filename}",
                    title=filename,
                    content=excerpt,
                    similarity=0.4,
                )
            )

        results.sort(key=lambda r: r.similarity, reverse=True)
        return results[: top_k * 2]

    def system_context(self) -> str:
        """The always-loaded context: synthesized overview.md."""
        return self.synthesized.load_overview()

    # -- session insights ---------------------------------------------------- #

    def capture_session_insight(self, insight: SessionInsight) -> SessionInsight:
        """Persist an insight and merge it into synthesized knowledge files."""
        self.insights_path.parent.mkdir(parents=True, exist_ok=True)
        with self.insights_path.open("a", encoding="utf-8") as fh:
            fh.write(insight.model_dump_json() + "\n")

        body_lines = [
            f"Incident `{insight.incident_id}` ({insight.outcome})",
            "",
            "**Symptoms observed:** " + ("; ".join(insight.symptoms_observed) or "n/a"),
            "**Root cause:** " + (insight.root_cause or "n/a"),
            "**Resolution steps:** " + ("; ".join(insight.resolution_steps) or "n/a"),
        ]
        if insight.pitfalls_to_avoid:
            body_lines.append("**Pitfalls to avoid:** " + "; ".join(insight.pitfalls_to_avoid))

        self.synthesized.save_topic(
            topic=f"debugging {insight.service_name}",
            insight="\n".join(body_lines),
            heading=f"{insight.service_name}: {insight.root_cause[:60] or insight.outcome}",
        )
        logger.info("Session insight captured: %s", insight.insight_id)
        return insight

    def load_insights(self) -> List[SessionInsight]:
        if not self.insights_path.exists():
            return []
        insights = []
        with self.insights_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    insights.append(SessionInsight.model_validate_json(line))
                except (ValueError, json.JSONDecodeError):
                    logger.warning("Skipping malformed session insight")
        return insights

    @staticmethod
    def new_insight_id() -> str:
        return f"ins-{uuid.uuid4().hex[:10]}"
