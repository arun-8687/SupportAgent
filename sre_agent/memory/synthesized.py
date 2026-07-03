"""
Synthesized knowledge — persistent markdown knowledge files.

The agent keeps a knowledge directory at memories/synthesizedKnowledge/:

  overview.md   -> service summary + index of topic files; ALWAYS loaded
                   into the system prompt (~2,000 character budget)
  <topic>.md    -> self-contained notes on one subject, organized
                   semantically (e.g. aks-networking-gotchas.md,
                   architecture.md, deployment.md, debugging.md)

The agent proactively records insights it discovers (constraints,
strategies that worked/failed, non-obvious dependencies, config details)
by merging them into the right topic file and linking it from overview.md.
"""
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from sre_agent.config import get_settings
from sre_agent.locking import file_lock

logger = logging.getLogger(__name__)

OVERVIEW_BUDGET_CHARS = 2000
OVERVIEW_FILE = "overview.md"


def _slugify(topic: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", topic.lower()).strip("-")
    return f"{slug or 'notes'}.md"


class SynthesizedKnowledge:
    """Markdown knowledge directory: overview.md + semantic topic files."""

    def __init__(self, directory: Optional[Path] = None) -> None:
        self.directory = directory or get_settings().memories_dir / "synthesizedKnowledge"

    # -- reading ----------------------------------------------------------- #

    def load_overview(self) -> str:
        """Always-loaded context; truncated to the character budget."""
        path = self.directory / OVERVIEW_FILE
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")[:OVERVIEW_BUDGET_CHARS]

    def read_topic(self, topic: str) -> str:
        path = self.directory / _slugify(topic)
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def topic_files(self) -> List[str]:
        if not self.directory.exists():
            return []
        return sorted(
            p.name for p in self.directory.glob("*.md") if p.name != OVERVIEW_FILE
        )

    def search(self, query: str) -> Dict[str, str]:
        """Topic files whose content overlaps the query (name -> excerpt)."""
        terms = {t for t in re.findall(r"[a-z0-9]+", query.lower()) if len(t) > 2}
        if not terms:
            return {}
        hits = {}
        for name in self.topic_files():
            content = (self.directory / name).read_text(encoding="utf-8")
            lowered = content.lower()
            if sum(1 for term in terms if term in lowered) >= max(1, len(terms) // 4):
                hits[name] = content[:1200]
        return hits

    # -- writing ----------------------------------------------------------- #

    def save_topic(self, topic: str, insight: str, heading: Optional[str] = None) -> str:
        """
        Merge an insight into a topic file (append under a dated heading);
        creating the file registers it in the overview index.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        filename = _slugify(topic)
        path = self.directory / filename
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        with file_lock(path):
            if path.exists():
                content = path.read_text(encoding="utf-8").rstrip()
            else:
                content = f"# {topic}\n"
            section_title = heading or f"Insight ({stamp})"
            content += f"\n\n## {section_title}\n\n{insight.strip()}\n"
            path.write_text(content, encoding="utf-8")

        self._ensure_overview_link(filename, topic)
        logger.info("Synthesized knowledge updated: %s", filename)
        return filename

    def _ensure_overview_link(self, filename: str, topic: str) -> None:
        """overview.md links every topic file so the agent knows it exists."""
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / OVERVIEW_FILE
        with file_lock(path):
            if path.exists():
                content = path.read_text(encoding="utf-8")
            else:
                content = (
                    "# Environment overview\n\n"
                    "Knowledge synthesized from past investigations. Detailed notes "
                    "live in the linked topic files.\n\n## Topics\n"
                )
            link = f"- [{topic}]({filename})"
            if filename not in content:
                if "## Topics" not in content:
                    content += "\n## Topics\n"
                content = content.rstrip() + f"\n{link}\n"
                path.write_text(content[:OVERVIEW_BUDGET_CHARS * 4], encoding="utf-8")
