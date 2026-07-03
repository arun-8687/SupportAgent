"""
Skills registry.

A skill combines knowledge with optional tools:

    skills/builtin/<skill-name>/
        manifest.yaml   -> name, description, files, tools
        SKILL.md        -> procedural guidance the agent follows
        *.md            -> supporting files (runbooks, reference material)

The agent decides which skill to load based on the skill's description
and the incident at hand — no explicit command needed. Loaded skills
inject their SKILL.md guidance into reasoning prompts and expose their
attached tools (Azure CLI, shell, Kusto, Python, links) for execution.

Constraints mirrored from the Azure SRE Agent skill model:
  - at most MAX_ACTIVE_SKILLS are active concurrently,
  - the oldest active skill is auto-unloaded when the limit is exceeded,
  - a skill's tools are only executable while the skill is active
    (the executor re-activates by re-reading SKILL.md when needed).
"""
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.models import RiskLevel

logger = logging.getLogger(__name__)

MAX_ACTIVE_SKILLS = 5

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set:
    return set(_WORD_RE.findall(text.lower()))


class SkillTool(BaseModel):
    """A tool attached to a skill (executes, not just describes)."""
    name: str
    type: str = "azure_cli"  # azure_cli | shell | kusto | python | link
    description: str = ""
    command: Optional[str] = None      # template with {parameter} placeholders
    query: Optional[str] = None        # kusto tools
    url_template: Optional[str] = None # link tools
    parameters: List[str] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.MEDIUM
    supports_rollback: bool = False
    rollback_command: Optional[str] = None


class SkillDefinition(BaseModel):
    """A skill loaded from a manifest.yaml + SKILL.md directory."""
    name: str
    description: str
    category: str = "general"
    files: List[str] = Field(default_factory=lambda: ["SKILL.md"])
    tools: List[SkillTool] = Field(default_factory=list)
    applies_to: List[str] = Field(default_factory=list)  # extra matching hints
    path: Optional[Path] = None

    def read_skill_md(self) -> str:
        """Procedural guidance; loaded when the skill activates."""
        if self.path is None:
            return ""
        skill_md = self.path / "SKILL.md"
        return skill_md.read_text(encoding="utf-8") if skill_md.exists() else ""

    def read_supporting_files(self) -> Dict[str, str]:
        """Runbooks / reference material shipped alongside SKILL.md."""
        if self.path is None:
            return {}
        contents = {}
        for name in self.files:
            if name == "SKILL.md":
                continue
            file_path = self.path / name
            if file_path.exists():
                contents[name] = file_path.read_text(encoding="utf-8")
        return contents

    def get_tool(self, tool_name: Optional[str]) -> Optional[SkillTool]:
        if not self.tools:
            return None
        if tool_name is None:
            return self.tools[0]
        return next((t for t in self.tools if t.name == tool_name), None)


class SkillRegistry:
    """Loads skill directories and manages the active-skill window."""

    def __init__(self, skills_dir: Optional[Path] = None) -> None:
        self.skills_dir = skills_dir or get_settings().skills_dir
        self._skills: Dict[str, SkillDefinition] = {}
        # Active skills: name -> SKILL.md content, LRU-ordered.
        self._active: "OrderedDict[str, str]" = OrderedDict()
        self._load()

    def _load(self) -> None:
        if not self.skills_dir.exists():
            logger.warning("Skills directory %s does not exist", self.skills_dir)
            return
        for skill_dir in sorted(p for p in self.skills_dir.iterdir() if p.is_dir()):
            manifest = skill_dir / "manifest.yaml"
            if not manifest.exists():
                continue
            try:
                data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
                skill = SkillDefinition.model_validate({**data, "path": skill_dir})
                self._skills[skill.name] = skill
            except Exception:
                logger.exception("Failed to load skill from %s", skill_dir)
        logger.info("Loaded %d skills", len(self._skills))

    # -- catalog ---------------------------------------------------------- #

    def get(self, name: str) -> Optional[SkillDefinition]:
        return self._skills.get(name)

    def all(self) -> List[SkillDefinition]:
        return list(self._skills.values())

    def catalog_text(self) -> str:
        """Skill descriptions as seen in the agent's system prompt."""
        lines = []
        for skill in self._skills.values():
            tools = ", ".join(t.name for t in skill.tools) or "none"
            lines.append(f"- {skill.name}: {skill.description} [tools: {tools}]")
        return "\n".join(lines)

    # -- relevance-based loading ------------------------------------------ #

    def find_relevant(self, query: str, top_k: int = 3) -> List[SkillDefinition]:
        """Rank skills by description/applies_to overlap with the query."""
        query_tokens = _tokens(query)
        if not query_tokens:
            return []
        scored = []
        for skill in self._skills.values():
            corpus = _tokens(skill.description) | _tokens(" ".join(skill.applies_to)) | _tokens(skill.name)
            overlap = len(query_tokens & corpus)
            if overlap:
                scored.append((overlap, skill.name, skill))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [skill for _, _, skill in scored[:top_k]]

    def activate(self, name: str) -> str:
        """
        Load a skill: read its SKILL.md into the active window.

        Returns the guidance text. Exceeding MAX_ACTIVE_SKILLS unloads the
        oldest active skill.
        """
        skill = self._skills.get(name)
        if skill is None:
            raise KeyError(f"Unknown skill: {name}")
        if name in self._active:
            self._active.move_to_end(name)
            return self._active[name]

        guidance = skill.read_skill_md()
        self._active[name] = guidance
        while len(self._active) > MAX_ACTIVE_SKILLS:
            unloaded, _ = self._active.popitem(last=False)
            logger.info("Skill '%s' auto-unloaded (active limit %d)", unloaded, MAX_ACTIVE_SKILLS)
        return guidance

    def is_active(self, name: str) -> bool:
        return name in self._active

    def active_guidance(self) -> str:
        """Concatenated SKILL.md guidance of all active skills."""
        return "\n\n---\n\n".join(
            f"# Skill: {name}\n{content}" for name, content in self._active.items()
        )

    def reset_active(self) -> None:
        """Active skills clear on conversation compaction / new incident."""
        self._active.clear()
