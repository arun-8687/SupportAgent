"""
Skills registry.

A skill is a directory whose SKILL.md combines metadata and knowledge in
one markdown file — YAML frontmatter for the structured fields, markdown
body for the procedural guidance:

    skills/builtin/<skill-name>/
        SKILL.md        -> frontmatter (name, description, tools, ...) +
                           guidance body the agent follows
        *.md            -> supporting files (runbooks, reference material)

A legacy layout with a separate manifest.yaml next to a plain SKILL.md is
still accepted (manifest wins when both carry metadata).

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
from sre_agent.frontmatter import parse_frontmatter
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


SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME_LEN = 64
MAX_DESCRIPTION_LEN = 1024


class SkillDefinition(BaseModel):
    """A skill loaded from a SKILL.md directory.

    Frontmatter follows the Agent Skills spec (agentskills.io): required
    name/description, optional license/compatibility/metadata. The
    `tools`, `applies_to`, `category`, and `files` fields are documented
    extensions of this implementation — they carry the executable-tool
    and gate/risk metadata the spec's scripts/ model has no place for.
    """
    name: str
    description: str
    # --- Agent Skills spec optional fields ---
    license: Optional[str] = None
    compatibility: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    # --- implementation extensions ---
    category: str = "general"
    files: List[str] = Field(default_factory=lambda: ["SKILL.md"])
    tools: List[SkillTool] = Field(default_factory=list)
    applies_to: List[str] = Field(default_factory=list)  # extra matching hints
    path: Optional[Path] = None

    def read_skill_md(self) -> str:
        """Procedural guidance (frontmatter stripped); loaded on activation."""
        if self.path is None:
            return ""
        skill_md = self.path / "SKILL.md"
        if not skill_md.exists():
            return ""
        _meta, body = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
        return body

    def read_supporting_files(self) -> Dict[str, str]:
        """Runbooks / reference material shipped alongside SKILL.md.

        Reads the files listed in frontmatter plus anything in the
        spec-recommended references/ directory (loaded on demand — the
        progressive-disclosure resource tier).
        """
        if self.path is None:
            return {}
        contents = {}
        for name in self.files:
            if name == "SKILL.md":
                continue
            file_path = self.path / name
            if file_path.exists():
                contents[name] = file_path.read_text(encoding="utf-8")
        references = self.path / "references"
        if references.is_dir():
            for file_path in sorted(references.glob("*.md")):
                key = f"references/{file_path.name}"
                contents.setdefault(key, file_path.read_text(encoding="utf-8"))
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
            try:
                data = self._read_metadata(skill_dir)
                if data is None:
                    continue
                skill = SkillDefinition.model_validate({**data, "path": skill_dir})
                self._validate_spec_rules(skill, skill_dir)
                self._skills[skill.name] = skill
            except Exception:
                logger.exception("Failed to load skill from %s", skill_dir)
        logger.info("Loaded %d skills", len(self._skills))

    @staticmethod
    def _validate_spec_rules(skill: "SkillDefinition", skill_dir: Path) -> None:
        """Enforce Agent Skills spec naming rules (warn, don't reject —
        an operator's misnamed skill should still work during an incident)."""
        if not SKILL_NAME_RE.match(skill.name) or len(skill.name) > MAX_NAME_LEN:
            logger.warning(
                "Skill name %r violates the Agent Skills spec "
                "(lowercase alphanumerics + single hyphens, max %d chars)",
                skill.name, MAX_NAME_LEN,
            )
        if skill.name != skill_dir.name:
            logger.warning(
                "Skill name %r must match its directory name %r per the "
                "Agent Skills spec", skill.name, skill_dir.name,
            )
        if not skill.description or len(skill.description) > MAX_DESCRIPTION_LEN:
            logger.warning(
                "Skill %r description must be 1-%d characters per the "
                "Agent Skills spec", skill.name, MAX_DESCRIPTION_LEN,
            )

    @staticmethod
    def _read_metadata(skill_dir: Path) -> Optional[dict]:
        """Skill metadata: SKILL.md frontmatter, or legacy manifest.yaml."""
        manifest = skill_dir / "manifest.yaml"
        if manifest.exists():
            return yaml.safe_load(manifest.read_text(encoding="utf-8"))
        skill_md = skill_dir / "SKILL.md"
        if skill_md.exists():
            meta, _body = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
            if meta:
                return meta
            logger.warning(
                "%s has no frontmatter and no manifest.yaml; skipping", skill_dir
            )
        return None

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
