"""
Skills registry.

Skills are the lightest extension primitive: discrete operational
capabilities declared in YAML (marketplace-runbook style), typically
wrapping an Azure CLI command. They extend the agent's reach without
custom code — drop a YAML file in the skills directory and it becomes
proposable by the mitigation planner and executable by the executor.
"""
import logging
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.models import RiskLevel

logger = logging.getLogger(__name__)


class SkillDefinition(BaseModel):
    """A YAML-declared skill."""
    name: str
    description: str
    category: str = "general"  # e.g. compute, scaling, networking
    risk: RiskLevel = RiskLevel.MEDIUM
    parameters: List[str] = Field(default_factory=list)
    executor: str = "azure_cli"  # azure_cli | shell
    command: str  # template with {parameter} placeholders
    verification_command: Optional[str] = None
    supports_rollback: bool = False
    rollback_command: Optional[str] = None
    # Free-text hints the planner matches against incident category/cause
    applies_to: List[str] = Field(default_factory=list)


class SkillRegistry:
    """Loads and indexes skill definitions from a directory of YAML files."""

    def __init__(self, skills_dir: Optional[Path] = None) -> None:
        self.skills_dir = skills_dir or get_settings().skills_dir
        self._skills: Dict[str, SkillDefinition] = {}
        self._load()

    def _load(self) -> None:
        if not self.skills_dir.exists():
            logger.warning("Skills directory %s does not exist", self.skills_dir)
            return
        for path in sorted(self.skills_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                skill = SkillDefinition.model_validate(data)
                self._skills[skill.name] = skill
            except Exception:
                logger.exception("Failed to load skill from %s", path)
        logger.info("Loaded %d skills", len(self._skills))

    def get(self, name: str) -> Optional[SkillDefinition]:
        return self._skills.get(name)

    def all(self) -> List[SkillDefinition]:
        return list(self._skills.values())

    def find_applicable(self, *hints: str) -> List[SkillDefinition]:
        """Match skills whose applies_to hints overlap the given keywords."""
        wanted = {h.lower() for h in hints if h}
        matches = []
        for skill in self._skills.values():
            tags = {t.lower() for t in skill.applies_to}
            if wanted & tags:
                matches.append(skill)
        return matches

    def catalog_text(self) -> str:
        """Human/LLM readable catalog used in mitigation-planning prompts."""
        lines = []
        for skill in self._skills.values():
            lines.append(
                f"- {skill.name} ({skill.risk.value} risk): {skill.description} "
                f"[params: {', '.join(skill.parameters) or 'none'}]"
            )
        return "\n".join(lines)
