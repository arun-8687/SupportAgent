"""
Custom agents defined in markdown.

Operators add domain specialists without writing code by dropping a
markdown file into the custom-agents directory — YAML frontmatter for the
structured fields, markdown body as the agent's system prompt:

    ---
    name: database_expert
    handoff_description: Handles SQL and database troubleshooting
    allowed_skills:
      - postgres-troubleshooting
    tools:
      - query_metrics
    ---
    You are a database specialist. Analyze query performance, diagnose
    connection issues, and recommend optimizations.

Legacy plain-YAML definitions (with a `system_prompt` field) are still
accepted.

Key properties:
  body / system_prompt -> the expert persona and instructions
  handoff_description  -> what the planner/orchestrator sees when deciding
                          whether to delegate to this agent
  allowed_skills       -> skills this agent may load (setting it enables
                          skills automatically); their SKILL.md guidance is
                          activated and fed into the agent's analysis
  tools                -> built-in Python tools the agent gathers evidence
                          with (query_metrics, query_logs, recent_deployments)

Custom agents share the same investigation context as built-in subagents:
their findings merge into the same state and flow into root cause analysis.
"""
import logging
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field

from sre_agent.frontmatter import parse_frontmatter
from sre_agent.models import Evidence, Incident, SubagentFinding
from sre_agent.skills.registry import SkillRegistry
from sre_agent.subagents.base import Subagent
from sre_agent.tools.deployments import DeploymentClient
from sre_agent.tools.observability import ObservabilityClient

logger = logging.getLogger(__name__)


class CustomAgentDefinition(BaseModel):
    """Schema of a custom-agent YAML file."""
    name: str
    system_prompt: str
    handoff_description: str = ""
    allowed_skills: List[str] = Field(default_factory=list)
    tools: List[str] = Field(default_factory=list)
    enable_skills: bool = False

    def model_post_init(self, __context) -> None:
        # Setting allowed_skills automatically enables skills.
        if self.allowed_skills:
            object.__setattr__(self, "enable_skills", True)


class YamlSubagent(Subagent):
    """A custom agent instantiated from a YAML definition."""

    def __init__(
        self,
        definition: CustomAgentDefinition,
        skills: Optional[SkillRegistry] = None,
        observability: Optional[ObservabilityClient] = None,
        deployments: Optional[DeploymentClient] = None,
    ) -> None:
        self.definition = definition
        self.name = definition.name
        self.description = definition.handoff_description or definition.system_prompt[:160]
        self.skills = skills or SkillRegistry()
        self.observability = observability or ObservabilityClient()
        self.deployments = deployments or DeploymentClient()

    async def collect(self, incident: Incident) -> List[Evidence]:
        evidence: List[Evidence] = []

        # Load allowed skills: their SKILL.md guidance becomes evidence the
        # analysis phase reasons over (the "skill activated" behavior).
        if self.definition.enable_skills:
            for skill_name in self.definition.allowed_skills:
                skill = self.skills.get(skill_name)
                if skill is None:
                    logger.warning(
                        "[%s] allowed skill '%s' not found", self.name, skill_name
                    )
                    continue
                guidance = self.skills.activate(skill_name)
                evidence.append(
                    Evidence(
                        source=f"skill:{skill_name}",
                        observation=f"Loaded skill guidance: {skill.description}",
                        data={"skill_md": guidance[:2000]},
                    )
                )

        # Gather telemetry through whichever built-in tools are attached.
        if "query_metrics" in self.definition.tools:
            metrics = await self.observability.query_metrics(
                incident.alert.resource.resource_id, ["MemoryWorkingSet", "CpuPercentage"]
            )
            for name, series in metrics.items():
                if series:
                    evidence.append(
                        Evidence(
                            source="azure_monitor",
                            observation=f"Metric {name}: {series[0]['value']} -> {series[-1]['value']}",
                            data={"metric": name},
                        )
                    )
        if "query_logs" in self.definition.tools:
            logs = await self.observability.query_logs(
                incident.alert.resource.resource_id, "AppTraces | where SeverityLevel >= 3"
            )
            for row in logs[:5]:
                evidence.append(
                    Evidence(
                        source="log_analytics",
                        observation=str(row.get("message", ""))[:200],
                        data=row,
                    )
                )
        if "recent_deployments" in self.definition.tools:
            for deploy in await self.deployments.recent_deployments(incident.service_name):
                evidence.append(
                    Evidence(
                        source="deployments",
                        observation=f"Deployment {deploy['id']}: {deploy.get('description', '')}",
                        data=deploy,
                    )
                )
        return evidence

    async def analyze(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        # Use the custom agent's own system prompt as its persona.
        original_description = self.description
        self.description = self.definition.system_prompt
        try:
            return await super().analyze(incident, evidence)
        finally:
            self.description = original_description

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        skills_loaded = [e.source for e in evidence if e.source.startswith("skill:")]
        return SubagentFinding(
            subagent=self.name,
            summary=(
                f"{self.definition.handoff_description or self.name}: reviewed "
                f"{len(evidence)} evidence items"
                + (f" using skills {', '.join(skills_loaded)}" if skills_loaded else "")
                + f" for {incident.service_name}."
            ),
            confidence=0.4 if evidence else 0.0,
        )


def _read_definition(path: Path) -> CustomAgentDefinition:
    """Parse a custom-agent file: .md (frontmatter + body) or legacy .yaml."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        meta, body = parse_frontmatter(text)
        if not meta:
            raise ValueError(f"{path.name} has no YAML frontmatter")
        # The markdown body IS the system prompt; an explicit
        # system_prompt field in the frontmatter wins if present.
        data = {"system_prompt": body.strip(), **meta}
    else:
        data = yaml.safe_load(text)
    return CustomAgentDefinition.model_validate(data)


def load_custom_agents(
    directory: Optional[Path] = None,
    skills: Optional[SkillRegistry] = None,
) -> List[YamlSubagent]:
    """Load every custom-agent definition (.md preferred, .yaml legacy)."""
    from sre_agent.config import get_settings

    directory = directory or get_settings().custom_agents_dir
    if not directory.exists():
        return []
    agents = []
    for path in sorted(list(directory.glob("*.md")) + list(directory.glob("*.yaml"))):
        try:
            definition = _read_definition(path)
            agents.append(YamlSubagent(definition, skills=skills))
        except Exception:
            logger.exception("Failed to load custom agent from %s", path)
    logger.info("Loaded %d custom agents", len(agents))
    return agents
