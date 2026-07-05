"""Custom agent (YAML-defined subagent) tests."""
import pytest

from sre_agent.integrations.normalizers import normalize, to_incident
from sre_agent.skills.registry import SkillRegistry
from sre_agent.subagents.custom_loader import (
    CustomAgentDefinition,
    YamlSubagent,
    load_custom_agents,
)
from sre_agent.subagents.registry import SubagentRegistry


@pytest.mark.unit
def test_shipped_custom_agent_loads():
    agents = load_custom_agents()
    names = {a.name for a in agents}
    assert "database_expert" in names


@pytest.mark.unit
def test_custom_agents_register_alongside_builtins():
    registry = SubagentRegistry()
    assert "database_expert" in registry.names()
    assert {"logs_metrics", "source_code", "architecture", "scanning"} <= set(registry.names())
    # handoff_description surfaces to the planner.
    assert "database troubleshooting" in registry.descriptions()


@pytest.mark.unit
def test_allowed_skills_auto_enables_skills():
    definition = CustomAgentDefinition(
        name="k8s_expert",
        system_prompt="You are a Kubernetes specialist.",
        allowed_skills=["aks-memory-pressure"],
    )
    assert definition.enable_skills is True


@pytest.mark.unit
async def test_custom_agent_investigation_loads_skill_guidance(azure_monitor_alert):
    skills = SkillRegistry()
    agent = YamlSubagent(
        CustomAgentDefinition(
            name="k8s_expert",
            system_prompt="You are a Kubernetes memory specialist.",
            handoff_description="Handles AKS memory issues",
            allowed_skills=["aks-memory-pressure"],
            tools=["query_metrics"],
        ),
        skills=skills,
    )
    incident = to_incident(normalize(azure_monitor_alert))
    finding = await agent.investigate(incident)

    assert finding.subagent == "k8s_expert"
    # SKILL.md guidance was activated and collected as evidence.
    skill_evidence = [e for e in finding.evidence if e.source == "skill:aks-memory-pressure"]
    assert skill_evidence
    assert "AKS memory pressure" in skill_evidence[0].data["skill_md"]
    assert skills.is_active("aks-memory-pressure")
    # Attached tool gathered telemetry too.
    assert any(e.source == "azure_monitor" for e in finding.evidence)


@pytest.mark.unit
async def test_custom_agent_from_yaml_directory(tmp_path, azure_monitor_alert):
    (tmp_path / "net_expert.yaml").write_text(
        """
name: net_expert
system_prompt: |
  You are a networking specialist.
handoff_description: Handles VNet, NSG, and load balancer issues
tools:
  - query_logs
"""
    )
    agents = load_custom_agents(directory=tmp_path)
    assert len(agents) == 1
    incident = to_incident(normalize(azure_monitor_alert))
    finding = await agents[0].investigate(incident)
    assert finding.subagent == "net_expert"
