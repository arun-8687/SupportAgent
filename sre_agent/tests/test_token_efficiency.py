"""Token-efficiency guarantees for every LLM call site.

These tests pin the prompt budgets so a future change can't silently
reintroduce unbounded evidence dumps or duplicated context.
"""
import pytest

from sre_agent.models import Evidence, SubagentFinding
from sre_agent.skills.registry import SkillRegistry
from sre_agent.subagents.base import Subagent
from sre_agent.subagents.root_cause import RootCauseSubagent


@pytest.mark.unit
def test_evidence_formatting_is_capped():
    evidence = [
        Evidence(
            source="log_analytics",
            observation="x" * 1000,
            data={"blob": "y" * 1000},
        )
        for _ in range(30)
    ]
    text = Subagent._format_evidence(evidence)
    lines = text.splitlines()
    assert len(lines) == 16  # 15 items + omission marker
    assert "(+15 more evidence items omitted)" in text
    # Each line bounded: 240-char observation + 200-char data + overhead.
    assert all(len(line) < 500 for line in lines)


@pytest.mark.unit
def test_evidence_without_data_has_no_data_suffix():
    text = Subagent._format_evidence(
        [Evidence(source="s", observation="short observation", data={})]
    )
    assert "|" not in text  # empty data dict adds nothing


@pytest.mark.unit
def test_rca_synthesis_does_not_resend_all_evidence():
    findings = [
        SubagentFinding(
            subagent="logs_metrics",
            summary="s" * 1000,
            suspected_cause="c" * 1000,
            confidence=0.5,
            evidence=[
                Evidence(source="azure_monitor", observation="o" * 500, data={})
                for _ in range(20)
            ],
        )
    ]
    text = RootCauseSubagent()._format_findings(findings)
    assert text.count("- [azure_monitor]") == RootCauseSubagent.MAX_EVIDENCE_PER_FINDING
    assert "(+15 more evidence items)" in text
    # Summary and cause are truncated too.
    assert "s" * 401 not in text
    assert "c" * 241 not in text


@pytest.mark.unit
def test_active_skill_guidance_is_capped(tmp_path):
    skill_dir = tmp_path / "huge-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: huge-skill\ndescription: enormous guidance body\n---\n"
        + "guidance line\n" * 2000
    )
    registry = SkillRegistry(skills_dir=tmp_path)
    registry.activate("huge-skill")
    guidance = registry.active_guidance()
    assert len(guidance) < SkillRegistry.MAX_GUIDANCE_CHARS_PER_SKILL + 200
    assert "…[guidance truncated for length]" in guidance


@pytest.mark.unit
async def test_planner_and_proposer_prompt_composition(
    service, azure_monitor_alert, monkeypatch
):
    """Response plan rides only in the proposer; static content leads."""
    import sre_agent.graph.nodes as nodes_module

    captured = {}
    real = nodes_module.generate_structured

    async def recorder(system_prompt, user_prompt, schema, fallback):
        captured[schema.__name__] = system_prompt
        return await real(system_prompt, user_prompt, schema, fallback)

    monkeypatch.setattr(nodes_module, "generate_structured", recorder)
    await service.handle_alert(azure_monitor_alert)

    planner = captured["InvestigationPlan"]
    proposer = captured["MitigationPlan"]

    # The response plan is mitigation guidance — proposer only.
    assert "Incident response plan" not in planner
    assert "Incident response plan" in proposer
    # Static-first ordering: per-incident skill guidance comes after the
    # static catalog + response plan in the proposer.
    assert proposer.index("Incident response plan") < proposer.index(
        "Active skill guidance"
    )
    # Skill guidance present but bounded.
    assert len(proposer) < 12_000