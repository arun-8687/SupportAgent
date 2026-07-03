"""Skills registry/executor and hook engine tests."""
import pytest

from sre_agent.hooks.engine import HookEngine
from sre_agent.models import HookEvent, MitigationAction
from sre_agent.skills.executor import SkillExecutor, render_command
from sre_agent.skills.registry import SkillRegistry


@pytest.mark.unit
def test_builtin_skills_load():
    registry = SkillRegistry()
    names = {skill.name for skill in registry.all()}
    assert {"restart_app_service", "restart_aks_deployment", "adjust_hpa_memory_threshold"} <= names


@pytest.mark.unit
def test_find_applicable_matches_memory_incidents():
    registry = SkillRegistry()
    matches = registry.find_applicable("memory", "prod")
    assert any(s.name == "restart_aks_deployment" for s in matches)


@pytest.mark.unit
def test_render_command_quotes_parameters():
    registry = SkillRegistry()
    skill = registry.get("restart_app_service")
    command = render_command(
        skill, {"resource_group": "my rg; rm -rf /", "app_name": "payments"}
    )
    assert "'my rg; rm -rf /'" in command  # injection attempt is quoted


@pytest.mark.unit
async def test_dry_run_execution_does_not_shell_out():
    registry = SkillRegistry()
    executor = SkillExecutor(registry=registry, dry_run=True)
    result = await executor.execute(
        MitigationAction(
            action_id="a1",
            name="restart_app_service",
            kind="skill",
            skill_name="restart_app_service",
            parameters={"resource_group": "rg", "app_name": "app"},
        )
    )
    assert result.success
    assert result.dry_run
    assert result.output.startswith("[dry-run] az webapp restart")


@pytest.mark.unit
async def test_unknown_skill_fails_cleanly():
    executor = SkillExecutor(registry=SkillRegistry(), dry_run=True)
    result = await executor.execute(
        MitigationAction(action_id="a2", name="nope", kind="skill", skill_name="nope")
    )
    assert not result.success
    assert "Unknown skill" in (result.error or "")


@pytest.mark.unit
async def test_hooks_fire_for_matching_event():
    engine = HookEngine()
    results = await engine.fire(
        HookEvent.INVESTIGATION_STARTED, {"incident_id": "sre-test"}
    )
    assert results, "expected the announce-investigation hook to fire"
    assert all(r.event == HookEvent.INVESTIGATION_STARTED for r in results)


@pytest.mark.unit
async def test_prompt_hook_defaults_to_allow_offline():
    engine = HookEngine()
    results = await engine.fire(HookEvent.BEFORE_MITIGATION, {"actions": []})
    prompt_results = [r for r in results if r.hook_type == "prompt"]
    assert prompt_results
    assert engine.blocked_by(results) is None
