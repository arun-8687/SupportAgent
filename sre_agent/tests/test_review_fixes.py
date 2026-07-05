"""Regression tests for the adversarial-review fixes."""
import asyncio
import logging

import pytest

from sre_agent.hooks.engine import HookDefinition, HookEngine
from sre_agent.models import HookEvent, HookResult, MitigationAction
from sre_agent.skills.executor import SkillExecutionError, SkillExecutor, render_command
from sre_agent.skills.registry import SkillRegistry, SkillTool
from sre_agent.stores import FileAlertLedger


# --------------------------------------------------------------------------- #
# Finding 1 — intake crash windows
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_crashed_investigation_is_reclaimed_not_dropped(service, azure_monitor_alert):
    """A claim that never reached mark_processed must be re-investigated."""
    # Simulate a crashed prior attempt: claim exists, processed=False.
    registration = service.register_alert(azure_monitor_alert)
    assert registration["action"] == "investigate"
    # (crash here: run_registered never runs, mark_processed never called)

    result = await service.handle_alert(azure_monitor_alert)  # redelivery
    assert result["status"] != "duplicate", "crashed investigation was dropped"
    assert result["status"] == "awaiting_approval"


@pytest.mark.unit
async def test_processed_claim_still_dedupes(service, azure_monitor_alert):
    first = await service.handle_alert(azure_monitor_alert)  # pauses -> processed
    second = await service.handle_alert(azure_monitor_alert)
    assert second["status"] == "duplicate"
    assert second["incident_id"] == first["incident_id"]


@pytest.mark.unit
async def test_stalled_intake_recovered_by_sweeper(service, azure_monitor_alert, monkeypatch):
    from sre_agent.config import get_settings

    service.register_alert(azure_monitor_alert)  # claim, then "crash"
    # Age the claim past the staleness deadline.
    entries = service.alert_ledger._read()  # type: ignore[attr-defined]
    for entry in entries:
        entry["ts"] -= 10_000
    service.alert_ledger._write(entries)  # type: ignore[attr-defined]

    recovered = await service.recover_stalled_intakes()
    assert len(recovered) == 1
    assert recovered[0]["status"] == "awaiting_approval"
    # And it is now durable: no longer stalled.
    assert not service.alert_ledger.stalled(0)


@pytest.mark.unit
def test_ledger_lifecycle(tmp_path):
    ledger = FileAlertLedger(path=tmp_path / "ledger.jsonl")
    claim = ledger.claim("a-1", "inc-1", "svc:x", payload={"p": 1})
    assert claim.status == "new" and claim.processed is False

    dup = ledger.claim("a-1", "inc-2", "svc:x")
    assert dup.status == "duplicate" and dup.processed is False

    assert ledger.reclaim("a-1", "inc-3") is True
    ledger.mark_processed("a-1")
    dup2 = ledger.claim("a-1", "inc-4", "svc:x")
    assert dup2.processed is True and dup2.incident_id == "inc-3"
    assert ledger.reclaim("a-1", "inc-5") is False  # processed: no reclaim
    assert ledger.stalled(0) == []


# --------------------------------------------------------------------------- #
# Findings 2 & 4 — hook contract
# --------------------------------------------------------------------------- #

def _result(event: HookEvent, decision: dict) -> HookResult:
    return HookResult(
        hook="h", event=event, hook_type="command", success=True, decision=decision
    )


@pytest.mark.unit
def test_post_tool_use_block_without_reason_blocks():
    veto = HookEngine.blocked_by([_result(HookEvent.POST_TOOL_USE, {"allow": False, "reason": ""})])
    assert veto is not None
    assert "no reason given" in veto.decision["reason"]


@pytest.mark.unit
def test_stop_block_without_reason_is_approval():
    assert HookEngine.blocked_by([_result(HookEvent.STOP, {"allow": False, "reason": ""})]) is None
    assert HookEngine.blocked_by([_result(HookEvent.STOP, {"allow": False, "reason": "incomplete"})]) is not None


@pytest.mark.unit
def test_invalid_matcher_never_crashes_and_is_disabled_at_load(tmp_path, caplog):
    hook = HookDefinition(name="bad", event=HookEvent.POST_TOOL_USE, type="command",
                          command="true", matcher="restart[")
    assert hook.matches_tool("restart_app") is False  # no re.error escape

    hooks_file = tmp_path / "hooks.yaml"
    hooks_file.write_text(
        "hooks:\n  - name: bad\n    event: PostToolUse\n    type: command\n"
        "    command: 'true'\n    matcher: 'restart['\n"
    )
    with caplog.at_level(logging.ERROR):
        engine = HookEngine(hooks_file=hooks_file)
    assert engine.hooks[0].enabled is False
    assert any("invalid matcher" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# Finding 3 — command template rendering
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_literal_braces_raise_skill_error_not_keyerror():
    tool = SkillTool(
        name="jsonpath", type="shell",
        command="kubectl get pod {pod} -o jsonpath={.status.phase}",
        parameters=["pod"],
    )
    with pytest.raises(SkillExecutionError, match="Escape literal braces"):
        render_command(tool, {"pod": "p1"})


@pytest.mark.unit
async def test_executor_never_raises(tmp_path):
    """Even a broken template yields a failed ActionResult, not a crash."""
    skill_dir = tmp_path / "broken-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: broken-skill\ndescription: broken template\n"
        "tools:\n  - name: bad_tool\n    type: shell\n"
        "    command: \"echo {a} {.oops}\"\n    parameters: [a]\n---\n# x\n"
    )
    executor = SkillExecutor(registry=SkillRegistry(skills_dir=tmp_path), dry_run=True)
    result = await executor.execute(
        MitigationAction(action_id="a1", name="bad_tool", kind="skill",
                         skill_name="broken-skill", tool_name="bad_tool",
                         parameters={"a": "x"})
    )
    assert result.success is False
    assert "Escape literal braces" in (result.error or "")


# --------------------------------------------------------------------------- #
# Finding 5 — semaphore per event loop
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_llm_semaphore_rebinds_per_event_loop():
    from sre_agent.llm import _get_semaphore

    async def grab():
        return _get_semaphore()

    sem1 = asyncio.run(grab())
    sem2 = asyncio.run(grab())  # fresh loop must get a fresh semaphore
    assert sem1 is not sem2


# --------------------------------------------------------------------------- #
# Finding 8 — storm parent correctness
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_storm_note_without_parent_has_no_none(service):
    """When no in-window parent exists the note must not read 'None'."""
    def alert(i):
        return {"alert_id": f"s-{i}", "source": "custom",
                "title": "orders-api error rate high", "description": "x",
                "resource": {"service_name": "orders-api", "environment": "staging"}}

    last = None
    for i in range(7):
        last = await service.handle_alert(alert(i), source_hint="custom")
    assert last["status"] == "storm_suppressed"
    assert "None" not in last["note"]


# --------------------------------------------------------------------------- #
# Finding 9 — BOM-tolerant frontmatter
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_bom_and_leading_blank_frontmatter(tmp_path):
    from sre_agent.frontmatter import parse_frontmatter

    meta, body = parse_frontmatter("﻿---\nname: x\n---\nbody")
    assert meta == {"name": "x"}
    meta2, _ = parse_frontmatter("\n\n---\nname: y\n---\nbody")
    assert meta2 == {"name": "y"}

    skill_dir = tmp_path / "bom-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "﻿---\nname: bom-skill\ndescription: saved with a BOM\n---\n# g\n",
        encoding="utf-8",
    )
    registry = SkillRegistry(skills_dir=tmp_path)
    assert registry.get("bom-skill") is not None


# --------------------------------------------------------------------------- #
# Finding 6 — knowledge store caching
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_knowledge_store_cache_invalidated_on_save(knowledge_store):
    from sre_agent.models import KnowledgeRecord

    assert knowledge_store.search("payment memory leak") == []
    knowledge_store.save(KnowledgeRecord(
        record_id="kb-1", incident_id="i-1", service_name="payment-service",
        title="payment memory leak", root_cause="leak in v2", category="memory",
    ))
    # Cache must refresh after the write (mtime/size key changed).
    assert knowledge_store.search("payment memory leak")
    # And repeated searches serve from cache without error.
    assert knowledge_store.search("payment memory leak")
