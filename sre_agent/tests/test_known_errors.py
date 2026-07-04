"""Tests for app-scoped known-error pre-approvals and their safety rails."""
import copy
from datetime import date, timedelta

import pytest
import yaml

from sre_agent.gate.permission_gate import PermissionGate
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.graph.workflow import route_after_gate
from sre_agent.hooks.engine import HookEngine
from sre_agent.known_errors import KnownErrorRecord, KnownErrorStore
from sre_agent.models import (
    ActionResult,
    ExecutionReport,
    GateDecision,
    GateOutcome,
    Incident,
    IncidentAlert,
    MitigationAction,
    MitigationPlan,
    ResourceRef,
    RiskLevel,
    RootCauseAnalysis,
    Severity,
)
from sre_agent.skills.executor import SkillExecutor


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def write_ke(directory, ke_id="ke-test", **overrides):
    """Write a known-error markdown file and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    meta = {
        "id": ke_id,
        "service_name": "payment-service",
        "error_signature": "payment service memory usage critical working set oomkilled",
        "min_signature_match": 0.5,
        "min_rca_confidence": 0.5,
        "approved_actions": [
            {"skill_name": "aks-memory-pressure", "tool_name": "restart_aks_deployment"}
        ],
        "environments": ["prod"],
        "approved_by": "platform@org.com",
        "enabled": True,
        "success_count": 0,
    }
    meta.update(overrides)
    path = directory / f"{ke_id}.md"
    path.write_text(
        "---\n" + yaml.safe_dump(meta, sort_keys=False) + "---\nRationale.\n",
        encoding="utf-8",
    )
    return path


ALERT_TEXT = (
    "payment-service memory usage critical Memory working set exceeded 90% of "
    "limit on payment-service for 15 minutes; pods restarting with OOMKilled."
)


def skill_action(action_id="a1", skill="aks-memory-pressure",
                 tool="restart_aks_deployment", risk=RiskLevel.MEDIUM, kind="skill"):
    return MitigationAction(
        action_id=action_id, name=tool, kind=kind,
        skill_name=skill if kind == "skill" else None,
        tool_name=tool if kind == "skill" else None,
        risk=risk,
    )


# --------------------------------------------------------------------------- #
# Store matching
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_app_scoped_match(known_errors):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    match = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert match is not None and match.id == "ke-test"


@pytest.mark.unit
def test_global_match_when_app_mapped(known_errors):
    write_ke(known_errors.global_dir, ke_id="ke-global")
    match = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert match is not None and match.id == "ke-global"


@pytest.mark.unit
def test_app_scoped_beats_global(known_errors):
    write_ke(known_errors.global_dir, ke_id="ke-global")
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors", ke_id="ke-app")
    match = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert match.id == "ke-app"


@pytest.mark.unit
def test_other_app_record_never_matches(known_errors):
    write_ke(known_errors.apps_dir / "OTHER-9" / "known_errors", ke_id="ke-other")
    match = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert match is None


@pytest.mark.unit
def test_unmapped_never_matches_even_global(known_errors):
    """Quarantine: an untagged resource inherits no pre-approval at all."""
    write_ke(known_errors.global_dir, ke_id="ke-global")
    assert known_errors.find_match("UNMAPPED", "payment-service", ALERT_TEXT, "prod", 0.8) is None
    assert known_errors.find_match("", "payment-service", ALERT_TEXT, "prod", 0.8) is None


@pytest.mark.unit
@pytest.mark.parametrize("overrides,reason", [
    ({"enabled": False}, "disabled"),
    ({"expires": date.today() - timedelta(days=1)}, "expired"),
    ({"environments": ["dev"]}, "wrong-env"),
    ({"min_rca_confidence": 0.95}, "low-rca"),
    ({"error_signature": "totally unrelated words xyzzy"}, "low-signature"),
    ({"service_name": "other-service"}, "service-mismatch"),
])
def test_non_matching_conditions(known_errors, overrides, reason):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors", **overrides)
    assert known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8) is None, reason


@pytest.mark.unit
def test_expired_none_still_matches(known_errors):
    """An omitted expires (None) means no expiry."""
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors", expires=None)
    assert known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8) is not None


# --------------------------------------------------------------------------- #
# covers() — the high-risk / manual exclusions
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_covers_accepts_listed_skill_action(known_errors):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    record = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert known_errors.covers(record, skill_action()) is True


@pytest.mark.unit
def test_covers_rejects_high_risk_even_if_listed(known_errors):
    """High-risk actions are never pre-approvable, regardless of the record."""
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    record = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert known_errors.covers(record, skill_action(risk=RiskLevel.HIGH)) is False


@pytest.mark.unit
def test_covers_rejects_manual_and_unlisted(known_errors):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    record = known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8)
    assert known_errors.covers(record, skill_action(kind="manual")) is False
    assert known_errors.covers(record, skill_action(skill="other", tool="other_tool")) is False


# --------------------------------------------------------------------------- #
# Mutating records: success + circuit breaker survive reload
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_record_success_persists(known_errors):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    record = known_errors.get("ke-test")
    known_errors.record_success(record)
    known_errors.record_success(record)
    assert known_errors.get("ke-test").success_count == 2


@pytest.mark.unit
def test_disable_persists_and_stops_matching(known_errors):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    record = known_errors.get("ke-test")
    known_errors.disable(record, reason="failed in prod")
    reloaded = known_errors.get("ke-test")
    assert reloaded.enabled is False
    assert reloaded.disabled_reason == "failed in prod"
    assert known_errors.find_match("PAY-1", "payment-service", ALERT_TEXT, "prod", 0.8) is None


# --------------------------------------------------------------------------- #
# Promotion drafts
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_record_candidate_drafts_at_threshold(known_errors):
    actions = [skill_action()]
    # Threshold is 3 by default: first two return None, third drafts.
    assert known_errors.record_candidate("PAY-1", "payment-service", "mem oom", actions) is None
    assert known_errors.record_candidate("PAY-1", "payment-service", "mem oom", actions) is None
    draft_path = known_errors.record_candidate("PAY-1", "payment-service", "mem oom", actions)
    assert draft_path is not None and draft_path.exists()

    # Draft is DISABLED and therefore does not match anything.
    text = draft_path.read_text()
    meta, _ = __import__("sre_agent.frontmatter", fromlist=["parse_frontmatter"]).parse_frontmatter(text)
    assert meta["enabled"] is False
    assert meta["approved_by"].startswith("DRAFT")


@pytest.mark.unit
def test_record_candidate_skips_unmapped(known_errors):
    for _ in range(5):
        assert known_errors.record_candidate("UNMAPPED", "svc", "t", [skill_action()]) is None


# --------------------------------------------------------------------------- #
# Gate integration (the safety-critical path)
# --------------------------------------------------------------------------- #

def _nodes(known_errors, skills, hooks, knowledge_store, agent_memory):
    return SREAgentNodes(
        skills=skills,
        gate=PermissionGate(autonomous_mode=False),
        hooks=hooks,
        knowledge=knowledge_store,
        memory=agent_memory,
        executor=SkillExecutor(registry=skills, dry_run=True, hooks=hooks),
        known_errors=known_errors,
    )


def _prod_incident(app_code="PAY-1"):
    return Incident(
        incident_id="sre-test",
        alert=IncidentAlert(
            alert_id="a-1", source="azure_monitor",
            title="payment-service memory usage critical",
            description="Memory working set exceeded; pods restarting with OOMKilled.",
            resource=ResourceRef(service_name="payment-service", environment="prod", app_code=app_code),
        ),
        severity=Severity.SEV2, service_name="payment-service",
        environment="prod", app_code=app_code,
    )


def _state(incident, actions):
    return {
        "incident": incident,
        "root_cause": RootCauseAnalysis(hypothesis="memory leak", confidence=0.8),
        "mitigation_plan": MitigationPlan(actions=actions),
    }


@pytest.mark.unit
async def test_full_auto_approve_when_all_covered(
    known_errors, skills, hooks, knowledge_store, agent_memory
):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    nodes = _nodes(known_errors, skills, hooks, knowledge_store, agent_memory)
    incident = _prod_incident()
    state = _state(incident, [skill_action()])  # only the covered skill action

    result = await nodes.permission_gate(state)
    decisions = result["gate_decisions"]
    assert decisions[0].outcome == GateOutcome.ALLOW
    assert decisions[0].matched_rule == "known-error:ke-test"
    # Routing: with every action pre-approved, no human pause.
    assert route_after_gate({"gate_decisions": decisions}) == "auto_approve"


@pytest.mark.unit
async def test_partial_coverage_still_pauses(
    known_errors, skills, hooks, knowledge_store, agent_memory
):
    """A covered skill action is auto-allowed but an uncovered manual action
    still forces a human pause."""
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    nodes = _nodes(known_errors, skills, hooks, knowledge_store, agent_memory)
    incident = _prod_incident()
    actions = [
        skill_action("a1"),
        skill_action("a2", kind="manual"),  # not pre-approvable
    ]
    result = await nodes.permission_gate(_state(incident, actions))
    decisions = {d.action_id: d for d in result["gate_decisions"]}
    assert decisions["a1"].outcome == GateOutcome.ALLOW
    assert decisions["a2"].outcome == GateOutcome.REQUIRE_APPROVAL
    assert route_after_gate({"gate_decisions": result["gate_decisions"]}) == "await_approval"


@pytest.mark.unit
async def test_deny_always_wins_over_known_error(
    known_errors, skills, hooks, knowledge_store, agent_memory
):
    """A known error can never upgrade a DENY."""
    write_ke(
        known_errors.apps_dir / "PAY-1" / "known_errors",
        approved_actions=[{"skill_name": "danger", "tool_name": "delete_everything"}],
    )
    nodes = _nodes(known_errors, skills, hooks, knowledge_store, agent_memory)
    incident = _prod_incident()
    # "delete_everything" hits the block-destructive deny rule.
    deny_action = skill_action("a1", skill="danger", tool="delete_everything")
    result = await nodes.permission_gate(_state(incident, [deny_action]))
    assert result["gate_decisions"][0].outcome == GateOutcome.DENY


@pytest.mark.unit
async def test_unmapped_incident_gets_no_preapproval(
    known_errors, skills, hooks, knowledge_store, agent_memory
):
    write_ke(known_errors.global_dir, ke_id="ke-global")
    nodes = _nodes(known_errors, skills, hooks, knowledge_store, agent_memory)
    incident = _prod_incident(app_code="UNMAPPED")
    result = await nodes.permission_gate(_state(incident, [skill_action()]))
    # Prod skill action with no pre-approval -> still requires approval.
    assert result["gate_decisions"][0].outcome == GateOutcome.REQUIRE_APPROVAL


@pytest.mark.unit
async def test_circuit_breaker_disables_on_failure(
    known_errors, skills, hooks, knowledge_store, agent_memory
):
    write_ke(known_errors.apps_dir / "PAY-1" / "known_errors")
    nodes = _nodes(known_errors, skills, hooks, knowledge_store, agent_memory)
    incident = _prod_incident()
    action = skill_action("a1")

    # Force the executed action to fail.
    async def failing_execute(a, incident_id=None):
        return ActionResult(action_id=a.action_id, success=False, error="boom", dry_run=True)

    nodes.executor.execute = failing_execute

    state = _state(incident, [action])
    state["gate_decisions"] = [
        GateDecision(action_id="a1", outcome=GateOutcome.ALLOW, matched_rule="known-error:ke-test")
    ]
    await nodes.execute_mitigation(state)

    # The record must be disabled (circuit breaker) and survive reload.
    assert known_errors.get("ke-test").enabled is False


# --------------------------------------------------------------------------- #
# End-to-end through the service
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_end_to_end_preapproval_flips_skill_decisions(
    service, known_errors, azure_monitor_alert
):
    """A tagged alert with a matching known error auto-allows its skill
    actions (the workflow may still pause for uncovered manual steps)."""
    # Cover both skill tools the planner proposes for this alert.
    write_ke(
        known_errors.apps_dir / "PAY-1" / "known_errors",
        approved_actions=[
            {"skill_name": "aks-memory-pressure", "tool_name": "restart_aks_deployment"},
            {"skill_name": "app-service-restart", "tool_name": "restart_app_service"},
        ],
    )
    payload = copy.deepcopy(azure_monitor_alert)
    payload["data"]["essentials"]["customProperties"] = {"app_code": "PAY-1"}

    result = await service.handle_alert(payload)
    snapshot = await service.graph.aget_state(
        {"configurable": {"thread_id": result["incident_id"]}}
    )
    decisions = snapshot.values.get("gate_decisions", [])
    preapproved = [d for d in decisions if (d.matched_rule or "").startswith("known-error:")]
    assert preapproved, "expected at least one skill action pre-approved by the known error"
    assert all(d.outcome == GateOutcome.ALLOW for d in preapproved)
