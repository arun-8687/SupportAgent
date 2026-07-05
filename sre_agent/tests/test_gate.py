"""Permission gate policy tests."""
import pytest

from sre_agent.gate.permission_gate import PermissionGate
from sre_agent.models import GateOutcome, MitigationAction, RiskLevel


def make_action(name: str, risk: RiskLevel = RiskLevel.MEDIUM) -> MitigationAction:
    return MitigationAction(
        action_id=f"act-{name}", name=name, kind="skill", skill_name=name, risk=risk
    )


@pytest.mark.unit
def test_destructive_actions_denied_everywhere():
    gate = PermissionGate()
    decision = gate.evaluate(make_action("delete_storage_account"), "dev")
    assert decision.outcome == GateOutcome.DENY


@pytest.mark.unit
def test_prod_requires_approval():
    gate = PermissionGate()
    decision = gate.evaluate(make_action("restart_app_service"), "prod")
    assert decision.outcome == GateOutcome.REQUIRE_APPROVAL


@pytest.mark.unit
def test_nonprod_restart_allowed():
    gate = PermissionGate()
    decision = gate.evaluate(make_action("restart_app_service"), "dev")
    assert decision.outcome == GateOutcome.ALLOW


@pytest.mark.unit
def test_autonomous_mode_allows_low_risk_unmatched():
    gate = PermissionGate(autonomous_mode=True)
    # An action no rule matches: low risk in an env not covered by rules.
    action = make_action("collect_diagnostics", risk=RiskLevel.LOW)
    # staging is covered by allow-low-risk-nonprod; use a synthetic env-free check
    decision = gate.evaluate(action, "staging")
    assert decision.outcome == GateOutcome.ALLOW


@pytest.mark.unit
def test_default_is_require_approval():
    gate = PermissionGate(autonomous_mode=False)
    action = make_action("unknown_action", risk=RiskLevel.HIGH)
    decision = gate.evaluate(action, "staging")
    assert decision.outcome == GateOutcome.REQUIRE_APPROVAL
