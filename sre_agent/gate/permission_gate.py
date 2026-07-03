"""
Permission gate — the pre-execution safety layer.

Every proposed mitigation action is evaluated against operator-defined
policy rules BEFORE it can run. Rules match on action name (glob), risk
level, and environment, and produce one of three outcomes:

  allow             -> action may run without a human in the loop
  require_approval  -> action pauses the workflow for human sign-off
  deny              -> action is blocked outright

The default posture is reviewed mode: anything not explicitly allowed
requires approval. Autonomous mode (settings.autonomous_mode) lets
low-risk actions through automatically, but deny rules always win.
"""
import fnmatch
import logging
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.models import GateDecision, GateOutcome, MitigationAction, RiskLevel

logger = logging.getLogger(__name__)


class GateRule(BaseModel):
    """One policy rule. All specified match fields must match."""
    name: str
    action: Optional[str] = None          # glob against action/skill name
    risk: Optional[List[RiskLevel]] = None
    environment: Optional[List[str]] = None
    decision: GateOutcome

    def matches(self, action: MitigationAction, environment: str) -> bool:
        if self.action is not None:
            # The gate evaluates proposed tool calls: match the tool being
            # invoked (falling back to the action name for manual steps).
            target = action.tool_name or action.name
            if not fnmatch.fnmatch(target, self.action):
                return False
        if self.risk is not None and action.risk not in self.risk:
            return False
        if self.environment is not None and environment not in self.environment:
            return False
        return True


class GatePolicy(BaseModel):
    """Full policy document."""
    default: GateOutcome = GateOutcome.REQUIRE_APPROVAL
    rules: List[GateRule] = Field(default_factory=list)


class PermissionGate:
    """Evaluates proposed actions against the loaded policy."""

    def __init__(self, policy_file: Optional[Path] = None, autonomous_mode: Optional[bool] = None) -> None:
        settings = get_settings()
        self.policy = self._load(policy_file or settings.gate_policy_file)
        self.autonomous_mode = (
            settings.autonomous_mode if autonomous_mode is None else autonomous_mode
        )

    @staticmethod
    def _load(path: Path) -> GatePolicy:
        if not path.exists():
            logger.warning("Gate policy %s missing; defaulting to require_approval", path)
            return GatePolicy()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return GatePolicy.model_validate(data)

    def evaluate(self, action: MitigationAction, environment: str) -> GateDecision:
        """First matching rule wins; deny rules are checked first."""
        matching = [r for r in self.policy.rules if r.matches(action, environment)]

        for rule in matching:
            if rule.decision == GateOutcome.DENY:
                return GateDecision(
                    action_id=action.action_id,
                    outcome=GateOutcome.DENY,
                    matched_rule=rule.name,
                    reason=f"Blocked by policy rule '{rule.name}'",
                )

        if matching:
            rule = matching[0]
            return GateDecision(
                action_id=action.action_id,
                outcome=rule.decision,
                matched_rule=rule.name,
                reason=f"Matched policy rule '{rule.name}'",
            )

        # No rule matched: autonomous mode auto-approves low risk only.
        if self.autonomous_mode and action.risk == RiskLevel.LOW:
            return GateDecision(
                action_id=action.action_id,
                outcome=GateOutcome.ALLOW,
                matched_rule=None,
                reason="Autonomous mode: low-risk action auto-approved",
            )

        return GateDecision(
            action_id=action.action_id,
            outcome=self.policy.default,
            matched_rule=None,
            reason=f"No rule matched; policy default is {self.policy.default.value}",
        )

    def evaluate_plan(self, actions: List[MitigationAction], environment: str) -> List[GateDecision]:
        return [self.evaluate(action, environment) for action in actions]
