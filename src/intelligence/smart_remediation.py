"""
Smart Remediation Strategy - SRE-informed decision making.

This ties together:
1. Error classification (what type of error?)
2. Guardrails (are we allowed to act?)
3. Tiered approach (try simple things first)
4. Follow-up tracking (workaround vs real fix)
"""
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import structlog

from src.intelligence.error_classification import (
    ErrorClassifier,
    ErrorClassification,
    ErrorCategory,
    RemediationStrategy
)
from src.intelligence.guardrails import (
    RemediationGuardrails,
    GuardrailCheck,
    GuardrailViolation,
    estimate_action_cost
)

logger = structlog.get_logger()


class ActionType(Enum):
    """Types of remediation actions."""
    RETRY = "retry"
    SCALE_MEMORY = "scale_memory"
    SCALE_CLUSTER = "scale_cluster"
    CLEAR_CACHE = "clear_cache"
    RESTART_CLUSTER = "restart_cluster"
    WAIT = "wait"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    CREATE_FOLLOWUP = "create_followup"


@dataclass
class RemediationAction:
    """A single remediation action."""
    action_type: ActionType
    params: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    estimated_cost_usd: float = 0.0
    estimated_duration_minutes: int = 5
    requires_approval: bool = False
    is_workaround: bool = False


@dataclass
class RemediationPlan:
    """Complete remediation plan with tiered actions."""
    incident_id: str
    classification: ErrorClassification

    # Tiered actions - try in order
    tier1_actions: List[RemediationAction] = field(default_factory=list)  # Quick, safe
    tier2_actions: List[RemediationAction] = field(default_factory=list)  # More invasive
    tier3_actions: List[RemediationAction] = field(default_factory=list)  # Escalation

    # Follow-up for workarounds
    follow_up_ticket: Optional[Dict] = None

    # Guardrail results
    guardrail_checks: List[GuardrailCheck] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.0


class SmartRemediationPlanner:
    """
    Creates intelligent, tiered remediation plans.

    Philosophy:
    1. Classify first, act second
    2. Try cheap/safe things before expensive/risky things
    3. Respect guardrails
    4. Track workarounds vs real fixes
    """

    def __init__(
        self,
        classifier: Optional[ErrorClassifier] = None,
        guardrails: Optional[RemediationGuardrails] = None
    ):
        self.classifier = classifier or ErrorClassifier()
        self.guardrails = guardrails or RemediationGuardrails()

    async def create_plan(
        self,
        incident_id: str,
        job_name: str,
        job_type: str,
        error_message: str,
        stack_trace: Optional[str] = None,
        environment: str = "prod",
        severity: str = "P3",
        retry_count: int = 0,
        current_memory_gb: float = 8.0,
        downstream_job_count: int = 0,
        recent_data_volume_change: Optional[float] = None,
        recent_code_change: bool = False
    ) -> RemediationPlan:
        """Create a smart remediation plan for an incident."""

        # Step 1: Classify the error
        classification = self.classifier.classify(
            error_message=error_message,
            stack_trace=stack_trace,
            retry_count=retry_count,
            recent_data_volume_change=recent_data_volume_change,
            recent_code_change=recent_code_change
        )

        logger.info(
            "error_classified",
            incident_id=incident_id,
            category=classification.category.value,
            strategy=classification.strategy.value,
            confidence=classification.confidence
        )

        # Step 2: Create base plan
        plan = RemediationPlan(
            incident_id=incident_id,
            classification=classification,
            confidence=classification.confidence
        )

        # Step 3: Build actions based on classification
        await self._build_tiered_actions(
            plan=plan,
            job_name=job_name,
            job_type=job_type,
            error_message=error_message,
            current_memory_gb=current_memory_gb
        )

        # Step 4: Check guardrails
        self._apply_guardrails(
            plan=plan,
            job_name=job_name,
            error_pattern=self._extract_error_pattern(error_message),
            environment=environment,
            severity=severity,
            downstream_count=downstream_job_count,
            current_memory_gb=current_memory_gb
        )

        # Step 5: Create follow-up ticket if workaround
        if classification.follow_up_required:
            plan.follow_up_ticket = self._create_follow_up_ticket(
                incident_id=incident_id,
                job_name=job_name,
                classification=classification
            )

        return plan

    async def _build_tiered_actions(
        self,
        plan: RemediationPlan,
        job_name: str,
        job_type: str,
        error_message: str,
        current_memory_gb: float
    ) -> None:
        """Build tiered remediation actions based on classification."""

        classification = plan.classification
        strategy = classification.strategy
        category = classification.category

        # TIER 1: Quick, safe actions (try these first)

        if strategy == RemediationStrategy.RETRY_IMMEDIATE:
            plan.tier1_actions.append(RemediationAction(
                action_type=ActionType.RETRY,
                reason="Transient error - immediate retry",
                estimated_cost_usd=estimate_action_cost("restart_job"),
                estimated_duration_minutes=5
            ))

        elif strategy == RemediationStrategy.RETRY_WITH_BACKOFF:
            plan.tier1_actions.append(RemediationAction(
                action_type=ActionType.WAIT,
                params={"wait_seconds": classification.suggested_wait_seconds},
                reason=f"Backoff before retry ({classification.suggested_wait_seconds}s)"
            ))
            plan.tier1_actions.append(RemediationAction(
                action_type=ActionType.RETRY,
                reason="Retry after backoff",
                estimated_cost_usd=estimate_action_cost("restart_job")
            ))

        elif strategy == RemediationStrategy.INVESTIGATE_FIRST:
            plan.tier1_actions.append(RemediationAction(
                action_type=ActionType.INVESTIGATE,
                params={"gather": ["logs", "metrics", "recent_changes"]},
                reason=classification.reasoning
            ))
            # After investigation, we'll re-evaluate

        # TIER 2: More invasive actions

        if strategy == RemediationStrategy.SCALE_AND_RETRY:
            if classification.resource_type == "memory":
                # Calculate new memory - but respect limits
                proposed_memory = self._calculate_safe_memory_increase(
                    current_memory_gb,
                    classification.estimated_need
                )

                plan.tier2_actions.append(RemediationAction(
                    action_type=ActionType.SCALE_MEMORY,
                    params={
                        "current_memory_gb": current_memory_gb,
                        "new_memory_gb": proposed_memory,
                        "target": "driver"  # or executor
                    },
                    reason=f"Increase memory: {current_memory_gb}GB → {proposed_memory}GB",
                    estimated_cost_usd=estimate_action_cost("scale_memory", memory_gb=int(proposed_memory)),
                    is_workaround=classification.is_workaround
                ))
                plan.tier2_actions.append(RemediationAction(
                    action_type=ActionType.RETRY,
                    reason="Retry with increased memory"
                ))

            elif classification.resource_type == "executors":
                plan.tier2_actions.append(RemediationAction(
                    action_type=ActionType.SCALE_CLUSTER,
                    params={"scale_factor": 1.5},
                    reason="Scale cluster for more parallelism",
                    estimated_cost_usd=estimate_action_cost("scale_cluster"),
                    is_workaround=True
                ))

        # For Databricks-specific issues
        if job_type == "databricks":
            # Clear cache might help with memory issues
            if category == ErrorCategory.RESOURCE and classification.resource_type == "memory":
                plan.tier1_actions.insert(0, RemediationAction(
                    action_type=ActionType.CLEAR_CACHE,
                    reason="Clear Spark cache before retry (might help with memory)",
                    estimated_cost_usd=0
                ))

        # TIER 3: Escalation

        if strategy == RemediationStrategy.ESCALATE_HUMAN:
            plan.tier3_actions.append(RemediationAction(
                action_type=ActionType.ESCALATE,
                params={
                    "reason": classification.reasoning,
                    "context": {
                        "category": category.value,
                        "confidence": classification.confidence
                    }
                },
                reason=classification.reasoning,
                requires_approval=True
            ))

        # Always have escalation as fallback
        if not plan.tier3_actions:
            plan.tier3_actions.append(RemediationAction(
                action_type=ActionType.ESCALATE,
                reason="Escalate if all automated remediation fails"
            ))

    def _apply_guardrails(
        self,
        plan: RemediationPlan,
        job_name: str,
        error_pattern: str,
        environment: str,
        severity: str,
        downstream_count: int,
        current_memory_gb: float
    ) -> None:
        """Apply guardrails to the plan."""

        # Find max proposed memory in actions
        proposed_memory = current_memory_gb
        for action in plan.tier2_actions:
            if action.action_type == ActionType.SCALE_MEMORY:
                proposed_memory = action.params.get("new_memory_gb", current_memory_gb)

        # Calculate total estimated cost
        total_cost = sum(
            a.estimated_cost_usd
            for a in plan.tier1_actions + plan.tier2_actions
        )

        # Run all guardrail checks
        checks = self.guardrails.check_all(
            incident_id=plan.incident_id,
            job_name=job_name,
            error_pattern=error_pattern,
            environment=environment,
            severity=severity,
            downstream_count=downstream_count,
            is_transient=plan.classification.category == ErrorCategory.TRANSIENT,
            proposed_memory_gb=proposed_memory if proposed_memory != current_memory_gb else None,
            current_memory_gb=current_memory_gb,
            estimated_cost_usd=total_cost
        )

        plan.guardrail_checks = checks

        # Check if any guardrail blocks us
        for check in checks:
            if not check.passed:
                if check.violation in [
                    GuardrailViolation.CIRCUIT_BREAKER_OPEN,
                    GuardrailViolation.MAX_RETRIES_EXCEEDED
                ]:
                    # These block automated remediation
                    plan.blocked = True
                    plan.block_reason = check.message
                    # Clear automated actions
                    plan.tier1_actions = []
                    plan.tier2_actions = []
                    # Add escalation
                    plan.tier3_actions = [RemediationAction(
                        action_type=ActionType.ESCALATE,
                        reason=check.message + ". " + check.suggested_action
                    )]
                    break

                elif check.violation == GuardrailViolation.MANUAL_OVERRIDE_REQUIRED:
                    # Mark all actions as requiring approval
                    for action in plan.tier1_actions + plan.tier2_actions:
                        action.requires_approval = True

    def _calculate_safe_memory_increase(
        self,
        current_gb: float,
        estimated_need: Optional[str]
    ) -> float:
        """Calculate a safe memory increase."""
        # Default: 1.5x current
        multiplier = 1.5

        if estimated_need:
            # Parse "2.0x current" format
            if "x current" in estimated_need:
                try:
                    multiplier = float(estimated_need.split("x")[0])
                except ValueError:
                    pass

        # Cap at 2x in a single jump (guardrails will enforce hard limits)
        multiplier = min(multiplier, 2.0)

        # Round to nice numbers
        proposed = current_gb * multiplier
        nice_values = [8, 12, 16, 24, 32, 48, 64]
        for nice in nice_values:
            if nice >= proposed:
                return float(nice)

        return proposed

    def _extract_error_pattern(self, error_message: str) -> str:
        """Extract a generalizable error pattern for circuit breaker."""
        import re

        # Remove specific IDs, timestamps, paths
        pattern = error_message
        pattern = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', pattern)
        pattern = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '<TIMESTAMP>', pattern)
        pattern = re.sub(r'/[^\s]+', '<PATH>', pattern)
        pattern = re.sub(r'\d+', '<N>', pattern)

        # Take first 100 chars
        return pattern[:100]

    def _create_follow_up_ticket(
        self,
        incident_id: str,
        job_name: str,
        classification: ErrorClassification
    ) -> Dict:
        """Create follow-up ticket for workarounds."""
        return {
            "type": "follow_up",
            "parent_incident": incident_id,
            "title": f"Investigate root cause for {job_name}",
            "description": classification.follow_up_reason,
            "priority": "P4",  # Lower priority than incident
            "tags": [
                "auto-generated",
                "workaround-applied",
                classification.category.value
            ],
            "context": {
                "original_error": classification.reasoning,
                "workaround_applied": True,
                "resource_type": classification.resource_type
            }
        }


# Convenience function for agents to use
async def get_smart_remediation(
    incident_id: str,
    job_name: str,
    job_type: str,
    error_message: str,
    **kwargs
) -> RemediationPlan:
    """Get a smart remediation plan for an incident."""
    planner = SmartRemediationPlanner()
    return await planner.create_plan(
        incident_id=incident_id,
        job_name=job_name,
        job_type=job_type,
        error_message=error_message,
        **kwargs
    )
