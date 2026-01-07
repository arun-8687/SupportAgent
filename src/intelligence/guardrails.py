"""
Remediation Guardrails - Safety limits for auto-remediation.

SRE Philosophy:
1. Automation should have hard limits
2. Cost matters - don't bankrupt the company to fix a P4
3. Know when to stop trying and call a human
4. Track what we're doing for audit
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional
import structlog

logger = structlog.get_logger()


class GuardrailViolation(Enum):
    """Types of guardrail violations."""
    MAX_RETRIES_EXCEEDED = "max_retries_exceeded"
    MAX_MEMORY_EXCEEDED = "max_memory_exceeded"
    MAX_COST_EXCEEDED = "max_cost_exceeded"
    MAX_BLAST_RADIUS = "max_blast_radius"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    TIME_WINDOW_VIOLATION = "time_window_violation"
    MANUAL_OVERRIDE_REQUIRED = "manual_override_required"


@dataclass
class GuardrailConfig:
    """Configuration for remediation guardrails."""

    # Retry limits
    max_retries_transient: int = 3
    max_retries_resource: int = 1  # Be conservative with scaling
    retry_window_minutes: int = 60  # Reset retry count after this

    # Memory scaling limits
    max_driver_memory_gb: int = 32  # Hard cap
    max_executor_memory_gb: int = 64
    max_memory_multiplier: float = 2.0  # Don't more than double in one shot

    # Cost limits (per incident)
    max_cost_per_incident_usd: float = 100.0
    max_cluster_scale_factor: float = 2.0  # Don't more than double cluster size

    # Blast radius limits
    max_affected_downstream_jobs: int = 5  # If more, get human approval
    block_if_prod_critical: bool = True  # P1 prod = human always

    # Circuit breaker (stop trying if pattern emerges)
    circuit_breaker_threshold: int = 5  # Failures in window
    circuit_breaker_window_minutes: int = 30
    circuit_breaker_cooldown_minutes: int = 60

    # Time-based restrictions
    block_auto_fix_during_freeze: bool = True
    change_freeze_windows: List[str] = field(default_factory=list)  # ["FRI 18:00-MON 06:00"]

    # Environment-specific
    require_approval_for_prod: bool = False  # True = always need human for prod
    auto_approve_dev_only: bool = True


@dataclass
class GuardrailCheck:
    """Result of a guardrail check."""
    passed: bool
    violation: Optional[GuardrailViolation] = None
    message: str = ""
    can_override: bool = False  # Can a human override this?
    suggested_action: str = ""


@dataclass
class IncidentHistory:
    """Track what we've done for an incident."""
    incident_id: str
    retry_count: int = 0
    last_retry_at: Optional[datetime] = None
    memory_scales: List[Dict] = field(default_factory=list)
    total_cost_usd: float = 0.0
    actions_taken: List[str] = field(default_factory=list)


class CircuitBreaker:
    """
    Circuit breaker to stop repeated failures.

    Pattern: If we see N failures of similar type in M minutes,
    stop trying and escalate.
    """

    def __init__(self, threshold: int = 5, window_minutes: int = 30, cooldown_minutes: int = 60):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.cooldown = timedelta(minutes=cooldown_minutes)
        # Key: (job_name, error_pattern) -> List[failure_times]
        self._failures: Dict[tuple, List[datetime]] = {}
        self._open_circuits: Dict[tuple, datetime] = {}

    def record_failure(self, job_name: str, error_pattern: str) -> None:
        """Record a failure for circuit breaker tracking."""
        key = (job_name, error_pattern)
        now = datetime.utcnow()

        if key not in self._failures:
            self._failures[key] = []

        self._failures[key].append(now)

        # Clean old failures
        cutoff = now - self.window
        self._failures[key] = [t for t in self._failures[key] if t > cutoff]

        # Check if we should open the circuit
        if len(self._failures[key]) >= self.threshold:
            self._open_circuits[key] = now
            logger.warning(
                "circuit_breaker_opened",
                job_name=job_name,
                error_pattern=error_pattern,
                failure_count=len(self._failures[key])
            )

    def is_open(self, job_name: str, error_pattern: str) -> bool:
        """Check if circuit breaker is open (should not retry)."""
        key = (job_name, error_pattern)

        if key not in self._open_circuits:
            return False

        opened_at = self._open_circuits[key]
        now = datetime.utcnow()

        # Check if cooldown has passed
        if now - opened_at > self.cooldown:
            del self._open_circuits[key]
            logger.info(
                "circuit_breaker_reset",
                job_name=job_name,
                error_pattern=error_pattern
            )
            return False

        return True

    def record_success(self, job_name: str, error_pattern: str) -> None:
        """Record success - reset failure count."""
        key = (job_name, error_pattern)
        if key in self._failures:
            del self._failures[key]
        if key in self._open_circuits:
            del self._open_circuits[key]


class RemediationGuardrails:
    """
    Safety guardrails for auto-remediation.

    Enforces limits on:
    - Retry counts
    - Resource scaling
    - Cost
    - Blast radius
    - Time windows
    """

    def __init__(self, config: Optional[GuardrailConfig] = None):
        self.config = config or GuardrailConfig()
        self.circuit_breaker = CircuitBreaker(
            threshold=self.config.circuit_breaker_threshold,
            window_minutes=self.config.circuit_breaker_window_minutes,
            cooldown_minutes=self.config.circuit_breaker_cooldown_minutes
        )
        # In-memory history (should be persisted in real implementation)
        self._incident_history: Dict[str, IncidentHistory] = {}

    def get_or_create_history(self, incident_id: str) -> IncidentHistory:
        """Get or create incident history."""
        if incident_id not in self._incident_history:
            self._incident_history[incident_id] = IncidentHistory(incident_id=incident_id)
        return self._incident_history[incident_id]

    def check_can_retry(
        self,
        incident_id: str,
        job_name: str,
        error_pattern: str,
        is_transient: bool = True
    ) -> GuardrailCheck:
        """Check if we can retry this incident."""
        history = self.get_or_create_history(incident_id)

        # Check circuit breaker first
        if self.circuit_breaker.is_open(job_name, error_pattern):
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.CIRCUIT_BREAKER_OPEN,
                message=f"Circuit breaker open for {job_name}/{error_pattern}. Too many failures.",
                can_override=True,
                suggested_action="Wait for cooldown or manually investigate"
            )

        # Check retry count
        max_retries = (
            self.config.max_retries_transient if is_transient
            else self.config.max_retries_resource
        )

        # Reset count if window passed
        if history.last_retry_at:
            window = timedelta(minutes=self.config.retry_window_minutes)
            if datetime.utcnow() - history.last_retry_at > window:
                history.retry_count = 0

        if history.retry_count >= max_retries:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MAX_RETRIES_EXCEEDED,
                message=f"Max retries ({max_retries}) exceeded for incident",
                can_override=True,
                suggested_action="Escalate to human for investigation"
            )

        return GuardrailCheck(passed=True, message="Retry allowed")

    def check_can_scale_memory(
        self,
        incident_id: str,
        current_memory_gb: float,
        proposed_memory_gb: float,
        is_driver: bool = True
    ) -> GuardrailCheck:
        """Check if we can scale to proposed memory."""

        # Hard cap
        max_allowed = (
            self.config.max_driver_memory_gb if is_driver
            else self.config.max_executor_memory_gb
        )

        if proposed_memory_gb > max_allowed:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MAX_MEMORY_EXCEEDED,
                message=f"Proposed {proposed_memory_gb}GB exceeds max allowed {max_allowed}GB",
                can_override=True,
                suggested_action=f"Review job efficiency - why does it need >{max_allowed}GB?"
            )

        # Multiplier check - don't scale too aggressively
        multiplier = proposed_memory_gb / current_memory_gb if current_memory_gb > 0 else 999
        if multiplier > self.config.max_memory_multiplier:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MAX_MEMORY_EXCEEDED,
                message=f"Scaling {multiplier:.1f}x exceeds max multiplier {self.config.max_memory_multiplier}x",
                can_override=True,
                suggested_action=f"Scale incrementally - try {current_memory_gb * self.config.max_memory_multiplier:.0f}GB first"
            )

        return GuardrailCheck(passed=True, message="Memory scaling allowed")

    def check_blast_radius(
        self,
        downstream_job_count: int,
        is_prod: bool,
        severity: str
    ) -> GuardrailCheck:
        """Check if blast radius is acceptable for auto-fix."""

        if downstream_job_count > self.config.max_affected_downstream_jobs:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MAX_BLAST_RADIUS,
                message=f"{downstream_job_count} downstream jobs affected - exceeds limit of {self.config.max_affected_downstream_jobs}",
                can_override=True,
                suggested_action="Get human approval due to high blast radius"
            )

        if is_prod and severity == "P1" and self.config.block_if_prod_critical:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MANUAL_OVERRIDE_REQUIRED,
                message="P1 production incident requires human approval",
                can_override=True,
                suggested_action="Page on-call for approval"
            )

        if is_prod and self.config.require_approval_for_prod:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MANUAL_OVERRIDE_REQUIRED,
                message="Production changes require human approval",
                can_override=True,
                suggested_action="Request approval from on-call"
            )

        return GuardrailCheck(passed=True, message="Blast radius acceptable")

    def check_cost_limit(
        self,
        incident_id: str,
        estimated_cost_usd: float
    ) -> GuardrailCheck:
        """Check if action cost is within limits."""
        history = self.get_or_create_history(incident_id)

        total_cost = history.total_cost_usd + estimated_cost_usd

        if total_cost > self.config.max_cost_per_incident_usd:
            return GuardrailCheck(
                passed=False,
                violation=GuardrailViolation.MAX_COST_EXCEEDED,
                message=f"Total cost ${total_cost:.2f} exceeds limit ${self.config.max_cost_per_incident_usd:.2f}",
                can_override=True,
                suggested_action="Escalate - too expensive to auto-remediate"
            )

        return GuardrailCheck(passed=True, message=f"Cost ${total_cost:.2f} within limit")

    def check_all(
        self,
        incident_id: str,
        job_name: str,
        error_pattern: str,
        environment: str,
        severity: str,
        downstream_count: int = 0,
        is_transient: bool = True,
        proposed_memory_gb: Optional[float] = None,
        current_memory_gb: Optional[float] = None,
        estimated_cost_usd: float = 0.0
    ) -> List[GuardrailCheck]:
        """Run all applicable guardrail checks."""
        checks = []

        # Always check retry limits
        checks.append(self.check_can_retry(
            incident_id=incident_id,
            job_name=job_name,
            error_pattern=error_pattern,
            is_transient=is_transient
        ))

        # Check memory scaling if applicable
        if proposed_memory_gb and current_memory_gb:
            checks.append(self.check_can_scale_memory(
                incident_id=incident_id,
                current_memory_gb=current_memory_gb,
                proposed_memory_gb=proposed_memory_gb
            ))

        # Check blast radius
        is_prod = environment.lower() == "prod"
        checks.append(self.check_blast_radius(
            downstream_job_count=downstream_count,
            is_prod=is_prod,
            severity=severity
        ))

        # Check cost
        if estimated_cost_usd > 0:
            checks.append(self.check_cost_limit(
                incident_id=incident_id,
                estimated_cost_usd=estimated_cost_usd
            ))

        return checks

    def record_action(
        self,
        incident_id: str,
        action: str,
        cost_usd: float = 0.0,
        memory_change: Optional[Dict] = None
    ) -> None:
        """Record an action taken for audit trail."""
        history = self.get_or_create_history(incident_id)
        history.actions_taken.append(action)
        history.total_cost_usd += cost_usd

        if memory_change:
            history.memory_scales.append(memory_change)

        if "retry" in action.lower():
            history.retry_count += 1
            history.last_retry_at = datetime.utcnow()

        logger.info(
            "remediation_action_recorded",
            incident_id=incident_id,
            action=action,
            cost_usd=cost_usd,
            total_actions=len(history.actions_taken)
        )

    def record_failure(self, job_name: str, error_pattern: str) -> None:
        """Record failure for circuit breaker."""
        self.circuit_breaker.record_failure(job_name, error_pattern)

    def record_success(self, job_name: str, error_pattern: str) -> None:
        """Record success - reset circuit breaker."""
        self.circuit_breaker.record_success(job_name, error_pattern)


# Convenience function for cost estimation
def estimate_action_cost(
    action: str,
    duration_minutes: int = 30,
    memory_gb: int = 8,
    num_executors: int = 2
) -> float:
    """
    Rough cost estimation for Databricks actions.
    Actual costs should come from your cloud pricing.
    """
    # Rough DBU rates (example)
    DBU_PER_HOUR_DRIVER = 0.5
    DBU_PER_HOUR_EXECUTOR = 0.3
    DBU_COST = 0.15  # $/DBU

    if action == "restart_job":
        # Just job restart - cluster already running
        hours = duration_minutes / 60
        total_dbu = hours * (DBU_PER_HOUR_DRIVER + (DBU_PER_HOUR_EXECUTOR * num_executors))
        return total_dbu * DBU_COST

    elif action == "scale_memory":
        # Memory increase might require cluster restart
        hours = duration_minutes / 60
        memory_multiplier = memory_gb / 8  # Base 8GB
        total_dbu = hours * (DBU_PER_HOUR_DRIVER * memory_multiplier +
                           (DBU_PER_HOUR_EXECUTOR * num_executors))
        return total_dbu * DBU_COST

    elif action == "scale_cluster":
        # Adding executors
        hours = duration_minutes / 60
        total_dbu = hours * (DBU_PER_HOUR_DRIVER +
                           (DBU_PER_HOUR_EXECUTOR * num_executors))
        return total_dbu * DBU_COST

    return 0.0
