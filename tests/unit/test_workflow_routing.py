"""
Tests for the workflow routing logic.
"""
import pytest
from datetime import datetime, timezone

from src.graph.state import (
    AppSupportState,
    ApprovalDecision,
    Classification,
    DeduplicationAction,
    DeduplicationResult,
    DiagnosticResult,
    ExecutionResult,
    ExecutionStep,
    FailureCategory,
    Incident,
    RemediationProposal,
    RemediationStep,
    RootCause,
    Severity,
    TriageResult,
    VerificationResult,
    WorkflowStage,
    create_initial_state,
)
from src.graph.workflow import (
    route_after_triage,
    route_after_diagnose,
    route_after_proposal,
    route_after_approval,
    route_after_execution,
    route_after_verification,
)


@pytest.fixture
def sample_incident():
    """Create a sample incident."""
    return Incident(
        incident_id="INC-ROUTE-001",
        job_name="test-job",
        job_type="databricks",
        source_system="Azure",
        environment="prod",
        error_message="Test error",
        failure_timestamp=datetime.now(timezone.utc),
        priority_hint="P2"
    )


def make_classification(
    category=FailureCategory.DATA_PIPELINE,
    is_known_issue=False,
    confidence=0.5,
    recommended_action="auto_fix"
):
    """Helper to create Classification with required fields."""
    return Classification(
        category=category,
        issue_type="test_issue",
        root_cause_hypothesis="Test hypothesis",
        hypothesis_confidence=confidence,
        business_impact="medium",
        is_known_issue=is_known_issue,
        recommended_action=recommended_action
    )


def make_proposal(
    source="known_error",
    success_prob=0.9,
    requires_approval=False,
    risk_level="low"
):
    """Helper to create RemediationProposal with required fields."""
    return RemediationProposal(
        source=source,
        steps=[
            RemediationStep(
                name="test_step",
                tool="restart_job",
                params={},
                description="Test step",
                risk_level=risk_level
            )
        ],
        estimated_success_probability=success_prob,
        risk_assessment="Low risk test",
        requires_approval=requires_approval,
        reasoning="Test reasoning"
    )


class TestRouteAfterTriage:
    """Tests for route_after_triage."""

    def test_suppress_on_duplicate(self, sample_incident):
        """Test routing to suppress on duplicate detection."""
        state = create_initial_state(sample_incident)
        state["triage_result"] = TriageResult(
            severity=Severity.P3,
            classification=make_classification(),
            deduplication=DeduplicationResult(
                action=DeduplicationAction.DUPLICATE,
                parent_id="INC-PARENT-001",
                confidence=0.95
            )
        )

        result = route_after_triage(state)
        assert result == "suppress"

    def test_proposal_on_high_confidence_known_issue(self, sample_incident):
        """Test routing to proposal for high-confidence known issues."""
        state = create_initial_state(sample_incident)
        state["triage_result"] = TriageResult(
            severity=Severity.P3,
            classification=make_classification(
                is_known_issue=True,
                confidence=0.95
            ),
            deduplication=DeduplicationResult(action=DeduplicationAction.NEW)
        )

        result = route_after_triage(state)
        assert result == "proposal"

    def test_escalate_on_human_review(self, sample_incident):
        """Test routing to escalate when human review is recommended."""
        state = create_initial_state(sample_incident)
        state["triage_result"] = TriageResult(
            severity=Severity.P1,
            classification=make_classification(
                category=FailureCategory.UNKNOWN,
                confidence=0.3,
                recommended_action="escalate_human"
            ),
            deduplication=DeduplicationResult(action=DeduplicationAction.NEW)
        )

        result = route_after_triage(state)
        assert result == "escalate"

    def test_diagnose_for_p1_even_if_known(self, sample_incident):
        """Test that P1 incidents always get diagnosed."""
        state = create_initial_state(sample_incident)
        state["triage_result"] = TriageResult(
            severity=Severity.P1,
            classification=make_classification(
                category=FailureCategory.INFRASTRUCTURE,
                is_known_issue=True,
                confidence=0.8
            ),
            deduplication=DeduplicationResult(action=DeduplicationAction.NEW)
        )

        result = route_after_triage(state)
        assert result == "diagnose"

    def test_diagnose_on_missing_triage(self, sample_incident):
        """Test default to diagnose when triage is missing."""
        state = create_initial_state(sample_incident)
        result = route_after_triage(state)
        assert result == "diagnose"


class TestRouteAfterDiagnose:
    """Tests for route_after_diagnose."""

    def test_proposal_on_high_confidence(self, sample_incident):
        """Test routing to proposal with high confidence root cause."""
        state = create_initial_state(sample_incident)
        state["diagnostic_result"] = DiagnosticResult(
            root_cause=RootCause(
                description="Memory exhaustion",
                confidence=0.85,
                supporting_evidence=["High memory usage"],
                recommended_approach="auto_fix"
            ),
            evidence=[],
            hypotheses_tested=[],
            reasoning_chain=[],
            affected_systems=[]
        )

        result = route_after_diagnose(state)
        assert result == "proposal"

    def test_escalate_on_low_confidence(self, sample_incident):
        """Test routing to escalate with low confidence."""
        state = create_initial_state(sample_incident)
        state["diagnostic_result"] = DiagnosticResult(
            root_cause=RootCause(
                description="Unknown issue",
                confidence=0.3,
                supporting_evidence=[],
                recommended_approach="escalate"
            ),
            evidence=[],
            hypotheses_tested=[],
            reasoning_chain=[],
            affected_systems=[]
        )

        result = route_after_diagnose(state)
        assert result == "escalate"

    def test_escalate_on_missing_diagnostic(self, sample_incident):
        """Test escalate when diagnostic is missing."""
        state = create_initial_state(sample_incident)
        result = route_after_diagnose(state)
        assert result == "escalate"


class TestRouteAfterProposal:
    """Tests for route_after_proposal."""

    def test_auto_approve_low_risk(self, sample_incident):
        """Test auto-approval for low-risk proposals."""
        state = create_initial_state(sample_incident)
        state["incident"] = sample_incident
        state["proposal"] = make_proposal(
            success_prob=0.95,
            requires_approval=False
        )

        result = route_after_proposal(state)
        assert result == "auto_approve"

    def test_human_approve_high_risk(self, sample_incident):
        """Test human approval for high-risk proposals."""
        state = create_initial_state(sample_incident)
        state["incident"] = sample_incident
        state["proposal"] = make_proposal(
            source="novel",
            success_prob=0.7,
            requires_approval=True,
            risk_level="high"
        )

        result = route_after_proposal(state)
        assert result == "human_approve"

    def test_escalate_on_missing_proposal(self, sample_incident):
        """Test escalate when proposal is missing."""
        state = create_initial_state(sample_incident)
        result = route_after_proposal(state)
        assert result == "escalate"


class TestRouteAfterApproval:
    """Tests for route_after_approval."""

    def test_execute_on_approval(self, sample_incident):
        """Test routing to execute on approval."""
        state = create_initial_state(sample_incident)
        state["approval"] = ApprovalDecision(
            approved=True,
            approver="auto",
            reason="Auto-approved",
            approved_at=datetime.now(timezone.utc)
        )

        result = route_after_approval(state)
        assert result == "execute"

    def test_escalate_on_rejection(self, sample_incident):
        """Test routing to escalate on rejection."""
        state = create_initial_state(sample_incident)
        state["approval"] = ApprovalDecision(
            approved=False,
            approver="human",
            approver_id="user@example.com",
            reason="Too risky",
            approved_at=datetime.now(timezone.utc)
        )

        result = route_after_approval(state)
        assert result == "escalate"

    def test_escalate_on_missing_approval(self, sample_incident):
        """Test escalate when approval is missing."""
        state = create_initial_state(sample_incident)
        result = route_after_approval(state)
        assert result == "escalate"


class TestRouteAfterExecution:
    """Tests for route_after_execution."""

    def test_verify_on_success(self, sample_incident):
        """Test routing to verify on successful execution."""
        state = create_initial_state(sample_incident)
        state["execution_result"] = ExecutionResult(
            success=True,
            executed_steps=[
                ExecutionStep(
                    step_name="restart",
                    tool="restart_job",
                    success=True,
                    output={},
                    execution_time_ms=5000,
                    executed_at=datetime.now(timezone.utc)
                )
            ]
        )

        result = route_after_execution(state)
        assert result == "verify"

    def test_rollback_on_failure(self, sample_incident):
        """Test routing to rollback on failed execution."""
        state = create_initial_state(sample_incident)
        state["execution_result"] = ExecutionResult(
            success=False,
            executed_steps=[],
            error_message="Execution failed"
        )

        result = route_after_execution(state)
        assert result == "rollback"

    def test_rollback_on_missing_result(self, sample_incident):
        """Test rollback when execution result is missing."""
        state = create_initial_state(sample_incident)
        result = route_after_execution(state)
        assert result == "rollback"


class TestRouteAfterVerification:
    """Tests for route_after_verification."""

    def test_resolve_on_success(self, sample_incident):
        """Test routing to resolve on successful verification."""
        state = create_initial_state(sample_incident)
        state["verification_result"] = VerificationResult(
            success=True,
            verification_checks=[{"check": "job_status", "passed": True}],
            job_status="SUCCEEDED"
        )

        result = route_after_verification(state)
        assert result == "resolve"

    def test_retry_on_failure_with_retries(self, sample_incident):
        """Test routing to retry when verification fails with retries available."""
        state = create_initial_state(sample_incident)
        state["verification_result"] = VerificationResult(
            success=False,
            verification_checks=[{"check": "job_status", "passed": False}],
            job_status="FAILED"
        )
        state["retry_count"] = 1
        state["max_retries"] = 3

        result = route_after_verification(state)
        assert result == "retry"

    def test_escalate_on_max_retries(self, sample_incident):
        """Test routing to escalate when max retries reached."""
        state = create_initial_state(sample_incident)
        state["verification_result"] = VerificationResult(
            success=False,
            verification_checks=[],
            job_status="FAILED"
        )
        state["retry_count"] = 3
        state["max_retries"] = 3

        result = route_after_verification(state)
        assert result == "escalate"

    def test_escalate_on_missing_verification(self, sample_incident):
        """Test escalate when verification result is missing."""
        state = create_initial_state(sample_incident)
        result = route_after_verification(state)
        assert result == "escalate"
