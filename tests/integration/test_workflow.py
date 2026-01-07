"""
Integration tests for the workflow.
"""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.graph.state import (
    AppSupportState,
    Incident,
    WorkflowStage,
    create_initial_state,
)
from src.graph.workflow import (
    route_after_triage,
    route_after_diagnose,
    route_after_proposal,
)


class TestWorkflowRouting:
    """Tests for workflow routing functions."""

    def test_route_after_triage_to_suppress(self, sample_state, sample_triage_result):
        """Test routing to suppress for duplicates."""
        from src.graph.state import DeduplicationAction, DeduplicationResult

        # Modify triage result to indicate duplicate
        sample_triage_result.deduplication = DeduplicationResult(
            action=DeduplicationAction.SUPPRESS,
            parent_id="parent-123",
            reason="Duplicate"
        )
        sample_state["triage_result"] = sample_triage_result

        route = route_after_triage(sample_state)

        assert route == "suppress"

    def test_route_after_triage_to_diagnose(self, sample_state, sample_triage_result):
        """Test routing to diagnose for new incidents."""
        sample_state["triage_result"] = sample_triage_result

        route = route_after_triage(sample_state)

        assert route == "diagnose"

    def test_route_after_triage_to_proposal(self, sample_state, sample_triage_result):
        """Test routing to proposal for known issues."""
        from src.graph.state import Classification, FailureCategory

        sample_triage_result.classification = Classification(
            category=FailureCategory.DATA_PIPELINE,
            issue_type="Known error",
            root_cause_hypothesis="Known issue KE-123",
            hypothesis_confidence=0.95,
            business_impact="medium",
            is_known_issue=True,
            matched_known_error_id="KE-123",
            recommended_action="auto_fix"
        )
        sample_state["triage_result"] = sample_triage_result

        route = route_after_triage(sample_state)

        assert route == "proposal"

    def test_route_after_triage_to_escalate(self, sample_state, sample_triage_result):
        """Test routing to escalate."""
        from src.graph.state import Classification, FailureCategory

        sample_triage_result.classification = Classification(
            category=FailureCategory.UNKNOWN,
            issue_type="Critical",
            root_cause_hypothesis="Unknown",
            hypothesis_confidence=0.1,
            business_impact="critical",
            is_known_issue=False,
            recommended_action="escalate_human"
        )
        sample_state["triage_result"] = sample_triage_result

        route = route_after_triage(sample_state)

        assert route == "escalate"

    def test_route_after_diagnose_to_proposal(self, sample_state):
        """Test routing to proposal after successful diagnosis."""
        from src.graph.state import DiagnosticResult, RootCause

        sample_state["diagnostic_result"] = DiagnosticResult(
            root_cause=RootCause(
                description="Cluster resource exhaustion",
                confidence=0.85,
                supporting_evidence=["Log analysis shows OOM"],
                recommended_approach="auto_fix"
            ),
            evidence=[],
            hypotheses_tested=[],
            reasoning_chain=[],
            affected_systems=["cluster-123"]
        )

        route = route_after_diagnose(sample_state)

        assert route == "proposal"

    def test_route_after_diagnose_to_escalate_low_confidence(self, sample_state):
        """Test routing to escalate for low confidence diagnosis."""
        from src.graph.state import DiagnosticResult, RootCause

        sample_state["diagnostic_result"] = DiagnosticResult(
            root_cause=RootCause(
                description="Unknown issue",
                confidence=0.3,
                supporting_evidence=[],
                recommended_approach="manual_investigation"
            ),
            evidence=[],
            hypotheses_tested=[],
            reasoning_chain=[],
            affected_systems=[]
        )

        route = route_after_diagnose(sample_state)

        assert route == "escalate"

    def test_route_after_proposal_auto_approve(self, sample_state):
        """Test routing to auto-approve for safe fixes."""
        from src.graph.state import RemediationProposal, RemediationStep

        sample_state["proposal"] = RemediationProposal(
            source="known_error",
            steps=[
                RemediationStep(
                    name="Restart job",
                    tool="restart_databricks_job",
                    params={"job_id": "123"},
                    description="Restart the job",
                    risk_level="low",
                    supports_rollback=True
                )
            ],
            estimated_success_probability=0.95,
            risk_assessment="Low risk restart operation",
            requires_approval=False,
            reasoning="Known transient failure"
        )

        # Set environment to non-prod for easier auto-approval
        sample_state["incident"].environment = "dev"

        route = route_after_proposal(sample_state)

        assert route == "auto_approve"

    def test_route_after_proposal_human_approve(self, sample_state):
        """Test routing to human approval for risky fixes."""
        from src.graph.state import RemediationProposal, RemediationStep

        sample_state["proposal"] = RemediationProposal(
            source="novel",
            steps=[
                RemediationStep(
                    name="Modify data",
                    tool="execute_sql",
                    params={"query": "UPDATE..."},
                    description="Modify production data",
                    risk_level="high",
                    supports_rollback=False
                )
            ],
            estimated_success_probability=0.6,
            risk_assessment="High risk data modification",
            requires_approval=True,
            reasoning="Novel solution"
        )

        route = route_after_proposal(sample_state)

        assert route == "human_approve"


class TestWorkflowIntegration:
    """Integration tests for the full workflow."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_simple_incident_flow(
        self,
        sample_incident_dict,
        mock_embedding_client,
        mock_vector_store
    ):
        """Test a simple incident through the workflow."""
        # This would require full setup
        # Marked as integration test
        pytest.skip("Requires full service setup")
