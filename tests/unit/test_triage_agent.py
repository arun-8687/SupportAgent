"""
Unit tests for the triage agent.
"""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.agents.triage_agent import TriageAgent
from src.graph.state import (
    Classification,
    CorrelationResult,
    DeduplicationAction,
    DeduplicationResult,
    FailureCategory,
    KnowledgeContext,
    Severity,
)
from src.tools.base import ToolRegistry


class TestTriageAgent:
    """Tests for TriageAgent."""

    @pytest.fixture
    def triage_agent(
        self,
        tool_registry,
        mock_embedding_client,
        mock_vector_store,
        mock_itsm_client,
        mock_llm
    ):
        """Create triage agent with mocked dependencies."""
        from src.intelligence.correlation import CorrelationEngine, DependencyGraph
        from src.intelligence.deduplication import IncidentDeduplicator
        from src.intelligence.knowledge_retrieval import KnowledgeRetriever

        deduplicator = IncidentDeduplicator(
            embedding_client=mock_embedding_client,
            vector_store=mock_vector_store
        )

        knowledge_retriever = KnowledgeRetriever(
            vector_store=mock_vector_store,
            embedding_client=mock_embedding_client,
            itsm_client=mock_itsm_client
        )

        correlation_engine = CorrelationEngine(
            dependency_graph=DependencyGraph(),
            itsm_client=mock_itsm_client
        )

        agent = TriageAgent(
            tool_registry=tool_registry,
            deduplicator=deduplicator,
            knowledge_retriever=knowledge_retriever,
            correlation_engine=correlation_engine,
            llm=mock_llm
        )

        return agent

    @pytest.mark.asyncio
    async def test_execute_new_incident(
        self,
        triage_agent,
        sample_state,
        mock_vector_store
    ):
        """Test triage of a new incident."""
        # Setup: No duplicates
        mock_vector_store.get_recent_incidents.return_value = []
        mock_vector_store.find_similar_incidents.return_value = []

        result = await triage_agent.execute(sample_state)

        assert "triage_result" in result
        assert result["triage_result"].deduplication.action == DeduplicationAction.NEW

    @pytest.mark.asyncio
    async def test_execute_duplicate_suppressed(
        self,
        triage_agent,
        sample_state,
        sample_incident,
        mock_vector_store
    ):
        """Test that duplicate incidents are suppressed."""
        # Setup: Return exact match
        mock_match = MagicMock()
        mock_match.id = "parent-incident-123"
        mock_match.similarity = 0.98
        mock_match.metadata = {
            "job_name": sample_incident.job_name,
            "error_message": sample_incident.error_message,
            "created_at": datetime.utcnow()
        }

        mock_vector_store.get_recent_incidents.return_value = [
            {"incident_id": "parent-incident-123", "job_name": sample_incident.job_name}
        ]
        mock_vector_store.find_similar_incidents.return_value = [mock_match]

        result = await triage_agent.execute(sample_state)

        assert "triage_result" in result
        assert result["triage_result"].deduplication.action == DeduplicationAction.SUPPRESS
        assert result.get("incident_closed") is True

    def test_assess_severity_high_impact(self, triage_agent, sample_incident):
        """Test severity calculation for high impact."""
        from src.graph.state import Correlation

        correlations = CorrelationResult(
            correlations=[
                Correlation(
                    type="UPSTREAM_FAILURE",
                    relationship="test",
                    confidence=0.8
                ),
                Correlation(
                    type="DOWNSTREAM_IMPACT",
                    relationship="test",
                    confidence=0.7
                )
            ],
            blast_radius=5,
            confidence=0.75
        )

        classification = Classification(
            category=FailureCategory.DATA_PIPELINE,
            issue_type="test",
            root_cause_hypothesis="test",
            hypothesis_confidence=0.7,
            business_impact="critical",
            recommended_action="diagnose_further"
        )

        severity = triage_agent._assess_severity(
            sample_incident, correlations, classification
        )

        # Critical impact + correlations + prod = high severity
        assert severity in [Severity.P1, Severity.P2]

    def test_assess_severity_low_impact(self, triage_agent, sample_incident):
        """Test severity calculation for low impact."""
        correlations = CorrelationResult(
            correlations=[],
            blast_radius=0,
            confidence=0.0
        )

        classification = Classification(
            category=FailureCategory.APPLICATION,
            issue_type="test",
            root_cause_hypothesis="test",
            hypothesis_confidence=0.9,
            business_impact="low",
            recommended_action="auto_fix"
        )

        # Change to dev environment
        sample_incident.environment = "dev"

        severity = triage_agent._assess_severity(
            sample_incident, correlations, classification
        )

        # Low impact + no correlations + dev = low severity
        assert severity in [Severity.P3, Severity.P4]

    def test_determine_routing_known_issue(self, triage_agent):
        """Test routing for known issues."""
        classification = Classification(
            category=FailureCategory.DATA_PIPELINE,
            issue_type="Known error",
            root_cause_hypothesis="Documented issue",
            hypothesis_confidence=0.95,
            business_impact="medium",
            is_known_issue=True,
            matched_known_error_id="KE-123",
            recommended_action="auto_fix"
        )

        knowledge = KnowledgeContext(
            known_errors=[],  # Would have the matched error
            similar_incidents=[],
            applicable_runbooks=["runbooks/databricks/restart.yaml"],
            relevant_docs=[],
            recent_changes=[]
        )

        routing = triage_agent._determine_routing(
            classification, Severity.P3, knowledge
        )

        assert routing == "proposal"

    def test_determine_routing_needs_diagnosis(self, triage_agent):
        """Test routing when diagnosis is needed."""
        classification = Classification(
            category=FailureCategory.UNKNOWN,
            issue_type="Unknown",
            root_cause_hypothesis="Needs investigation",
            hypothesis_confidence=0.3,
            business_impact="medium",
            is_known_issue=False,
            recommended_action="diagnose_further"
        )

        knowledge = KnowledgeContext()

        routing = triage_agent._determine_routing(
            classification, Severity.P2, knowledge
        )

        assert routing == "diagnose"

    def test_determine_routing_escalate(self, triage_agent):
        """Test routing for escalation."""
        classification = Classification(
            category=FailureCategory.INFRASTRUCTURE,
            issue_type="Critical infrastructure",
            root_cause_hypothesis="Unknown",
            hypothesis_confidence=0.2,
            business_impact="critical",
            is_known_issue=False,
            recommended_action="escalate_human"
        )

        knowledge = KnowledgeContext()

        routing = triage_agent._determine_routing(
            classification, Severity.P1, knowledge
        )

        assert routing == "escalate"
