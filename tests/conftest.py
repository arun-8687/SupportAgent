"""
Pytest configuration and shared fixtures.
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.graph.state import (
    AppSupportState,
    Classification,
    CorrelationResult,
    DeduplicationAction,
    DeduplicationResult,
    FailureCategory,
    Incident,
    KnowledgeContext,
    Severity,
    TriageResult,
    WorkflowStage,
    create_initial_state,
)
from src.tools.base import BaseTool, ToolRegistry, ToolResult


# =============================================================================
# Event Loop Fixture
# =============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture
def sample_incident() -> Incident:
    """Create a sample incident for testing."""
    return Incident(
        incident_id=f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid4())[:8]}",
        job_name="etl-daily-sales",
        job_type="databricks",
        source_system="Azure-EastUS",
        environment="prod",
        error_message="SparkException: Job aborted due to stage failure: Task 0 in stage 15.0 failed 4 times",
        error_code="SPARK_ABORT",
        stack_trace="org.apache.spark.SparkException: Job aborted...\n  at org.apache.spark.scheduler.DAGScheduler...",
        failure_timestamp=datetime.utcnow(),
        job_run_id="run-12345",
        cluster_id="cluster-abc-123",
        notebook_path="/Users/data-team/etl/daily_sales",
        affected_tables=["sales.daily_summary", "sales.hourly_metrics"],
        owner_team="data-engineering",
        priority_hint="P2"
    )


@pytest.fixture
def sample_incident_dict(sample_incident: Incident) -> Dict[str, Any]:
    """Convert sample incident to dict."""
    return sample_incident.model_dump()


@pytest.fixture
def sample_iws_incident() -> Incident:
    """Create a sample IWS incident."""
    return Incident(
        incident_id=f"INC-IWS-{str(uuid4())[:8]}",
        job_name="DAILY_BATCH_LOAD",
        job_type="iws",
        source_system="DXC",
        environment="prod",
        error_message="Job failed with return code 8 - File not found",
        error_code="RC8",
        failure_timestamp=datetime.utcnow(),
        workstation="PROD_WS01",
        owner_team="batch-operations"
    )


@pytest.fixture
def sample_state(sample_incident: Incident) -> AppSupportState:
    """Create initial state from sample incident."""
    return create_initial_state(sample_incident)


@pytest.fixture
def sample_triage_result() -> TriageResult:
    """Create a sample triage result."""
    return TriageResult(
        classification=Classification(
            category=FailureCategory.DATA_PIPELINE,
            issue_type="Spark job failure",
            root_cause_hypothesis="Transient cluster issue causing task failures",
            hypothesis_confidence=0.75,
            business_impact="medium",
            is_known_issue=False,
            recommended_action="diagnose_further"
        ),
        severity=Severity.P2,
        deduplication=DeduplicationResult(
            action=DeduplicationAction.NEW,
            parent_id=None,
            reason="New incident",
            similar_past_incidents=[]
        ),
        correlations=CorrelationResult(
            correlations=[],
            root_cause_hypothesis=None,
            blast_radius=0,
            confidence=0.0
        ),
        knowledge_context=KnowledgeContext(
            known_errors=[],
            similar_incidents=[],
            applicable_runbooks=[],
            relevant_docs=[],
            recent_changes=[]
        ),
        routing_decision="diagnose"
    )


# =============================================================================
# Mock Fixtures
# =============================================================================

@pytest.fixture
def mock_embedding_client():
    """Mock embedding client."""
    client = AsyncMock()
    # Return a fixed 1536-dimension embedding
    client.embed.return_value = [0.1] * 1536
    client.embed_batch.return_value = [[0.1] * 1536]
    return client


@pytest.fixture
def mock_vector_store(mock_embedding_client):
    """Mock vector store."""
    store = AsyncMock()
    store.embedding_client = mock_embedding_client

    # Default empty results
    store.find_similar_incidents.return_value = []
    store.search_known_errors.return_value = []
    store.search_runbooks.return_value = []
    store.get_recent_incidents.return_value = []
    store.similarity_search.return_value = []

    return store


@pytest.fixture
def mock_itsm_client():
    """Mock ITSM client."""
    client = AsyncMock()
    client.get_recent_incidents.return_value = []
    client.get_recent_changes.return_value = []
    client.get_incident.return_value = None
    return client


@pytest.fixture
def mock_llm():
    """Mock LLM client."""
    llm = AsyncMock()
    llm.ainvoke.return_value = MagicMock(
        content='{"category": "data_pipeline", "issue_type": "Spark failure", "root_cause_hypothesis": "Task failure", "confidence": 0.7, "business_impact": "medium", "is_known_issue": false, "recommended_action": "diagnose_further"}'
    )
    return llm


@pytest.fixture
def tool_registry() -> ToolRegistry:
    """Create a tool registry with mock tools."""
    registry = ToolRegistry()

    # Add a mock tool
    class MockTool(BaseTool):
        @property
        def name(self):
            return "mock_tool"

        @property
        def description(self):
            return "A mock tool for testing"

        async def execute(self, **kwargs):
            return ToolResult(success=True, data={"mock": "data"})

    registry.register(MockTool())
    return registry


# =============================================================================
# Database Fixtures (for integration tests)
# =============================================================================

@pytest.fixture
async def test_database():
    """
    Create a test database connection.

    For integration tests, requires TEST_DATABASE_URL env var.
    """
    import os
    db_url = os.environ.get("TEST_DATABASE_URL")

    if not db_url:
        pytest.skip("TEST_DATABASE_URL not set")

    # Return connection info
    yield {"url": db_url}


# =============================================================================
# Helper Functions
# =============================================================================

def create_incident_with_error(error_message: str, job_type: str = "databricks") -> Incident:
    """Helper to create incidents with specific errors."""
    return Incident(
        incident_id=f"INC-TEST-{str(uuid4())[:8]}",
        job_name="test-job",
        job_type=job_type,
        source_system="test",
        environment="dev",
        error_message=error_message,
        failure_timestamp=datetime.utcnow()
    )
