"""
Unit tests for the deduplication module.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from src.graph.state import DeduplicationAction, Incident
from src.intelligence.deduplication import IncidentDeduplicator, EventStormDetector


class TestIncidentDeduplicator:
    """Tests for IncidentDeduplicator class."""

    @pytest.fixture
    def deduplicator(self, mock_embedding_client, mock_vector_store):
        """Create deduplicator with mocks."""
        return IncidentDeduplicator(
            embedding_client=mock_embedding_client,
            vector_store=mock_vector_store,
            similarity_threshold=0.85,
            time_window_minutes=15,
            storm_threshold=10
        )

    @pytest.mark.asyncio
    async def test_new_incident_no_duplicates(
        self,
        deduplicator,
        sample_incident,
        mock_vector_store
    ):
        """Test that a new incident with no matches returns NEW action."""
        # No similar incidents
        mock_vector_store.get_recent_incidents.return_value = []
        mock_vector_store.find_similar_incidents.return_value = []

        result = await deduplicator.process_incoming_incident(sample_incident)

        assert result.action == DeduplicationAction.NEW
        assert result.parent_id is None
        assert "New incident" in result.reason

    @pytest.mark.asyncio
    async def test_exact_duplicate_detected(
        self,
        deduplicator,
        sample_incident,
        mock_vector_store
    ):
        """Test that exact duplicates are suppressed."""
        from src.storage.vector_store import SimilarityMatch

        # Return a very similar incident
        mock_match = MagicMock()
        mock_match.id = "existing-incident-123"
        mock_match.similarity = 0.98
        mock_match.metadata = {
            "job_name": sample_incident.job_name,
            "error_message": sample_incident.error_message,
            "created_at": datetime.utcnow()
        }
        mock_match.content = sample_incident.error_message

        mock_vector_store.get_recent_incidents.return_value = [
            {"incident_id": "existing-incident-123", "job_name": sample_incident.job_name}
        ]
        mock_vector_store.find_similar_incidents.return_value = [mock_match]

        result = await deduplicator.process_incoming_incident(sample_incident)

        assert result.action == DeduplicationAction.SUPPRESS
        assert result.parent_id == "existing-incident-123"

    @pytest.mark.asyncio
    async def test_related_incident_linked(
        self,
        deduplicator,
        sample_incident,
        mock_vector_store
    ):
        """Test that related incidents are linked."""
        mock_match = MagicMock()
        mock_match.id = "related-incident-456"
        mock_match.similarity = 0.88  # Above threshold but not exact
        mock_match.metadata = {
            "job_name": sample_incident.job_name,
            "error_message": "Different but related error",
            "created_at": datetime.utcnow()
        }
        mock_match.content = "Different but related error"

        mock_vector_store.get_recent_incidents.return_value = [
            {"incident_id": "related-incident-456", "job_name": sample_incident.job_name}
        ]
        mock_vector_store.find_similar_incidents.return_value = [mock_match]

        result = await deduplicator.process_incoming_incident(sample_incident)

        assert result.action == DeduplicationAction.RELATED
        assert result.parent_id == "related-incident-456"

    @pytest.mark.asyncio
    async def test_event_storm_detected(
        self,
        deduplicator,
        sample_incident,
        mock_vector_store,
        mock_embedding_client
    ):
        """Test that event storms are detected when threshold exceeded."""
        # Create many recent incidents
        recent = [
            {
                "incident_id": f"storm-inc-{i}",
                "job_name": sample_incident.job_name,
                "error_message": sample_incident.error_message
            }
            for i in range(15)  # Above storm threshold
        ]
        mock_vector_store.get_recent_incidents.return_value = recent
        mock_vector_store.find_similar_incidents.return_value = []

        result = await deduplicator.process_incoming_incident(sample_incident)

        assert result.action == DeduplicationAction.STORM
        assert "storm" in result.reason.lower()

    def test_create_incident_text(self, deduplicator, sample_incident):
        """Test incident text generation for embedding."""
        text = deduplicator._create_incident_text(sample_incident)

        assert sample_incident.job_name in text
        assert sample_incident.job_type in text
        assert sample_incident.error_message in text

    def test_jobs_related_same_prefix(self, deduplicator):
        """Test job relatedness detection."""
        assert deduplicator._are_jobs_related("etl-sales-daily", "etl-sales-weekly")
        assert deduplicator._are_jobs_related("etl_sales_load", "etl_sales_transform")

    def test_jobs_not_related_different_names(self, deduplicator):
        """Test unrelated jobs."""
        assert not deduplicator._are_jobs_related("etl-sales", "api-gateway")


class TestEventStormDetector:
    """Tests for EventStormDetector class."""

    @pytest.fixture
    def detector(self, mock_embedding_client):
        """Create detector with mocks."""
        return EventStormDetector(
            embedding_client=mock_embedding_client,
            window_minutes=5,
            threshold=5
        )

    def test_cluster_by_time(self, detector):
        """Test time-based clustering."""
        now = datetime.utcnow()

        # Create incidents in two time clusters
        incidents = [
            Incident(
                incident_id=f"inc-{i}",
                job_name="test-job",
                job_type="databricks",
                source_system="test",
                environment="prod",
                error_message="Error",
                failure_timestamp=now + timedelta(minutes=i)
            )
            for i in range(3)
        ] + [
            Incident(
                incident_id=f"inc-late-{i}",
                job_name="test-job",
                job_type="databricks",
                source_system="test",
                environment="prod",
                error_message="Error",
                failure_timestamp=now + timedelta(minutes=20 + i)
            )
            for i in range(3)
        ]

        clusters = detector._cluster_by_time(incidents)

        # Should have 2 clusters
        assert len(clusters) == 2
        assert len(clusters[0]) == 3
        assert len(clusters[1]) == 3

    @pytest.mark.asyncio
    async def test_no_storm_below_threshold(self, detector):
        """Test no storm detected below threshold."""
        incidents = [
            Incident(
                incident_id=f"inc-{i}",
                job_name="test-job",
                job_type="databricks",
                source_system="test",
                environment="prod",
                error_message="Error",
                failure_timestamp=datetime.utcnow()
            )
            for i in range(3)  # Below threshold of 5
        ]

        result = await detector.detect_storm(incidents)

        assert result is None
