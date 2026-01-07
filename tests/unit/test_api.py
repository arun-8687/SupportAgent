"""
Tests for the API endpoints.
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from src.api.main import create_app, RateLimiter


@pytest.fixture
def app():
    """Create test app instance."""
    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def api_headers():
    """Create headers with API key."""
    return {"X-API-Key": "test-api-key"}


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_liveness_probe(self, client):
        """Test liveness probe returns alive."""
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_readiness_probe_success(self, client):
        """Test readiness probe when healthy."""
        with patch("src.api.main.health.is_healthy", new_callable=AsyncMock) as mock_health:
            mock_health.return_value = True
            response = client.get("/health/ready")
            assert response.status_code == 200
            assert response.json()["status"] == "ready"

    def test_readiness_probe_failure(self, client):
        """Test readiness probe when unhealthy."""
        with patch("src.api.main.health.is_healthy", new_callable=AsyncMock) as mock_health:
            mock_health.return_value = False
            response = client.get("/health/ready")
            assert response.status_code == 503

    def test_health_check_returns_components(self, client):
        """Test health check returns component status."""
        with patch("src.api.main.health.check_all", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = {}
            with patch("src.api.main.health.get_status") as mock_status:
                mock_status.return_value = {
                    "status": "healthy",
                    "components": {
                        "database": {"healthy": True, "message": "OK", "latency_ms": 5},
                        "llm": {"healthy": True, "message": "OK", "latency_ms": 10}
                    }
                }
                response = client.get("/health")
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "healthy"
                assert "components" in data


class TestAuthentication:
    """Tests for API authentication."""

    def test_missing_api_key_rejected(self, client):
        """Test that missing API key returns 401."""
        response = client.post("/api/v1/incidents", json={
            "job_name": "test-job",
            "job_type": "databricks",
            "source_system": "Azure",
            "environment": "prod",
            "error_message": "Test error"
        })
        assert response.status_code == 401
        assert "Missing API key" in response.json()["detail"]

    def test_valid_api_key_accepted(self, client, api_headers):
        """Test that valid API key is accepted."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                environment="development",
                api_keys="test-api-key"
            )
            with patch("src.api.main.process_incident", new_callable=AsyncMock):
                response = client.post(
                    "/api/v1/incidents",
                    json={
                        "job_name": "test-job",
                        "job_type": "databricks",
                        "source_system": "Azure",
                        "environment": "prod",
                        "error_message": "Test error"
                    },
                    headers=api_headers
                )
                # Should not be 401 or 403
                assert response.status_code not in [401, 403]


class TestRateLimiter:
    """Tests for rate limiting."""

    def test_rate_limiter_allows_under_limit(self):
        """Test rate limiter allows requests under limit."""
        limiter = RateLimiter(requests_per_minute=10)

        for i in range(10):
            assert limiter.is_allowed("client-1") is True

    def test_rate_limiter_blocks_over_limit(self):
        """Test rate limiter blocks requests over limit."""
        limiter = RateLimiter(requests_per_minute=5)

        # Use up the limit
        for i in range(5):
            limiter.is_allowed("client-1")

        # Next request should be blocked
        assert limiter.is_allowed("client-1") is False

    def test_rate_limiter_separate_clients(self):
        """Test rate limiter tracks clients separately."""
        limiter = RateLimiter(requests_per_minute=5)

        # Use up client-1's limit
        for i in range(5):
            limiter.is_allowed("client-1")

        # client-2 should still be allowed
        assert limiter.is_allowed("client-2") is True


class TestIncidentEndpoints:
    """Tests for incident management endpoints."""

    def test_create_incident_success(self, client, api_headers):
        """Test successful incident creation."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            with patch("src.api.main.process_incident", new_callable=AsyncMock):
                response = client.post(
                    "/api/v1/incidents",
                    json={
                        "job_name": "test-etl-job",
                        "job_type": "databricks",
                        "source_system": "Azure-EastUS",
                        "environment": "prod",
                        "error_message": "OutOfMemoryError: Java heap space",
                        "priority_hint": "P2"
                    },
                    headers=api_headers
                )
                assert response.status_code == 200
                data = response.json()
                assert "incident_id" in data
                assert data["status"] == "processing"

    def test_create_incident_missing_fields(self, client, api_headers):
        """Test incident creation with missing required fields."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            response = client.post(
                "/api/v1/incidents",
                json={
                    "job_name": "test-job"
                    # Missing required fields
                },
                headers=api_headers
            )
            assert response.status_code == 422  # Validation error

    def test_get_incident_not_found(self, client, api_headers):
        """Test getting non-existent incident returns 404."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            with patch("src.api.main.get_vector_store", new_callable=AsyncMock) as mock_vs:
                mock_pool = MagicMock()
                mock_conn = MagicMock()
                mock_conn.fetchrow = AsyncMock(return_value=None)
                mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
                mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
                mock_vs.return_value.pool = mock_pool

                response = client.get(
                    "/api/v1/incidents/INC-NOTEXIST",
                    headers=api_headers
                )
                assert response.status_code == 404


class TestApprovalEndpoints:
    """Tests for approval management endpoints."""

    def test_submit_approval_success(self, client, api_headers):
        """Test successful approval submission."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            with patch("src.api.main.continue_incident_workflow", new_callable=AsyncMock):
                response = client.post(
                    "/api/v1/approvals",
                    json={
                        "incident_id": "INC-12345678",
                        "approved": True,
                        "approver": "admin@example.com",
                        "reason": "Looks safe to proceed"
                    },
                    headers=api_headers
                )
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "approved"

    def test_submit_rejection(self, client, api_headers):
        """Test rejection submission."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            response = client.post(
                "/api/v1/approvals",
                json={
                    "incident_id": "INC-12345678",
                    "approved": False,
                    "approver": "admin@example.com",
                    "reason": "Too risky"
                },
                headers=api_headers
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "rejected"

    def test_get_pending_approvals(self, client, api_headers):
        """Test getting pending approvals."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            response = client.get(
                "/api/v1/approvals/pending",
                headers=api_headers
            )
            assert response.status_code == 200
            assert "pending" in response.json()


class TestDashboardEndpoints:
    """Tests for dashboard endpoints."""

    def test_get_dashboard_summary(self, client, api_headers):
        """Test dashboard summary endpoint."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            response = client.get(
                "/api/v1/dashboard/summary",
                headers=api_headers
            )
            assert response.status_code == 200
            data = response.json()
            assert "incidents_received" in data
            assert "incidents_resolved" in data
            assert "auto_resolution_rate" in data

    def test_get_recent_incidents(self, client, api_headers):
        """Test getting recent incidents for dashboard."""
        with patch("src.api.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(environment="development")
            with patch("src.api.main.get_vector_store", new_callable=AsyncMock) as mock_vs:
                mock_pool = MagicMock()
                mock_conn = MagicMock()
                mock_conn.fetch = AsyncMock(return_value=[])
                mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
                mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
                mock_vs.return_value.pool = mock_pool

                response = client.get(
                    "/api/v1/dashboard/recent?limit=10",
                    headers=api_headers
                )
                assert response.status_code == 200
                assert "incidents" in response.json()


class TestMetricsEndpoint:
    """Tests for metrics endpoint."""

    def test_metrics_returns_prometheus_format(self, client):
        """Test metrics endpoint returns Prometheus format."""
        response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"
        # Should contain some metric names
        content = response.text
        assert "support_agent" in content or len(content) > 0
