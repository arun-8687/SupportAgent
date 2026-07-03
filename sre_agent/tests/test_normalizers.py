"""Alert normalizer tests."""
import pytest

from sre_agent.integrations.normalizers import normalize, to_incident
from sre_agent.models import AlertSource, Severity


@pytest.mark.unit
def test_azure_monitor_normalization(azure_monitor_alert):
    alert = normalize(azure_monitor_alert)
    assert alert.source == AlertSource.AZURE_MONITOR
    assert alert.severity_hint == Severity.SEV2
    assert alert.resource.service_name == "payment-service"
    assert alert.resource.resource_group == "prod-payments-rg"
    assert alert.resource.environment == "prod"
    assert alert.signals.get("metricName") == "MemoryWorkingSet"


@pytest.mark.unit
def test_pagerduty_normalization(pagerduty_alert):
    alert = normalize(pagerduty_alert)
    assert alert.source == AlertSource.PAGERDUTY
    assert alert.severity_hint == Severity.SEV2
    assert alert.resource.service_name == "checkout-frontend-prod"
    assert alert.resource.environment == "prod"


@pytest.mark.unit
def test_servicenow_normalization():
    alert = normalize(
        {
            "number": "INC0012345",
            "short_description": "orders-api degraded",
            "description": "High latency on orders-api",
            "urgency": "1",
            "cmdb_ci": "orders-api-staging",
            "opened_at": "2026-07-03T02:00:00Z",
        }
    )
    assert alert.source == AlertSource.SERVICENOW
    assert alert.severity_hint == Severity.SEV1
    assert alert.resource.environment == "staging"


@pytest.mark.unit
def test_source_hint_short_circuits_detection(pagerduty_alert):
    alert = normalize(pagerduty_alert, source_hint="pagerduty")
    assert alert.source == AlertSource.PAGERDUTY


@pytest.mark.unit
def test_unknown_payload_wrapped_as_custom():
    alert = normalize({"foo": "bar"})
    assert alert.source == AlertSource.CUSTOM
    assert alert.alert_id.startswith("unknown-")


@pytest.mark.unit
def test_to_incident(azure_monitor_alert):
    incident = to_incident(normalize(azure_monitor_alert))
    assert incident.incident_id.startswith("sre-")
    assert incident.service_name == "payment-service"
    assert incident.environment == "prod"
