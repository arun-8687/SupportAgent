"""Alert normalizer tests."""
import copy

import pytest
import yaml

from sre_agent.config import get_settings
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


# --------------------------------------------------------------------------- #
# app_code
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_app_code_default_unmapped(azure_monitor_alert):
    """No customProperties.app_code and no mapping file -> UNMAPPED."""
    alert = normalize(azure_monitor_alert)
    assert alert.resource.app_code == "UNMAPPED"
    incident = to_incident(alert)
    assert incident.app_code == "UNMAPPED"


@pytest.mark.unit
def test_azure_monitor_app_code_from_custom_properties(azure_monitor_alert):
    payload = copy.deepcopy(azure_monitor_alert)
    payload["data"]["essentials"]["customProperties"] = {"app_code": "PAY-42"}
    alert = normalize(payload)
    assert alert.resource.app_code == "PAY-42"


@pytest.mark.unit
def test_azure_monitor_app_code_missing_custom_properties(azure_monitor_alert):
    """customProperties absent entirely must not raise."""
    payload = copy.deepcopy(azure_monitor_alert)
    payload["data"]["essentials"].pop("customProperties", None)
    alert = normalize(payload)
    assert alert.resource.app_code == "UNMAPPED"


@pytest.mark.unit
def test_azure_monitor_app_code_null_custom_properties(azure_monitor_alert):
    """customProperties explicitly null must not raise."""
    payload = copy.deepcopy(azure_monitor_alert)
    payload["data"]["essentials"]["customProperties"] = None
    alert = normalize(payload)
    assert alert.resource.app_code == "UNMAPPED"


@pytest.mark.unit
def test_pagerduty_app_code_from_custom_fields(pagerduty_alert):
    payload = copy.deepcopy(pagerduty_alert)
    payload["event"]["data"]["custom_fields"] = [
        {"name": "team", "value": "checkout"},
        {"name": "app_code", "value": "CHK-7"},
    ]
    alert = normalize(payload)
    assert alert.resource.app_code == "CHK-7"


@pytest.mark.unit
def test_pagerduty_app_code_absent_custom_fields(pagerduty_alert):
    alert = normalize(pagerduty_alert)
    assert alert.resource.app_code == "UNMAPPED"


@pytest.mark.unit
def test_servicenow_app_code_from_payload():
    alert = normalize(
        {
            "number": "INC0012345",
            "short_description": "orders-api degraded",
            "description": "High latency on orders-api",
            "urgency": "1",
            "cmdb_ci": "orders-api-staging",
            "opened_at": "2026-07-03T02:00:00Z",
            "u_app_code": "ORD-3",
        }
    )
    assert alert.resource.app_code == "ORD-3"


@pytest.mark.unit
def test_custom_payload_app_code_passthrough():
    """Already-shaped custom payloads: resource.app_code passes through pydantic."""
    alert = normalize(
        {
            "alert_id": "custom-1",
            "source": "custom",
            "title": "custom alert",
            "resource": {"service_name": "widgets", "app_code": "WID-9"},
        }
    )
    assert alert.resource.app_code == "WID-9"


@pytest.mark.unit
def test_app_code_map_file_fallback(tmp_path, monkeypatch):
    """Mapping file resolves app_code when the payload carries none."""
    map_file = tmp_path / "app_code_map.yaml"
    map_file.write_text(yaml.safe_dump({"orders-api-staging": "ORD-MAPPED"}))

    monkeypatch.setenv("SRE_AGENT_APP_CODE_MAP_FILE", str(map_file))
    get_settings.cache_clear()
    try:
        alert = normalize(
            {
                "number": "INC0099999",
                "short_description": "orders-api degraded",
                "cmdb_ci": "orders-api-staging",
            }
        )
        assert alert.resource.app_code == "ORD-MAPPED"

        # A service with no map entry keeps UNMAPPED.
        alert2 = normalize(
            {
                "number": "INC0099998",
                "short_description": "unrelated",
                "cmdb_ci": "some-other-service",
            }
        )
        assert alert2.resource.app_code == "UNMAPPED"
    finally:
        monkeypatch.delenv("SRE_AGENT_APP_CODE_MAP_FILE", raising=False)
        get_settings.cache_clear()


@pytest.mark.unit
def test_app_code_map_file_unset_keeps_unmapped():
    alert = normalize(
        {
            "number": "INC0011111",
            "short_description": "svc issue",
            "cmdb_ci": "no-mapping-service",
        }
    )
    assert alert.resource.app_code == "UNMAPPED"
