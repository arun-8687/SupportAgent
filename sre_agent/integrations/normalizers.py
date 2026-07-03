"""
Alert normalizers.

Messages arriving on the Service Bus topic can come from Azure Monitor
(Common Alert Schema), PagerDuty (webhook v3), ServiceNow, or custom
publishers. Each is normalized to an IncidentAlert before entering the
workflow, so the graph is source-agnostic.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from sre_agent.models import AlertSource, Incident, IncidentAlert, ResourceRef, Severity

logger = logging.getLogger(__name__)

_AZMON_SEVERITY = {
    "Sev0": Severity.SEV1,
    "Sev1": Severity.SEV1,
    "Sev2": Severity.SEV2,
    "Sev3": Severity.SEV3,
    "Sev4": Severity.SEV4,
}

_PAGERDUTY_URGENCY = {"high": Severity.SEV2, "low": Severity.SEV3}


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def _environment_from(text: str) -> str:
    lowered = text.lower()
    if any(tag in lowered for tag in ("prod", "prd")):
        return "prod"
    if any(tag in lowered for tag in ("stag", "uat", "preprod")):
        return "staging"
    return "prod"  # safest default: treat unknown as production


def normalize_azure_monitor(payload: Dict[str, Any]) -> IncidentAlert:
    """Azure Monitor Common Alert Schema -> IncidentAlert."""
    essentials = payload.get("data", {}).get("essentials", payload.get("essentials", {}))
    context = payload.get("data", {}).get("alertContext", {})
    targets = essentials.get("alertTargetIDs", [])
    resource_id = targets[0] if targets else None

    resource_group = None
    service_name = "unknown"
    if resource_id:
        parts = resource_id.strip("/").split("/")
        if "resourceGroups" in parts:
            resource_group = parts[parts.index("resourceGroups") + 1]
        service_name = parts[-1] if parts else "unknown"

    return IncidentAlert(
        alert_id=essentials.get("alertId", f"azmon-{uuid.uuid4().hex[:10]}"),
        source=AlertSource.AZURE_MONITOR,
        title=essentials.get("alertRule", "Azure Monitor alert"),
        description=essentials.get("description", ""),
        severity_hint=_AZMON_SEVERITY.get(essentials.get("severity", "")),
        resource=ResourceRef(
            resource_id=resource_id,
            resource_group=resource_group,
            service_name=service_name,
            environment=_environment_from(resource_id or ""),
        ),
        signals=context.get("condition", {}),
        fired_at=_parse_ts(essentials.get("firedDateTime")),
        raw=payload,
    )


def normalize_pagerduty(payload: Dict[str, Any]) -> IncidentAlert:
    """PagerDuty webhook v3 -> IncidentAlert."""
    event = payload.get("event", payload)
    data = event.get("data", {})
    service = data.get("service", {})
    return IncidentAlert(
        alert_id=data.get("id", f"pd-{uuid.uuid4().hex[:10]}"),
        source=AlertSource.PAGERDUTY,
        title=data.get("title", "PagerDuty incident"),
        description=data.get("description", data.get("title", "")),
        severity_hint=_PAGERDUTY_URGENCY.get(data.get("urgency", "")),
        resource=ResourceRef(
            service_name=service.get("summary", "unknown"),
            environment=_environment_from(service.get("summary", "")),
        ),
        fired_at=_parse_ts(event.get("occurred_at")),
        raw=payload,
    )


def normalize_servicenow(payload: Dict[str, Any]) -> IncidentAlert:
    """ServiceNow incident record -> IncidentAlert."""
    urgency = str(payload.get("urgency", "3"))
    severity = {"1": Severity.SEV1, "2": Severity.SEV2}.get(urgency, Severity.SEV3)
    return IncidentAlert(
        alert_id=payload.get("number", f"snow-{uuid.uuid4().hex[:10]}"),
        source=AlertSource.SERVICENOW,
        title=payload.get("short_description", "ServiceNow incident"),
        description=payload.get("description", ""),
        severity_hint=severity,
        resource=ResourceRef(
            service_name=payload.get("cmdb_ci", "unknown"),
            environment=_environment_from(payload.get("cmdb_ci", "")),
        ),
        fired_at=_parse_ts(payload.get("opened_at")),
        raw=payload,
    )


def normalize_custom(payload: Dict[str, Any]) -> IncidentAlert:
    """Already-shaped IncidentAlert payloads (custom publishers)."""
    return IncidentAlert.model_validate(payload)


NORMALIZERS = {
    "azure_monitor": normalize_azure_monitor,
    "pagerduty": normalize_pagerduty,
    "servicenow": normalize_servicenow,
    "custom": normalize_custom,
}


def normalize(payload: Dict[str, Any], source_hint: str = "") -> IncidentAlert:
    """
    Detect the payload shape and normalize.

    source_hint (e.g. a Service Bus application property) short-circuits
    detection when the publisher labels its messages.
    """
    if source_hint in NORMALIZERS:
        return NORMALIZERS[source_hint](payload)

    if "data" in payload and "essentials" in payload.get("data", {}):
        return normalize_azure_monitor(payload)
    if "essentials" in payload:
        return normalize_azure_monitor(payload)
    if "event" in payload and "data" in payload.get("event", {}):
        return normalize_pagerduty(payload)
    if "short_description" in payload:
        return normalize_servicenow(payload)
    if "alert_id" in payload and "source" in payload:
        return normalize_custom(payload)

    logger.warning("Unrecognized alert payload; wrapping as custom alert")
    return IncidentAlert(
        alert_id=f"unknown-{uuid.uuid4().hex[:10]}",
        source=AlertSource.CUSTOM,
        title=str(payload.get("title", "Unclassified alert")),
        description=str(payload)[:2000],
        raw=payload,
    )


def to_incident(alert: IncidentAlert) -> Incident:
    """Wrap a normalized alert in a tracked Incident."""
    return Incident(
        incident_id=f"sre-{uuid.uuid4().hex[:10]}",
        alert=alert,
        severity=alert.severity_hint or Severity.SEV3,
        service_name=alert.resource.service_name,
        environment=alert.resource.environment,
    )
