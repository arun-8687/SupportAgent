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
from typing import Any, Dict, Optional

import yaml

from sre_agent.config import get_settings
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


def _load_app_code_map() -> Dict[str, str]:
    """Optional service_name -> app_code mapping (settings.app_code_map_file).

    Missing file or unset setting -> empty map, callers keep "UNMAPPED".
    """
    path = get_settings().app_code_map_file
    if not path:
        return {}
    try:
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("Failed to read app_code_map_file %s", path)
        return {}
    return data if isinstance(data, dict) else {}


def _apply_app_code_fallback(resource: ResourceRef) -> None:
    """Fill resource.app_code from the mapping file when still UNMAPPED."""
    if resource.app_code and resource.app_code != "UNMAPPED":
        return
    mapping = _load_app_code_map()
    app_code = mapping.get(resource.service_name)
    if app_code:
        resource.app_code = app_code


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

    custom_properties = essentials.get("customProperties") or essentials.get("custom_properties") or {}
    if not isinstance(custom_properties, dict):
        custom_properties = {}
    app_code = custom_properties.get("app_code")

    resource = ResourceRef(
        resource_id=resource_id,
        resource_group=resource_group,
        service_name=service_name,
        environment=_environment_from(resource_id or ""),
        **({"app_code": app_code} if app_code else {}),
    )
    _apply_app_code_fallback(resource)

    return IncidentAlert(
        alert_id=essentials.get("alertId", f"azmon-{uuid.uuid4().hex[:10]}"),
        source=AlertSource.AZURE_MONITOR,
        title=essentials.get("alertRule", "Azure Monitor alert"),
        description=essentials.get("description", ""),
        severity_hint=_AZMON_SEVERITY.get(essentials.get("severity", "")),
        resource=resource,
        signals=context.get("condition", {}),
        fired_at=_parse_ts(essentials.get("firedDateTime")),
        raw=payload,
    )


def _pagerduty_app_code(data: Dict[str, Any]) -> Optional[str]:
    """PagerDuty custom_fields: list of {name|field, value} -> app_code."""
    custom_fields = data.get("custom_fields")
    if not isinstance(custom_fields, list):
        return None
    for field in custom_fields:
        if not isinstance(field, dict):
            continue
        key = field.get("name") or field.get("field")
        if key == "app_code":
            value = field.get("value")
            return str(value) if value else None
    return None


def normalize_pagerduty(payload: Dict[str, Any]) -> IncidentAlert:
    """PagerDuty webhook v3 -> IncidentAlert."""
    event = payload.get("event", payload)
    data = event.get("data", {})
    service = data.get("service", {})

    app_code = _pagerduty_app_code(data)
    resource = ResourceRef(
        service_name=service.get("summary", "unknown"),
        environment=_environment_from(service.get("summary", "")),
        **({"app_code": app_code} if app_code else {}),
    )
    _apply_app_code_fallback(resource)

    return IncidentAlert(
        alert_id=data.get("id", f"pd-{uuid.uuid4().hex[:10]}"),
        source=AlertSource.PAGERDUTY,
        title=data.get("title", "PagerDuty incident"),
        description=data.get("description", data.get("title", "")),
        severity_hint=_PAGERDUTY_URGENCY.get(data.get("urgency", "")),
        resource=resource,
        fired_at=_parse_ts(event.get("occurred_at")),
        raw=payload,
    )


def normalize_servicenow(payload: Dict[str, Any]) -> IncidentAlert:
    """ServiceNow incident record -> IncidentAlert."""
    urgency = str(payload.get("urgency", "3"))
    severity = {"1": Severity.SEV1, "2": Severity.SEV2}.get(urgency, Severity.SEV3)

    app_code = payload.get("u_app_code")
    resource = ResourceRef(
        service_name=payload.get("cmdb_ci", "unknown"),
        environment=_environment_from(payload.get("cmdb_ci", "")),
        **({"app_code": app_code} if app_code else {}),
    )
    _apply_app_code_fallback(resource)

    return IncidentAlert(
        alert_id=payload.get("number", f"snow-{uuid.uuid4().hex[:10]}"),
        source=AlertSource.SERVICENOW,
        title=payload.get("short_description", "ServiceNow incident"),
        description=payload.get("description", ""),
        severity_hint=severity,
        resource=resource,
        fired_at=_parse_ts(payload.get("opened_at")),
        raw=payload,
    )


def normalize_custom(payload: Dict[str, Any]) -> IncidentAlert:
    """Already-shaped IncidentAlert payloads (custom publishers)."""
    alert = IncidentAlert.model_validate(payload)
    _apply_app_code_fallback(alert.resource)
    return alert


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
        app_code=alert.resource.app_code,
    )
