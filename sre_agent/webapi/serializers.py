"""
Serialize workflow state and store rows into JSON-safe API payloads.

The detail endpoint sits behind auth, but must still not leak the raw alert
payload (`incident.alert.raw` can carry provider secrets/tokens) or ship
unbounded evidence blobs. `serialize_state` walks the checkpointer's state,
dumps each pydantic value with `model_dump(mode="json")`, redacts the raw
payload, and caps large text fields.
"""
from typing import Any, Dict, List

from pydantic import BaseModel

from sre_agent.incident_index import IncidentIndexRow
from sre_agent.step_events import StepEvent

# Evidence/log text longer than this is truncated with a marker — the detail
# view summarizes; the full artifact lives in App Insights / the ticket.
MAX_TEXT_CHARS = 8000
_REDACTED = "[redacted]"


def _dump(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_dump(v) for v in value]
    if isinstance(value, dict):
        return {k: _dump(v) for k, v in value.items()}
    return value


def _cap_text(obj: Any) -> Any:
    """Recursively truncate oversized strings so one blob can't bloat a page."""
    if isinstance(obj, str) and len(obj) > MAX_TEXT_CHARS:
        return obj[:MAX_TEXT_CHARS] + f"… [truncated {len(obj) - MAX_TEXT_CHARS} chars]"
    if isinstance(obj, list):
        return [_cap_text(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _cap_text(v) for k, v in obj.items()}
    return obj


def serialize_state(values: Dict[str, Any]) -> Dict[str, Any]:
    """Redact + JSON-serialize a checkpointer state dict for the detail view."""
    out: Dict[str, Any] = {}
    for key, value in values.items():
        if key.startswith("__"):  # LangGraph internals (__interrupt__, etc.)
            continue
        out[key] = _dump(value)

    # Redact the raw provider payload; keep normalized signals/thresholds.
    incident = out.get("incident")
    if isinstance(incident, dict):
        alert = incident.get("alert")
        if isinstance(alert, dict) and alert.get("raw"):
            alert["raw"] = _REDACTED
    return _cap_text(out)


def serialize_index_row(row: IncidentIndexRow) -> Dict[str, Any]:
    return row.to_json()


def serialize_step_event(event: StepEvent) -> Dict[str, Any]:
    return event.to_json()


def serialize_timeline(events: List[StepEvent]) -> List[Dict[str, Any]]:
    return [serialize_step_event(e) for e in events]
