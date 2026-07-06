"""
Telemetry: structured step logging and tracing to Azure Application Insights.

Every workflow node, tool execution, and service-level event emits a
structured "step" log record carrying incident_id, step name, outcome, and
duration — so one App Insights query reconstructs an incident's entire
timeline:

    traces
    | where customDimensions.incident_id == "sre-..."
    | project timestamp, customDimensions.step, customDimensions.status,
              customDimensions.duration_ms
    | order by timestamp asc

Export path: when APPLICATIONINSIGHTS_CONNECTION_STRING is set and
azure-monitor-opentelemetry is installed, configure_telemetry() wires the
OpenTelemetry log/trace exporters (logs land as App Insights `traces`,
spans as `dependencies`). Without either, everything degrades to plain
stdlib logging — offline dev and tests need no Azure.
"""
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("sre_agent.telemetry")

_configured: Optional[bool] = None

# Extra durable sinks for step records (e.g. the monitoring-UI step-event
# writer). Empty by default, so non-UI deploys and tests are unaffected and
# the hot path reads no settings — it only checks this list.
_sinks: List[Callable[[Dict[str, Any]], None]] = []


def register_step_sink(sink: Callable[[Dict[str, Any]], None]) -> None:
    """Register a durable sink to receive every step record (best-effort)."""
    if sink not in _sinks:
        _sinks.append(sink)


def unregister_step_sink(sink: Callable[[Dict[str, Any]], None]) -> None:
    if sink in _sinks:
        _sinks.remove(sink)


def clear_step_sinks() -> None:
    _sinks.clear()


def configure_telemetry() -> bool:
    """Wire the Azure Monitor OpenTelemetry exporters (idempotent).

    Returns True when telemetry exports to App Insights, False when only
    local logging is active. Called from every entry point (service
    construction, listener, Functions app), so triggers can't forget it.
    """
    global _configured
    if _configured is not None:
        return _configured

    connection_string = os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING")
    if not connection_string:
        _configured = False
        logger.debug("App Insights not configured; telemetry is local-only")
        return False

    try:
        from azure.monitor.opentelemetry import configure_azure_monitor

        # logger_name scopes the log exporter to the sre_agent.* hierarchy,
        # so every module logger in this package exports automatically.
        configure_azure_monitor(
            connection_string=connection_string,
            logger_name="sre_agent",
        )
        _configured = True
        logger.info("Telemetry exporting to Azure Application Insights")
    except ImportError:
        _configured = False
        logger.warning(
            "APPLICATIONINSIGHTS_CONNECTION_STRING is set but "
            "azure-monitor-opentelemetry is not installed; telemetry is "
            "local-only (pip install azure-monitor-opentelemetry)."
        )
    except Exception:
        _configured = False
        logger.exception("Failed to configure Azure Monitor telemetry")
    return _configured


def reset_for_tests() -> None:
    """Allow tests to re-run configuration."""
    global _configured
    _configured = None


@contextmanager
def span(name: str, **attributes: Any):
    """OpenTelemetry span when the SDK is present; no-op otherwise."""
    try:
        from opentelemetry import trace
    except ImportError:
        yield None
        return
    tracer = trace.get_tracer("sre_agent")
    with tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        yield current


def log_step(
    step: str,
    status: str,
    incident_id: Optional[str] = None,
    duration_ms: Optional[int] = None,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit one structured step record.

    The flat keyword fields ride on the LogRecord (via `extra`), which the
    Azure Monitor log exporter surfaces as customDimensions; the formatted
    message keeps local logs readable.
    """
    dimensions: Dict[str, Any] = {
        "step": step,
        "status": status,
        "incident_id": incident_id or "",
    }
    if duration_ms is not None:
        dimensions["duration_ms"] = duration_ms
    for key, value in fields.items():
        if value is not None:
            dimensions[key] = str(value)

    logger.log(
        level,
        "step=%s status=%s incident=%s duration_ms=%s %s",
        step,
        status,
        incident_id or "-",
        duration_ms if duration_ms is not None else "-",
        " ".join(f"{k}={v}" for k, v in fields.items() if v is not None),
        extra=dimensions,
    )

    # Durable sinks (monitoring UI). Best-effort and non-blocking: a sink
    # only enqueues; it must never raise into the hot path.
    if _sinks:
        record = {
            "step": step,
            "status": status,
            "incident_id": incident_id or "",
            "duration_ms": duration_ms,
            "ts": time.time(),
            "fields": {k: v for k, v in fields.items() if v is not None},
        }
        for sink in _sinks:
            try:
                sink(record)
            except Exception:  # pragma: no cover - defensive
                pass
