"""Telemetry tests: per-step logging with incident correlation."""
import logging

import pytest

from sre_agent import observability
from sre_agent.observability import configure_telemetry, log_step, span


@pytest.fixture(autouse=True)
def reset_telemetry():
    observability.reset_for_tests()
    yield
    observability.reset_for_tests()


@pytest.mark.unit
def test_configure_telemetry_local_only_without_connection_string(monkeypatch):
    monkeypatch.delenv("APPLICATIONINSIGHTS_CONNECTION_STRING", raising=False)
    assert configure_telemetry() is False
    # Idempotent second call.
    assert configure_telemetry() is False


@pytest.mark.unit
def test_configure_telemetry_degrades_without_sdk(monkeypatch):
    """Connection string set but exporter package missing -> local-only."""
    monkeypatch.setenv(
        "APPLICATIONINSIGHTS_CONNECTION_STRING",
        "InstrumentationKey=00000000-0000-0000-0000-000000000000",
    )
    # azure-monitor-opentelemetry is not installed in the test env.
    assert configure_telemetry() is False


@pytest.mark.unit
def test_log_step_carries_custom_dimensions(caplog):
    with caplog.at_level(logging.INFO, logger="sre_agent.telemetry"):
        log_step(
            "triage", "completed", "sre-123",
            duration_ms=42, service_name="payment-service",
        )
    record = caplog.records[-1]
    # Fields ride on the LogRecord -> exported as customDimensions.
    assert record.step == "triage"
    assert record.status == "completed"
    assert record.incident_id == "sre-123"
    assert record.duration_ms == 42
    assert record.service_name == "payment-service"
    assert "step=triage" in record.getMessage()


@pytest.mark.unit
def test_span_is_noop_without_opentelemetry():
    with span("sre_agent.node.triage", node="triage") as current:
        pass  # must not raise regardless of SDK availability


@pytest.mark.unit
async def test_every_workflow_step_emits_telemetry(
    service, azure_monitor_alert, caplog
):
    """One incident produces a correlated step trail across all nodes."""
    with caplog.at_level(logging.INFO, logger="sre_agent.telemetry"):
        paused = await service.handle_alert(azure_monitor_alert)
        incident_id = paused["incident_id"]
        await service.submit_approval(incident_id, approved=True, approver="x")

    steps = {
        record.step: record.status
        for record in caplog.records
        if getattr(record, "incident_id", "") == incident_id
    }
    # Intake + every node the incident touched, plus approval events.
    assert steps.get("alert_intake") == "accepted"
    for node in (
        "intake", "triage", "plan_investigation", "run_subagent",
        "analyze_root_cause", "propose_mitigation", "open_ticket",
        "permission_gate", "execute_mitigation", "verify", "resolve",
    ):
        assert steps.get(node) == "completed", f"missing step log for {node}"
    assert steps.get("await_approval") in ("paused", "completed")
    assert steps.get("approval_request") == "pending"
    assert steps.get("approval_decision") == "approved"

    # Node records carry durations for App Insights charts.
    node_records = [
        r for r in caplog.records
        if getattr(r, "step", "") == "triage"
        and getattr(r, "incident_id", "") == incident_id
    ]
    assert node_records and hasattr(node_records[0], "duration_ms")


@pytest.mark.unit
async def test_duplicate_and_tool_steps_are_logged(
    service, azure_monitor_alert, caplog
):
    with caplog.at_level(logging.INFO, logger="sre_agent.telemetry"):
        paused = await service.handle_alert(azure_monitor_alert)
        await service.handle_alert(azure_monitor_alert)  # redelivery
        await service.submit_approval(
            paused["incident_id"], approved=True, approver="x"
        )

    statuses = [
        (r.step, r.status) for r in caplog.records if hasattr(r, "step")
    ]
    assert ("alert_intake", "duplicate") in statuses
    assert ("skill_tool_execution", "succeeded") in statuses

    # Tool executions are correlated to the incident like every other step.
    tool_records = [
        r for r in caplog.records
        if getattr(r, "step", "") == "skill_tool_execution"
    ]
    assert tool_records
    assert all(
        r.incident_id == paused["incident_id"] for r in tool_records
    )
