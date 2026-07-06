"""The service maintains the incident index at its intake/approval chokepoints."""
import pytest


@pytest.mark.integration
async def test_intake_creates_descriptive_index_row(service, incident_index, azure_monitor_alert):
    result = await service.handle_alert(azure_monitor_alert)
    incident_id = result["incident_id"]

    row = incident_index.get(incident_id)
    assert row is not None
    assert row.service_name and row.service_name != "unknown"
    assert row.severity and row.title
    assert row.created_at > 0 and row.updated_at >= row.created_at


@pytest.mark.integration
async def test_pause_marks_awaiting_approval(service, incident_index, azure_monitor_alert):
    paused = await service.handle_alert(azure_monitor_alert)
    assert paused["status"] == "awaiting_approval"

    row = incident_index.get(paused["incident_id"])
    assert row.status == "awaiting_approval"
    assert row.awaiting_approval is True


@pytest.mark.integration
async def test_approval_clears_flag_and_records_terminal_state(
    service, incident_index, azure_monitor_alert
):
    paused = await service.handle_alert(azure_monitor_alert)
    incident_id = paused["incident_id"]
    final = await service.submit_approval(incident_id, approved=True, approver="op")

    row = incident_index.get(incident_id)
    assert row.awaiting_approval is False
    assert row.status == final["status"]  # e.g. "resolved"
    assert row.ticket_id == final["ticket_id"]
    assert row.resolution_summary == final["resolution_summary"]


@pytest.mark.integration
async def test_index_lists_the_incident(service, incident_index, azure_monitor_alert):
    await service.handle_alert(azure_monitor_alert)
    rows, total = incident_index.list()
    assert total == 1
    assert len(rows) == 1
