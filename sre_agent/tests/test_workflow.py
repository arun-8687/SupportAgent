"""End-to-end workflow tests (offline: heuristic analysis, dry-run skills)."""
import pytest


@pytest.mark.unit
async def test_prod_incident_pauses_for_approval(service, azure_monitor_alert):
    """Prod alerts must stop at the permission gate for human sign-off."""
    result = await service.handle_alert(azure_monitor_alert)

    assert result["status"] == "awaiting_approval"
    request = result["approval_request"]
    assert request["type"] == "approval_request"
    assert request["actions"], "expected at least one gated action"
    assert request["root_cause"]


@pytest.mark.unit
async def test_approval_resumes_to_resolution(
    service, azure_monitor_alert, knowledge_store, agent_memory
):
    """Approving the plan executes (dry-run), verifies, resolves, and captures knowledge."""
    paused = await service.handle_alert(azure_monitor_alert)
    incident_id = paused["incident_id"]

    final = await service.submit_approval(
        incident_id=incident_id, approved=True, approver="oncall@example.com"
    )

    assert final["status"] == "resolved"
    assert final["root_cause"]
    assert final["ticket_id"]
    assert final["knowledge_record_id"]

    records = knowledge_store.load_all()
    assert len(records) == 1
    assert records[0].outcome == "resolved"
    assert records[0].incident_id == incident_id

    # Session insight captured with markdown knowledge files updated.
    insights = agent_memory.load_insights()
    assert len(insights) == 1
    assert insights[0].incident_id == incident_id
    assert insights[0].root_cause
    topic = agent_memory.synthesized.read_topic("debugging payment-service")
    assert insights[0].root_cause[:40] in topic
    # overview.md exists and links the topic file.
    assert "debugging-payment-service.md" in (
        agent_memory.synthesized.directory / "overview.md"
    ).read_text()


@pytest.mark.unit
async def test_rejection_escalates(service, azure_monitor_alert):
    """Rejecting the plan escalates to a human instead of executing."""
    paused = await service.handle_alert(azure_monitor_alert)

    final = await service.submit_approval(
        incident_id=paused["incident_id"],
        approved=False,
        approver="oncall@example.com",
        reason="Do not restart during batch window",
    )

    assert final["status"] == "escalated"
    assert "Escalated" in final["resolution_summary"]


@pytest.mark.unit
async def test_pagerduty_alert_normalized_and_investigated(service, pagerduty_alert):
    """A PagerDuty webhook payload flows through the same graph."""
    result = await service.handle_alert(pagerduty_alert)

    # prod service -> requires approval
    assert result["status"] == "awaiting_approval"


@pytest.mark.unit
async def test_test_alert_suppressed(service):
    """Alerts marked [TEST] are suppressed at triage without investigation."""
    result = await service.handle_alert(
        {
            "alert_id": "test-001",
            "source": "custom",
            "title": "[TEST] synthetic validation alert",
            "description": "ignore me",
        },
        source_hint="custom",
    )
    assert result["status"] == "suppressed"


@pytest.mark.unit
async def test_knowledge_reused_on_second_incident(service, azure_monitor_alert, knowledge_store):
    """Second similar incident finds the first one in institutional knowledge."""
    paused = await service.handle_alert(azure_monitor_alert)
    await service.submit_approval(paused["incident_id"], approved=True, approver="x")

    matches = knowledge_store.search(
        "payment-service memory usage critical", service_name="payment-service"
    )
    assert matches, "expected the resolved incident to be retrievable"
    assert matches[0].similarity > 0
