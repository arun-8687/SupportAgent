"""
Azure Functions trigger surface (serverless alternative to the listener).

- Service Bus TOPIC trigger: alerts published to the incidents topic start
  investigations automatically.
- HTTP endpoints: approve/reject paused mitigations and inspect status —
  the "single action approval" the on-call engineer takes from the ticket.

Note: for approvals to resume across function instances, configure a
Postgres checkpointer (SRE_AGENT_DATABASE_URL); MemorySaver only works
within one long-lived instance.
"""
import json
import logging

import azure.functions as func

from sre_agent.service import SREAgentService

app = func.FunctionApp()

_service: SREAgentService | None = None


def get_service() -> SREAgentService:
    global _service
    if _service is None:
        _service = SREAgentService()
    return _service


@app.function_name("OnIncidentAlert")
@app.service_bus_topic_trigger(
    arg_name="message",
    topic_name="%SRE_AGENT_SERVICEBUS_TOPIC%",
    subscription_name="%SRE_AGENT_SERVICEBUS_SUBSCRIPTION%",
    connection="SRE_AGENT_SERVICEBUS_CONNECTION_STRING",
)
async def on_incident_alert(message: func.ServiceBusMessage) -> None:
    """Investigation kicks off the moment an alert lands on the topic."""
    payload = json.loads(message.get_body().decode("utf-8"))
    props = message.application_properties or {}
    source_hint = str(props.get("source", ""))

    service = get_service()
    if str(props.get("event_type", "alert")) == "approval":
        result = await service.submit_approval(
            incident_id=payload["incident_id"],
            approved=bool(payload.get("approved", False)),
            approver=str(payload.get("approver", "service-bus")),
            reason=str(payload.get("reason", "")),
            channel="service_bus",
        )
    else:
        result = await service.handle_alert(payload, source_hint=source_hint)
    logging.info("SRE agent processed message %s: %s", message.message_id, result)


@app.function_name("ApproveMitigation")
@app.route(route="incidents/{incident_id}/approval", methods=["POST"])
async def approve_mitigation(req: func.HttpRequest) -> func.HttpResponse:
    """POST {"approved": true, "approver": "...", "reason": "..."}"""
    incident_id = req.route_params.get("incident_id", "")
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "invalid JSON body"}),
            status_code=400, mimetype="application/json",
        )

    result = await get_service().submit_approval(
        incident_id=incident_id,
        approved=bool(body.get("approved", False)),
        approver=str(body.get("approver", "unknown")),
        reason=str(body.get("reason", "")),
        channel="http",
    )
    return func.HttpResponse(
        json.dumps(result, default=str), mimetype="application/json"
    )


@app.function_name("IncidentStatus")
@app.route(route="incidents/{incident_id}", methods=["GET"])
async def incident_status(req: func.HttpRequest) -> func.HttpResponse:
    incident_id = req.route_params.get("incident_id", "")
    status = await get_service().get_status(incident_id)
    if status is None:
        return func.HttpResponse(
            json.dumps({"error": "incident not found"}),
            status_code=404, mimetype="application/json",
        )
    return func.HttpResponse(
        json.dumps(status, default=str), mimetype="application/json"
    )
