"""
Azure Functions trigger surface (serverless alternative to the listener).

- Service Bus TOPIC trigger: alerts published to the incidents topic start
  investigations automatically (idempotent — redeliveries are deduped).
- HTTP endpoints: approve/reject paused mitigations and inspect status.
  The approver identity comes from App Service Authentication's
  X-MS-CLIENT-PRINCIPAL header (Entra), never from the request body —
  approving a production mitigation is a privileged action.
- Timer trigger: sweeps approvals past their timeout (escalates them) and
  prunes old checkpoints.

Production requirements (enforced at startup by create_checkpointer):
- SRE_AGENT_DATABASE_URL (Postgres) so approvals resume on any instance.
- SRE_AGENT_DATA_DIR on durable shared storage (Azure Files mount) so
  knowledge/memory files survive instance recycling.
- host.json: see sre_agent/deploy/host.json for the Service Bus lock
  renewal, concurrency, and timeout settings this workload needs.
"""
import json
import logging

import azure.functions as func

from sre_agent.config import get_settings
from sre_agent.observability import configure_telemetry
from sre_agent.security import parse_client_principal
from sre_agent.service import SREAgentService

configure_telemetry()  # export step logs/spans to App Insights from startup

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
    try:
        payload = json.loads(message.get_body().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Unparseable payloads can never succeed; log and swallow so the
        # host completes the message instead of redelivering to max count.
        logging.error("Poison message %s: unparseable body", message.message_id)
        return

    props = message.application_properties or {}
    source_hint = str(props.get("source", ""))

    service = get_service()
    if str(props.get("event_type", "alert")) == "approval":
        result = await service.submit_approval(
            incident_id=str(payload["incident_id"]),
            approved=bool(payload.get("approved", False)),
            approver=str(payload.get("approver", "service-bus")),
            reason=str(payload.get("reason", "")),
            channel="service_bus",
            # Publishing rights to the topic are the credential here;
            # restrict senders with Service Bus RBAC.
            approver_verified=True,
        )
    else:
        result = await service.handle_alert(payload, source_hint=source_hint)
    logging.info("SRE agent processed message %s: %s", message.message_id, result)


@app.function_name("ApproveMitigation")
@app.route(route="incidents/{incident_id}/approval", methods=["POST"])
async def approve_mitigation(req: func.HttpRequest) -> func.HttpResponse:
    """POST {"approved": true, "reason": "..."}

    The approver is the Entra principal from Easy Auth — a body-supplied
    approver name is only honored in non-production environments.
    """
    incident_id = req.route_params.get("incident_id", "")
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "invalid JSON body"}),
            status_code=400, mimetype="application/json",
        )

    principal = parse_client_principal(req.headers.get("x-ms-client-principal"))
    settings = get_settings()
    if principal is None and settings.verified_identity_required:
        return func.HttpResponse(
            json.dumps(
                {
                    "error": (
                        "Verified identity required. Enable App Service "
                        "Authentication (Entra) on this Function App; the "
                        "X-MS-CLIENT-PRINCIPAL header is missing."
                    )
                }
            ),
            status_code=401, mimetype="application/json",
        )

    approver = (
        principal["identity"]
        if principal
        else f"unverified:{body.get('approver', 'unknown')}"
    )
    result = await get_service().submit_approval(
        incident_id=incident_id,
        approved=bool(body.get("approved", False)),
        approver=approver,
        reason=str(body.get("reason", "")),
        channel="http",
        approver_verified=principal is not None,
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


@app.function_name("ApprovalSweep")
@app.timer_trigger(arg_name="timer", schedule="0 */5 * * * *")  # every 5 min
async def approval_sweep(timer: func.TimerRequest) -> None:
    """Escalate timed-out approvals; prune old checkpoints hourly-ish."""
    service = get_service()
    escalated = await service.sweep_expired_approvals()
    if escalated:
        logging.warning("Sweeper escalated %d timed-out approvals", len(escalated))

    recovered = await service.recover_stalled_intakes()
    if recovered:
        logging.warning("Sweeper recovered %d stalled intakes", len(recovered))

    from sre_agent.maintenance import prune_checkpoints

    pruned = prune_checkpoints()
    if pruned:
        logging.info("Pruned %d expired checkpoint rows", pruned)
