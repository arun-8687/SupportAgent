"""
Azure Functions entry point for the Support Agent.

Handles:
- Service Bus trigger for incoming incidents
- HTTP endpoints for API access
- Timer trigger for scheduled tasks
"""
import json
import logging
from datetime import datetime

import azure.functions as func

from src.services.workflow_service import WorkflowService

# Initialize the function app
app = func.FunctionApp()

# Get workflow service (singleton)
_workflow_service = None


def get_workflow_service() -> WorkflowService:
    """Get or create the workflow service."""
    global _workflow_service
    if _workflow_service is None:
        _workflow_service = WorkflowService()
    return _workflow_service


# =============================================================================
# Service Bus Trigger - Incident Intake
# =============================================================================

@app.function_name("ProcessIncident")
@app.service_bus_queue_trigger(
    arg_name="message",
    queue_name="job-failures",
    connection="SERVICEBUS_CONNECTION_STRING"
)
async def process_incident(message: func.ServiceBusMessage) -> None:
    """
    Process incoming incident from Service Bus.

    Triggered when a new job failure event is published.
    """
    logging.info(f"Processing incident: {message.message_id}")

    try:
        # Parse the message
        body = message.get_body().decode("utf-8")
        incident_data = json.loads(body)

        logging.info(
            f"Incident received: job={incident_data.get('job_name')}, "
            f"type={incident_data.get('job_type')}"
        )

        # Process through workflow
        service = get_workflow_service()
        result = await service.process_incident(incident_data)

        logging.info(
            f"Incident processed: {result.get('incident_id')}, "
            f"status={result.get('workflow_stage')}"
        )

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse incident message: {e}")
        raise

    except Exception as e:
        logging.error(f"Error processing incident: {e}", exc_info=True)
        raise


# =============================================================================
# HTTP Endpoints
# =============================================================================

@app.function_name("GetIncidentStatus")
@app.route(route="incidents/{incident_id}", methods=["GET"])
async def get_incident_status(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get status of an incident.

    GET /api/incidents/{incident_id}
    """
    incident_id = req.route_params.get("incident_id")

    if not incident_id:
        return func.HttpResponse(
            json.dumps({"error": "incident_id is required"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        service = get_workflow_service()
        status = await service.get_incident_status(incident_id)

        if status is None:
            return func.HttpResponse(
                json.dumps({"error": "Incident not found"}),
                status_code=404,
                mimetype="application/json"
            )

        return func.HttpResponse(
            json.dumps(status, default=str),
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error getting incident status: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"error": "An internal server error occurred"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name("ApproveRemediation")
@app.route(route="incidents/{incident_id}/approve", methods=["POST"])
async def approve_remediation(req: func.HttpRequest) -> func.HttpResponse:
    """
    Approve or reject a remediation proposal.

    POST /api/incidents/{incident_id}/approve
    Body: {"approved": true/false, "reason": "...", "approver_id": "..."}
    """
    incident_id = req.route_params.get("incident_id")

    if not incident_id:
        return func.HttpResponse(
            json.dumps({"error": "incident_id is required"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )

    approved = body.get("approved", False)
    reason = body.get("reason", "")
    approver_id = body.get("approver_id", "unknown")

    try:
        service = get_workflow_service()
        result = await service.submit_approval(
            incident_id=incident_id,
            approved=approved,
            approver_id=approver_id,
            reason=reason
        )

        return func.HttpResponse(
            json.dumps(result, default=str),
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error submitting approval: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"error": "An internal server error occurred"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name("SubmitIncident")
@app.route(route="incidents", methods=["POST"])
async def submit_incident(req: func.HttpRequest) -> func.HttpResponse:
    """
    Submit a new incident via HTTP (alternative to Service Bus).

    POST /api/incidents
    Body: JobFailureEvent schema
    """
    try:
        incident_data = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json"
        )

    # Validate required fields
    required = ["job_name", "job_type", "error_message"]
    missing = [f for f in required if f not in incident_data]
    if missing:
        return func.HttpResponse(
            json.dumps({"error": f"Missing required fields: {missing}"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        service = get_workflow_service()
        result = await service.process_incident(incident_data)

        return func.HttpResponse(
            json.dumps({
                "incident_id": result.get("incident_id"),
                "status": result.get("workflow_stage"),
                "message": "Incident submitted successfully"
            }, default=str),
            status_code=201,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error submitting incident: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"error": "An internal server error occurred"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name("ListPendingApprovals")
@app.route(route="approvals/pending", methods=["GET"])
async def list_pending_approvals(req: func.HttpRequest) -> func.HttpResponse:
    """
    List incidents awaiting approval.

    GET /api/approvals/pending
    """
    try:
        service = get_workflow_service()
        pending = await service.get_pending_approvals()

        return func.HttpResponse(
            json.dumps(pending, default=str),
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error listing pending approvals: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"error": "An internal server error occurred"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name("GetMetrics")
@app.route(route="metrics", methods=["GET"])
async def get_metrics(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get support agent metrics.

    GET /api/metrics
    """
    try:
        service = get_workflow_service()
        metrics = await service.get_metrics()

        return func.HttpResponse(
            json.dumps(metrics, default=str),
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error getting metrics: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"error": "An internal server error occurred"}),
            status_code=500,
            mimetype="application/json"
        )


# =============================================================================
# Health Check
# =============================================================================

@app.function_name("HealthCheck")
@app.route(route="health", methods=["GET"])
async def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """
    Health check endpoint.

    GET /api/health
    """
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0"
        }),
        mimetype="application/json"
    )
