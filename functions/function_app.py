"""
Azure Functions for Support Agent.

Service Bus trigger to process incoming job failure incidents.
"""
import json
import logging
import os
from datetime import datetime

import azure.functions as func
import httpx

app = func.FunctionApp()

# Configuration
SUPPORT_AGENT_URL = os.getenv("SUPPORT_AGENT_URL", "https://app-support-agent-dev.azurewebsites.net")
SUPPORT_AGENT_API_KEY = os.getenv("SUPPORT_AGENT_API_KEY", "")


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="job-failures",
    connection="SERVICEBUS_CONNECTION"
)
async def process_job_failure(msg: func.ServiceBusMessage) -> None:
    """
    Process job failure events from Service Bus queue.

    Triggered when a new message arrives in the 'job-failures' queue.
    Forwards the incident to the Support Agent API for processing.
    """
    try:
        # Parse message
        message_body = msg.get_body().decode('utf-8')
        incident_data = json.loads(message_body)

        logging.info(f"Processing incident: {incident_data.get('job_name', 'unknown')}")

        # Validate required fields
        required_fields = ["job_name", "job_type", "error_message"]
        missing = [f for f in required_fields if f not in incident_data]
        if missing:
            logging.error(f"Missing required fields: {missing}")
            # Don't retry - message is malformed
            return

        # Add metadata from Service Bus message
        incident_data["source_message_id"] = msg.message_id
        incident_data["enqueued_time"] = msg.enqueued_time_utc.isoformat() if msg.enqueued_time_utc else None

        # Set defaults
        if "source_system" not in incident_data:
            incident_data["source_system"] = "service-bus"
        if "environment" not in incident_data:
            incident_data["environment"] = os.getenv("ENVIRONMENT", "dev")

        # Forward to Support Agent API
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{SUPPORT_AGENT_URL}/api/v1/incidents",
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": SUPPORT_AGENT_API_KEY,
                    "X-Source": "azure-function",
                    "X-Message-ID": msg.message_id or ""
                },
                json=incident_data
            )

            if response.status_code == 200:
                result = response.json()
                logging.info(
                    f"Incident created successfully: {result.get('incident_id')} "
                    f"for job {incident_data['job_name']}"
                )
            elif response.status_code == 429:
                # Rate limited - let Service Bus retry
                logging.warning("Rate limited by Support Agent API, will retry")
                raise Exception("Rate limited - retry")
            else:
                logging.error(
                    f"Failed to create incident: {response.status_code} - {response.text}"
                )
                # For 4xx errors (except 429), don't retry
                if 400 <= response.status_code < 500:
                    return
                # For 5xx, raise to trigger retry
                raise Exception(f"API error: {response.status_code}")

    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in message: {e}")
        # Don't retry malformed messages
        return

    except httpx.TimeoutException:
        logging.error("Timeout calling Support Agent API")
        raise  # Retry

    except Exception as e:
        logging.error(f"Error processing incident: {e}")
        raise  # Retry


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="job-failures-deadletter",
    connection="SERVICEBUS_CONNECTION"
)
async def process_deadletter(msg: func.ServiceBusMessage) -> None:
    """
    Process dead-lettered messages for alerting/logging.

    Messages end up here after max delivery attempts.
    """
    try:
        message_body = msg.get_body().decode('utf-8')
        incident_data = json.loads(message_body)

        logging.error(
            f"Dead-lettered incident: job={incident_data.get('job_name', 'unknown')}, "
            f"reason={msg.dead_letter_reason}, "
            f"error={msg.dead_letter_error_description}"
        )

        # TODO: Send alert to ops team
        # await send_alert(
        #     title="Failed to process incident",
        #     details=incident_data,
        #     reason=msg.dead_letter_reason
        # )

    except Exception as e:
        logging.error(f"Error processing dead-letter message: {e}")


@app.route(route="health", methods=["GET"])
async def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint for the function app."""
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "support_agent_url": SUPPORT_AGENT_URL
        }),
        mimetype="application/json"
    )
