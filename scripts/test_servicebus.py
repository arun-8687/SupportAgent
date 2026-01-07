"""
Test Service Bus incident intake.

Sends a test incident to the Service Bus queue to verify:
1. Message is delivered to queue
2. Azure Function triggers
3. Incident is created in Support Agent

Run with:
    export SERVICEBUS_CONNECTION_STRING="Endpoint=sb://..."
    python scripts/test_servicebus.py
"""
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from uuid import uuid4


async def send_test_incident():
    """Send test incident via Service Bus."""
    try:
        from azure.servicebus.aio import ServiceBusClient
        from azure.servicebus import ServiceBusMessage
    except ImportError:
        print("ERROR: azure-servicebus not installed")
        print("Run: pip install azure-servicebus")
        sys.exit(1)

    connection_string = os.getenv("SERVICEBUS_CONNECTION_STRING")
    if not connection_string:
        print("ERROR: SERVICEBUS_CONNECTION_STRING not set")
        sys.exit(1)

    queue_name = os.getenv("SERVICEBUS_QUEUE", "job-failures")

    # Create test incident
    incident = {
        "event_id": f"test-{uuid4().hex[:8]}",
        "job_name": f"servicebus-test-job-{int(time.time())}",
        "job_type": "databricks",
        "source_system": "servicebus-test",
        "environment": os.getenv("ENVIRONMENT", "dev"),
        "error_message": "java.lang.OutOfMemoryError: Java heap space",
        "error_code": "OOM_ERROR",
        "stack_trace": """
            java.lang.OutOfMemoryError: Java heap space
                at org.apache.spark.sql.execution.WholeStageCodegenExec.doExecute
                at org.apache.spark.sql.execution.SparkPlan.execute
        """,
        "cluster_id": "test-cluster-123",
        "job_run_id": f"run-{int(time.time())}",
        "failure_timestamp": datetime.utcnow().isoformat(),
        "owner_team": "test-team",
        "priority_hint": "P3"
    }

    print("=" * 60)
    print("Service Bus Integration Test")
    print("=" * 60)
    print(f"\nQueue: {queue_name}")
    print(f"Event ID: {incident['event_id']}")
    print(f"Job Name: {incident['job_name']}")

    async with ServiceBusClient.from_connection_string(connection_string) as client:
        async with client.get_queue_sender(queue_name) as sender:
            message = ServiceBusMessage(
                body=json.dumps(incident),
                content_type="application/json",
                subject=f"job-failure:{incident['job_name']}",
                message_id=incident["event_id"]
            )

            await sender.send_messages(message)
            print(f"\n✓ Message sent to queue: {queue_name}")

    print("\nNext steps:")
    print("  1. Check Azure Function logs for trigger")
    print("  2. Verify incident created in Support Agent API")
    print(f"  3. Search for job: {incident['job_name']}")
    print("\nTo view function logs:")
    print("  az functionapp log tail --name func-support-agent-dev --resource-group rg-support-agent")


async def check_queue_status():
    """Check Service Bus queue status."""
    try:
        from azure.servicebus.aio import ServiceBusClient
    except ImportError:
        return

    connection_string = os.getenv("SERVICEBUS_CONNECTION_STRING")
    if not connection_string:
        return

    queue_name = os.getenv("SERVICEBUS_QUEUE", "job-failures")

    print("\n" + "-" * 60)
    print("Queue Status")
    print("-" * 60)

    async with ServiceBusClient.from_connection_string(connection_string) as client:
        # Get queue runtime properties
        try:
            from azure.servicebus.management.aio import ServiceBusAdministrationClient

            # Parse namespace from connection string
            parts = dict(p.split("=", 1) for p in connection_string.split(";") if "=" in p)
            namespace = parts.get("Endpoint", "").replace("sb://", "").replace("/", "")

            async with ServiceBusAdministrationClient.from_connection_string(connection_string) as admin:
                props = await admin.get_queue_runtime_properties(queue_name)
                print(f"  Active messages: {props.active_message_count}")
                print(f"  Dead-letter messages: {props.dead_letter_message_count}")
                print(f"  Scheduled messages: {props.scheduled_message_count}")
        except Exception as e:
            print(f"  Could not get queue properties: {e}")


if __name__ == "__main__":
    print("Starting Service Bus test...\n")
    asyncio.run(send_test_incident())
    asyncio.run(check_queue_status())
