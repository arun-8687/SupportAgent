#!/usr/bin/env python
"""
Send a test incident to the Support Agent API.

Usage:
    python scripts/send_test_incident.py [--api-url URL] [--scenario SCENARIO]

Scenarios:
    oom          - OutOfMemoryError (common)
    connection   - Connection timeout (transient)
    data         - Data quality error
    config       - Configuration error
    unknown      - Unknown error (escalation test)
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import requests

# Test scenarios
SCENARIOS = {
    "oom": {
        "job_name": "etl-customer-data-daily",
        "job_type": "databricks",
        "source_system": "Azure-EastUS",
        "environment": "prod",
        "error_message": "org.apache.spark.SparkException: Job aborted due to stage failure: Task 15 in stage 23.0 failed 4 times, most recent failure: Lost task 15.3 in stage 23.0: ExecutorLostFailure (executor 5 exited caused by OutOfMemoryError: Java heap space)",
        "error_code": "SPARK_OOM",
        "stack_trace": """
org.apache.spark.SparkException: Job aborted due to stage failure
    at org.apache.spark.scheduler.DAGScheduler.failJobAndIndependentStages(DAGScheduler.scala:2454)
    at org.apache.spark.scheduler.DAGScheduler.$anonfun$abortStage$2(DAGScheduler.scala:2403)
Caused by: java.lang.OutOfMemoryError: Java heap space
    at java.util.Arrays.copyOf(Arrays.java:3236)
    at org.apache.spark.sql.execution.joins.HashedRelation$.apply(HashedRelation.scala:178)
        """,
        "cluster_id": "1234-567890-abc123",
        "priority_hint": "P2"
    },
    "connection": {
        "job_name": "sync-azure-sql-warehouse",
        "job_type": "databricks",
        "source_system": "Azure-WestUS",
        "environment": "prod",
        "error_message": "com.microsoft.sqlserver.jdbc.SQLServerException: Connection reset by peer. ClientConnectionId:abc-123",
        "error_code": "SQL_CONNECTION_RESET",
        "priority_hint": "P3"
    },
    "data": {
        "job_name": "ingest-customer-events",
        "job_type": "databricks",
        "source_system": "Azure-EastUS",
        "environment": "prod",
        "error_message": "org.apache.spark.sql.AnalysisException: cannot resolve 'customer_id' given input columns: [event_type, timestamp, user_id, metadata]",
        "error_code": "SCHEMA_MISMATCH",
        "priority_hint": "P2"
    },
    "config": {
        "job_name": "export-to-snowflake",
        "job_type": "databricks",
        "source_system": "Azure-EastUS",
        "environment": "uat",
        "error_message": "net.snowflake.client.jdbc.SnowflakeSQLException: Invalid credentials. Ensure your username and password are correct.",
        "error_code": "SNOWFLAKE_AUTH_FAILED",
        "priority_hint": "P2"
    },
    "unknown": {
        "job_name": "mystery-batch-processor",
        "job_type": "databricks",
        "source_system": "Azure-EastUS",
        "environment": "prod",
        "error_message": "Unexpected error occurred during execution: [INTERNAL_ERROR] Something went wrong, please contact support.",
        "error_code": "UNKNOWN",
        "priority_hint": "P1"
    }
}


def send_incident(api_url: str, api_key: str, scenario: str) -> dict:
    """Send a test incident to the API."""
    if scenario not in SCENARIOS:
        print(f"Unknown scenario: {scenario}")
        print(f"Available: {', '.join(SCENARIOS.keys())}")
        sys.exit(1)

    incident = SCENARIOS[scenario].copy()
    incident["failure_timestamp"] = datetime.now(timezone.utc).isoformat()
    incident["metadata"] = {
        "test": True,
        "scenario": scenario,
        "sent_at": datetime.now(timezone.utc).isoformat()
    }

    print(f"\nSending {scenario} incident...")
    print(f"Job: {incident['job_name']}")
    print(f"Error: {incident['error_message'][:100]}...")
    print()

    response = requests.post(
        f"{api_url}/api/v1/incidents",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key
        },
        json=incident,
        timeout=30
    )

    if response.status_code == 200:
        result = response.json()
        print(f"✓ Incident created: {result['incident_id']}")
        print(f"  Status: {result['status']}")
        print(f"  Message: {result['message']}")
        return result
    else:
        print(f"✗ Failed: {response.status_code}")
        print(f"  {response.text}")
        return None


def check_incident_status(api_url: str, api_key: str, incident_id: str) -> dict:
    """Check the status of an incident."""
    response = requests.get(
        f"{api_url}/api/v1/incidents/{incident_id}",
        headers={"X-API-Key": api_key},
        timeout=30
    )

    if response.status_code == 200:
        return response.json()
    return None


def main():
    parser = argparse.ArgumentParser(description="Send test incident to Support Agent")
    parser.add_argument(
        "--api-url",
        default=os.getenv("SUPPORT_AGENT_URL", "http://localhost:8000"),
        help="API URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("SUPPORT_AGENT_API_KEY", "dev-api-key-12345"),
        help="API key"
    )
    parser.add_argument(
        "--scenario",
        default="oom",
        choices=list(SCENARIOS.keys()),
        help="Test scenario (default: oom)"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch incident status after creation"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("Support Agent - Test Incident Sender")
    print("=" * 50)
    print(f"API URL: {args.api_url}")
    print(f"Scenario: {args.scenario}")

    # Check API health first
    try:
        health = requests.get(f"{args.api_url}/health/live", timeout=5)
        if health.status_code != 200:
            print(f"\n✗ API not healthy: {health.status_code}")
            sys.exit(1)
        print("✓ API is healthy")
    except requests.exceptions.ConnectionError:
        print(f"\n✗ Cannot connect to {args.api_url}")
        print("  Make sure the API is running: uvicorn src.api.main:app --reload")
        sys.exit(1)

    # Send incident
    result = send_incident(args.api_url, args.api_key, args.scenario)

    if result and args.watch:
        import time

        incident_id = result["incident_id"]
        print(f"\nWatching incident {incident_id}...")
        print("(Press Ctrl+C to stop)\n")

        try:
            while True:
                status = check_incident_status(args.api_url, args.api_key, incident_id)
                if status:
                    print(f"  [{datetime.now().strftime('%H:%M:%S')}] "
                          f"Stage: {status.get('workflow_stage', 'unknown')}, "
                          f"Status: {status.get('status', 'unknown')}")

                    if status.get("status") in ["resolved", "escalated", "error"]:
                        print(f"\n  Final status: {status.get('status')}")
                        if status.get("resolution_summary"):
                            print(f"  Resolution: {status.get('resolution_summary')}")
                        break

                time.sleep(2)
        except KeyboardInterrupt:
            print("\n  Stopped watching")


if __name__ == "__main__":
    main()
