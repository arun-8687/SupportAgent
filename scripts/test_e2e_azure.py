"""
End-to-end test for Azure deployment.

Tests the complete Support Agent workflow:
1. Submit incident via API
2. Poll for completion
3. Verify LangSmith traces
4. Check metrics

Run with:
    export APP_URL="https://app-support-agent-dev.azurewebsites.net"
    export API_KEY="your-api-key"
    python scripts/test_e2e_azure.py
"""
import asyncio
import httpx
import os
import sys
import time
from datetime import datetime


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"


def log(msg, color=None):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if color:
        print(f"{color}[{timestamp}] {msg}{Colors.END}")
    else:
        print(f"[{timestamp}] {msg}")


async def test_health(client: httpx.AsyncClient, app_url: str) -> bool:
    """Test health endpoints."""
    log("Testing health endpoints...", Colors.BLUE)

    # Liveness
    response = await client.get(f"{app_url}/health/live")
    if response.status_code != 200:
        log(f"✗ Liveness check failed: {response.status_code}", Colors.RED)
        return False
    log("  ✓ Liveness: OK", Colors.GREEN)

    # Readiness
    response = await client.get(f"{app_url}/health/ready")
    if response.status_code != 200:
        log(f"✗ Readiness check failed: {response.text}", Colors.RED)
        return False

    ready_data = response.json()
    log(f"  ✓ Readiness: {ready_data.get('status', 'unknown')}", Colors.GREEN)

    # Show component status
    components = ready_data.get("components", {})
    for name, status in components.items():
        healthy = status.get("healthy", False)
        symbol = "✓" if healthy else "✗"
        color = Colors.GREEN if healthy else Colors.RED
        log(f"    {symbol} {name}: {status.get('message', 'unknown')}", color)

    return True


async def test_langsmith(client: httpx.AsyncClient, app_url: str) -> bool:
    """Test LangSmith integration."""
    log("Testing LangSmith integration...", Colors.BLUE)

    response = await client.get(f"{app_url}/api/v1/test-langsmith")
    if response.status_code != 200:
        log(f"✗ LangSmith test endpoint not found", Colors.YELLOW)
        return True  # Not critical

    data = response.json()
    if data.get("status") == "enabled":
        log(f"  ✓ LangSmith enabled, project: {data.get('project')}", Colors.GREEN)
        log(f"    Run ID: {data.get('run_id')}", Colors.GREEN)
        return True
    else:
        log(f"  ⚠ LangSmith disabled: {data.get('message')}", Colors.YELLOW)
        return True


async def test_incident_submission(
    client: httpx.AsyncClient,
    app_url: str,
    api_key: str
) -> str:
    """Submit a test incident."""
    log("Submitting test incident...", Colors.BLUE)

    incident_data = {
        "job_name": f"e2e-test-job-{int(time.time())}",
        "job_type": "databricks",
        "source_system": "e2e-test",
        "environment": "dev",
        "error_message": "java.lang.OutOfMemoryError: Java heap space",
        "error_code": "OOM_ERROR",
        "stack_trace": """
            java.lang.OutOfMemoryError: Java heap space
                at org.apache.spark.sql.execution.WholeStageCodegenExec.doExecute(WholeStageCodegenExec.scala:74)
                at org.apache.spark.sql.execution.SparkPlan.execute(SparkPlan.scala:180)
                at org.apache.spark.sql.Dataset.collectFromPlan(Dataset.scala:3868)
        """,
        "cluster_id": "test-cluster-123",
        "job_run_id": f"run-{int(time.time())}"
    }

    response = await client.post(
        f"{app_url}/api/v1/incidents",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=incident_data
    )

    if response.status_code == 401:
        log("✗ Authentication failed - check API_KEY", Colors.RED)
        return None

    if response.status_code != 200:
        log(f"✗ Incident submission failed: {response.text}", Colors.RED)
        return None

    data = response.json()
    incident_id = data.get("incident_id")
    log(f"  ✓ Incident created: {incident_id}", Colors.GREEN)
    log(f"    Status: {data.get('status')}", Colors.GREEN)

    return incident_id


async def poll_incident_status(
    client: httpx.AsyncClient,
    app_url: str,
    api_key: str,
    incident_id: str,
    max_wait: int = 60
) -> dict:
    """Poll for incident completion."""
    log(f"Polling incident status (max {max_wait}s)...", Colors.BLUE)

    for i in range(max_wait // 2):
        response = await client.get(
            f"{app_url}/api/v1/incidents/{incident_id}",
            headers={"X-API-Key": api_key}
        )

        if response.status_code != 200:
            log(f"  Warning: Status check failed: {response.status_code}", Colors.YELLOW)
            await asyncio.sleep(2)
            continue

        status = response.json()
        stage = status.get("workflow_stage", "unknown")
        log(f"  Stage: {stage}", Colors.BLUE)

        if status.get("incident_closed"):
            log(f"  ✓ Incident resolved!", Colors.GREEN)
            log(f"    Resolution: {status.get('resolution_summary', 'N/A')[:100]}", Colors.GREEN)
            return status

        if status.get("requires_human_review"):
            log(f"  ⚠ Incident escalated to human review", Colors.YELLOW)
            return status

        await asyncio.sleep(2)

    log(f"  ⚠ Timeout waiting for completion", Colors.YELLOW)
    return None


async def check_metrics(client: httpx.AsyncClient, app_url: str) -> bool:
    """Verify Prometheus metrics."""
    log("Checking Prometheus metrics...", Colors.BLUE)

    response = await client.get(f"{app_url}/metrics")
    if response.status_code != 200:
        log(f"✗ Metrics endpoint failed", Colors.RED)
        return False

    metrics = response.text
    checks = [
        ("support_agent_incidents_received_total", "Incidents received"),
        ("support_agent_llm_requests_total", "LLM requests"),
        ("support_agent_workflow_stage_seconds", "Workflow timing"),
        ("support_agent_tool_executions_total", "Tool executions"),
    ]

    for metric, description in checks:
        if metric in metrics:
            log(f"  ✓ {description} metric present", Colors.GREEN)
        else:
            log(f"  ⚠ {description} metric not found", Colors.YELLOW)

    return True


async def main():
    """Run all tests."""
    app_url = os.getenv("APP_URL")
    api_key = os.getenv("API_KEY")

    if not app_url:
        log("ERROR: APP_URL environment variable not set", Colors.RED)
        log("Usage: APP_URL=https://your-app.azurecontainerapps.io API_KEY=xxx python test_e2e_azure.py")
        sys.exit(1)

    if not api_key:
        log("ERROR: API_KEY environment variable not set", Colors.RED)
        sys.exit(1)

    log(f"Testing: {app_url}", Colors.BLUE)
    log("=" * 60)

    async with httpx.AsyncClient(timeout=120) as client:
        # 1. Health checks
        if not await test_health(client, app_url):
            log("\nHealth checks failed. Aborting.", Colors.RED)
            sys.exit(1)
        log("")

        # 2. LangSmith
        await test_langsmith(client, app_url)
        log("")

        # 3. Submit incident
        incident_id = await test_incident_submission(client, app_url, api_key)
        if not incident_id:
            log("\nIncident submission failed. Aborting.", Colors.RED)
            sys.exit(1)
        log("")

        # 4. Poll for completion
        final_status = await poll_incident_status(client, app_url, api_key, incident_id)
        log("")

        # 5. Check metrics
        await check_metrics(client, app_url)
        log("")

    # Summary
    log("=" * 60)
    log("TEST SUMMARY", Colors.BLUE)
    log(f"  Incident ID: {incident_id}")
    if final_status:
        if final_status.get("incident_closed"):
            log("  Result: RESOLVED", Colors.GREEN)
        else:
            log("  Result: ESCALATED", Colors.YELLOW)
    else:
        log("  Result: TIMEOUT", Colors.YELLOW)

    log("")
    log("Next steps:")
    log("  1. Check LangSmith: https://smith.langchain.com")
    log(f"  2. View incident: {app_url}/api/v1/incidents/{incident_id}")
    log(f"  3. View metrics: {app_url}/metrics")


if __name__ == "__main__":
    asyncio.run(main())
