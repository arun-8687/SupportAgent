"""
Test LangSmith integration locally.

Run with:
    # Set up .env with LANGCHAIN_API_KEY
    python scripts/test_langsmith_local.py
"""
import asyncio
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Load .env file
load_dotenv()


async def test_langsmith():
    """Test LangSmith tracing locally."""
    # Import after loading env
    from src.observability import get_langsmith
    from src.observability.langsmith_integration import LangSmithObservability

    print("=" * 60)
    print("LangSmith Local Test")
    print("=" * 60)

    # Check configuration
    api_key = os.getenv("LANGCHAIN_API_KEY", "")
    project = os.getenv("LANGCHAIN_PROJECT", "support-agent-test")

    print(f"\nConfiguration:")
    print(f"  LANGCHAIN_API_KEY: {'***' + api_key[-8:] if len(api_key) > 8 else 'NOT SET'}")
    print(f"  LANGCHAIN_PROJECT: {project}")
    print(f"  LANGCHAIN_ENDPOINT: {os.getenv('LANGCHAIN_ENDPOINT', 'https://api.smith.langchain.com')}")

    # Get LangSmith instance
    ls = get_langsmith()
    print(f"\nLangSmith enabled: {ls.enabled}")

    if not ls.enabled:
        print("\n❌ LangSmith not enabled!")
        print("   Make sure LANGCHAIN_API_KEY is set in your .env file")
        print("   Get your API key at: https://smith.langchain.com/settings")
        sys.exit(1)

    print("\n" + "-" * 60)
    print("Creating test traces...")
    print("-" * 60)

    # Test 1: Trace an incident
    print("\n1. Creating incident trace...")
    with ls.trace_incident(
        incident_id="TEST-LOCAL-001",
        job_name="local-test-etl-job",
        job_type="databricks",
        environment="local",
        source_system="local-test"
    ) as incident_run:
        print(f"   Run ID: {incident_run.run_id}")

        # Test 2: Trace triage stage
        print("\n2. Creating triage stage trace...")
        with ls.trace_stage(
            stage_name="triage",
            inputs={"incident_id": "TEST-LOCAL-001"}
        ) as triage_run:
            print(f"   Triage Run ID: {triage_run.run_id}")
            await asyncio.sleep(0.1)  # Simulate work
            triage_run.add_outputs({"classification": "resource", "severity": "P2"})

        # Test 3: Trace diagnosis stage
        print("\n3. Creating diagnosis stage trace...")
        with ls.trace_stage(
            stage_name="diagnose",
            inputs={"incident_id": "TEST-LOCAL-001"}
        ) as diagnose_run:
            print(f"   Diagnose Run ID: {diagnose_run.run_id}")

            # Test 4: Trace tool calls
            print("\n4. Creating tool call traces...")
            with ls.trace_tool(
                tool_name="get_job_run_details",
                inputs={"run_id": "12345"}
            ) as tool_run:
                print(f"   Tool Run ID: {tool_run.run_id}")
                await asyncio.sleep(0.05)
                tool_run.add_outputs({
                    "state": "FAILED",
                    "error": "OutOfMemoryError"
                })

            with ls.trace_tool(
                tool_name="get_cluster_status",
                inputs={"cluster_id": "cluster-abc"}
            ) as tool_run:
                print(f"   Tool Run ID: {tool_run.run_id}")
                await asyncio.sleep(0.05)
                tool_run.add_outputs({
                    "state": "RUNNING",
                    "num_workers": 4
                })

        # Record classification metadata
        incident_run.record_classification(
            category="resource",
            confidence=0.85,
            is_known_issue=False
        )
        incident_run.record_severity("P2")

        # Record remediation
        incident_run.record_remediation(
            actions=["restart_job", "increase_memory"],
            success=True,
            automated=True
        )

        incident_run.add_outputs({
            "resolution_summary": "Increased driver memory and restarted job",
            "incident_closed": True
        })

    print("\n" + "-" * 60)
    print("Test complete!")
    print("-" * 60)

    print(f"\n✅ Traces created successfully!")
    print(f"\nView traces at:")
    print(f"  https://smith.langchain.com/o/default/projects/p/{project}")
    print(f"\nLook for:")
    print(f"  - incident:TEST-LOCAL-001 (parent run)")
    print(f"  - Nested: triage, diagnose stages")
    print(f"  - Nested: tool calls (get_job_run_details, get_cluster_status)")


async def test_feedback():
    """Test feedback collection."""
    from src.observability import get_langsmith

    ls = get_langsmith()
    if not ls.enabled:
        return

    print("\n" + "-" * 60)
    print("Testing feedback collection...")
    print("-" * 60)

    # Create a simple run to test feedback
    with ls.trace_stage("feedback_test", inputs={"test": True}) as run:
        run.add_outputs({"result": "success"})
        run_id = run.run_id

    # Record feedback
    ls.record_feedback(
        run_id=run_id,
        key="test_score",
        score=1.0,
        comment="Automated test feedback"
    )
    print("✅ Feedback recorded")


if __name__ == "__main__":
    print("Starting LangSmith local test...\n")
    asyncio.run(test_langsmith())
    asyncio.run(test_feedback())
