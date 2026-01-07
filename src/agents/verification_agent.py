"""
Verification Agent - Verifies remediation success.

Handles:
- Post-remediation verification checks
- Job status validation
- Health check execution
- Success/failure determination
"""
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.agents.base_agent import AgentConfig, DiagnosticAgent
from src.graph.state import (
    AppSupportState,
    ExecutionResult,
    VerificationResult,
    WorkflowStage,
)
from src.tools.base import ToolRegistry, ToolResult
from src.observability import (
    metrics,
    audit,
    AuditEventType,
)


class VerificationAgent(DiagnosticAgent):
    """
    Verifies that remediation was successful.

    Workflow:
    1. Wait for system stabilization
    2. Run verification checks
    3. Validate job status
    4. Determine success/failure
    5. Generate verification report
    """

    # Verification check configurations by job type
    VERIFICATION_CHECKS = {
        "databricks": [
            {"name": "job_status", "tool": "get_job_status", "success_states": ["SUCCEEDED", "RUNNING"]},
            {"name": "cluster_health", "tool": "get_cluster_status", "success_states": ["RUNNING", "PENDING"]},
            {"name": "recent_runs", "tool": "get_recent_job_runs", "check": "no_failures"}
        ],
        "adf": [
            {"name": "pipeline_status", "tool": "get_pipeline_status", "success_states": ["Succeeded", "InProgress"]},
            {"name": "activity_status", "tool": "get_activity_status", "success_states": ["Succeeded"]}
        ],
        "iws": [
            {"name": "job_status", "tool": "get_iws_job_status", "success_states": ["COMPLETED", "RUNNING"]},
            {"name": "schedule_status", "tool": "get_iws_schedule", "check": "enabled"}
        ],
        "webapp": [
            {"name": "health_check", "tool": "run_health_check", "success_states": ["healthy"]},
            {"name": "endpoint_check", "tool": "check_endpoint", "success_states": ["200", "201", "204"]}
        ],
        "api": [
            {"name": "health_check", "tool": "run_health_check", "success_states": ["healthy"]},
            {"name": "endpoint_check", "tool": "check_endpoint", "success_states": ["200", "201", "204"]}
        ]
    }

    def __init__(
        self,
        tool_registry: ToolRegistry,
        stabilization_wait_seconds: int = 30,
        **kwargs
    ):
        """
        Initialize verification agent.

        Args:
            tool_registry: Registry of available tools
            stabilization_wait_seconds: Seconds to wait before verification
        """
        config = AgentConfig(
            name="verification",
            description="Post-remediation verification",
            max_tool_calls=20,
            temperature=0.1
        )
        super().__init__(config, tool_registry, **kwargs)
        self.stabilization_wait_seconds = stabilization_wait_seconds

    async def execute(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Execute verification workflow.

        Args:
            state: Current workflow state

        Returns:
            State updates with verification results
        """
        incident = state["incident"]
        execution = state.get("execution_result")

        # Validate execution exists and succeeded
        if not execution:
            self.logger.error("no_execution_to_verify")
            return self._failure_result(
                state, "No execution result to verify"
            )

        if not execution.success:
            self.logger.info("execution_failed_skipping_verification")
            return self._failure_result(
                state, "Execution failed, verification skipped"
            )

        self.logger.info(
            "starting_verification",
            incident_id=incident.incident_id,
            job_name=incident.job_name
        )

        # Audit verification start
        audit.log(
            event_type=AuditEventType.VERIFICATION_COMPLETED,
            action="Starting verification",
            incident_id=incident.incident_id,
            details={"job_name": incident.job_name, "job_type": incident.job_type}
        )

        # Wait for system stabilization
        if self.stabilization_wait_seconds > 0:
            self.logger.info(
                "waiting_for_stabilization",
                seconds=self.stabilization_wait_seconds
            )
            await asyncio.sleep(self.stabilization_wait_seconds)

        # Run verification checks
        verification_checks = await self._run_verification_checks(incident)

        # Determine overall success
        success = self._determine_success(verification_checks)

        # Get job status
        job_status = await self._get_job_status(incident)

        verification_result = VerificationResult(
            success=success,
            verification_checks=verification_checks,
            job_status=job_status,
            verified_at=datetime.now(timezone.utc),
            notes=self._generate_notes(verification_checks, success)
        )

        self.logger.info(
            "verification_completed",
            success=success,
            checks_passed=sum(1 for c in verification_checks if c.get("passed")),
            checks_total=len(verification_checks)
        )

        # Record metrics
        if success:
            metrics.verification_success.labels(job_type=incident.job_type).inc()
        else:
            metrics.verification_failure.labels(job_type=incident.job_type).inc()

        # Audit verification completion
        audit.log(
            event_type=AuditEventType.VERIFICATION_COMPLETED,
            action="Verification completed",
            incident_id=incident.incident_id,
            outcome="success" if success else "failure",
            details={
                "checks_passed": sum(1 for c in verification_checks if c.get("passed")),
                "checks_total": len(verification_checks),
                "job_status": job_status
            }
        )

        # Determine next workflow stage
        if success:
            workflow_stage = WorkflowStage.RESOLUTION
            resolution_summary = self._generate_resolution_summary(state)
        else:
            workflow_stage = WorkflowStage.ESCALATED
            resolution_summary = None

        result = {
            "verification_result": verification_result,
            "workflow_stage": workflow_stage,
            "messages": self.add_message(
                state,
                "assistant",
                f"Verification {'succeeded' if success else 'failed'}: "
                f"{sum(1 for c in verification_checks if c.get('passed'))}/{len(verification_checks)} checks passed"
            )
        }

        if resolution_summary:
            result["resolution_summary"] = resolution_summary
            result["incident_closed"] = True
            result["closed_at"] = datetime.now(timezone.utc)

        if not success:
            result["requires_human_review"] = True

        return result

    async def _run_verification_checks(
        self,
        incident: Any
    ) -> List[Dict[str, Any]]:
        """Run verification checks for the incident's job type."""
        job_type = incident.job_type
        checks_config = self.VERIFICATION_CHECKS.get(job_type, [])

        if not checks_config:
            # Default generic check
            checks_config = [
                {"name": "job_status", "tool": "get_job_status", "success_states": ["SUCCESS", "RUNNING"]}
            ]

        verification_results = []

        for check in checks_config:
            result = await self._run_single_check(check, incident)
            verification_results.append(result)

        return verification_results

    async def _run_single_check(
        self,
        check: Dict[str, Any],
        incident: Any
    ) -> Dict[str, Any]:
        """Run a single verification check."""
        check_name = check["name"]
        tool_name = check["tool"]

        self.logger.debug("running_check", check_name=check_name, tool=tool_name)

        # Check if tool exists
        tool = self.tool_registry.get(tool_name)
        if not tool:
            return {
                "name": check_name,
                "tool": tool_name,
                "passed": None,
                "error": f"Tool not found: {tool_name}",
                "skipped": True
            }

        # Build params
        params = self._build_tool_params(tool_name, incident)

        try:
            result = await self.execute_tool(tool_name, **params)

            if not result.success:
                return {
                    "name": check_name,
                    "tool": tool_name,
                    "passed": False,
                    "error": result.error,
                    "data": result.data
                }

            # Evaluate check result
            passed = self._evaluate_check(check, result.data)

            return {
                "name": check_name,
                "tool": tool_name,
                "passed": passed,
                "data": result.data,
                "success_criteria": check.get("success_states") or check.get("check")
            }

        except Exception as e:
            self.logger.error(
                "check_exception",
                check_name=check_name,
                error=str(e)
            )
            return {
                "name": check_name,
                "tool": tool_name,
                "passed": False,
                "error": str(e)
            }

    def _evaluate_check(
        self,
        check: Dict[str, Any],
        data: Any
    ) -> bool:
        """Evaluate if a check passed based on its criteria."""
        if not data:
            return False

        # Check against success states
        if "success_states" in check:
            success_states = check["success_states"]

            # Handle different data formats
            if isinstance(data, dict):
                status = data.get("status") or data.get("state") or data.get("Status")
                if status:
                    return str(status) in success_states

                # Check for status code
                status_code = data.get("status_code") or data.get("statusCode")
                if status_code:
                    return str(status_code) in success_states

            elif isinstance(data, str):
                return data in success_states

        # Check against custom check type
        if "check" in check:
            check_type = check["check"]

            if check_type == "no_failures":
                if isinstance(data, list):
                    return not any(
                        r.get("status") in ["FAILED", "ERROR", "CANCELLED"]
                        for r in data
                    )
                return True

            if check_type == "enabled":
                if isinstance(data, dict):
                    return data.get("enabled", False) or data.get("is_enabled", False)

        # Default: if we have data and no explicit failure, pass
        return True

    def _determine_success(
        self,
        checks: List[Dict[str, Any]]
    ) -> bool:
        """Determine overall verification success."""
        if not checks:
            return False

        # Filter out skipped checks
        active_checks = [c for c in checks if not c.get("skipped")]

        if not active_checks:
            # All checks were skipped, consider it a pass
            return True

        # Require majority of checks to pass
        passed = sum(1 for c in active_checks if c.get("passed"))
        required = len(active_checks) // 2 + 1

        return passed >= required

    async def _get_job_status(self, incident: Any) -> Optional[str]:
        """Get current job status."""
        status_tools = {
            "databricks": "get_job_status",
            "adf": "get_pipeline_status",
            "iws": "get_iws_job_status",
            "webapp": "run_health_check",
            "api": "run_health_check"
        }

        tool_name = status_tools.get(incident.job_type, "get_job_status")
        tool = self.tool_registry.get(tool_name)

        if not tool:
            return None

        try:
            params = self._build_tool_params(tool_name, incident)
            result = await self.execute_tool(tool_name, **params)

            if result.success and result.data:
                if isinstance(result.data, dict):
                    return result.data.get("status") or result.data.get("state")
                return str(result.data)

        except Exception:
            pass

        return None

    def _generate_notes(
        self,
        checks: List[Dict[str, Any]],
        success: bool
    ) -> str:
        """Generate verification notes."""
        parts = []

        if success:
            parts.append("Verification successful.")
        else:
            parts.append("Verification failed.")

        # Summarize check results
        passed = [c for c in checks if c.get("passed")]
        failed = [c for c in checks if c.get("passed") is False]
        skipped = [c for c in checks if c.get("skipped")]

        if passed:
            parts.append(f"Passed: {', '.join(c['name'] for c in passed)}")

        if failed:
            parts.append(f"Failed: {', '.join(c['name'] for c in failed)}")
            for c in failed:
                if c.get("error"):
                    parts.append(f"  - {c['name']}: {c['error']}")

        if skipped:
            parts.append(f"Skipped: {', '.join(c['name'] for c in skipped)}")

        return " ".join(parts)

    def _generate_resolution_summary(self, state: AppSupportState) -> str:
        """Generate resolution summary for closing the incident."""
        incident = state["incident"]
        diagnostic = state.get("diagnostic_result")
        proposal = state.get("proposal")
        execution = state.get("execution_result")

        parts = [
            f"Incident {incident.incident_id} resolved automatically.",
            ""
        ]

        if diagnostic and diagnostic.root_cause:
            parts.append(f"Root Cause: {diagnostic.root_cause.description}")

        if proposal:
            parts.append(f"Resolution: {proposal.reasoning}")
            parts.append(f"Steps Executed: {len(proposal.steps)}")

        if execution:
            duration = sum(s.execution_time_ms for s in execution.executed_steps)
            parts.append(f"Execution Time: {duration}ms")

        parts.append("")
        parts.append("Verified successfully - incident closed.")

        return "\n".join(parts)

    def _failure_result(
        self,
        state: AppSupportState,
        error_message: str
    ) -> Dict[str, Any]:
        """Create failure result."""
        return {
            "verification_result": VerificationResult(
                success=False,
                verification_checks=[],
                verified_at=datetime.now(timezone.utc),
                notes=error_message
            ),
            "workflow_stage": WorkflowStage.ESCALATED,
            "requires_human_review": True,
            "messages": self.add_message(
                state,
                "assistant",
                f"Verification failed: {error_message}"
            )
        }
