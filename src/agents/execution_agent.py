"""
Execution Agent - Executes approved remediation plans.

Handles:
- Step-by-step execution with monitoring
- Rollback on failure
- Progress tracking
- Execution audit logging
"""
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.agents.base_agent import AgentConfig, RemediationAgent
from src.graph.state import (
    AppSupportState,
    ExecutionResult,
    ExecutionStep,
    RemediationProposal,
    WorkflowStage,
)
from src.tools.base import ToolRegistry, ToolResult
from src.observability import (
    metrics,
    audit,
    AuditEventType,
)


class ExecutionAgent(RemediationAgent):
    """
    Executes approved remediation plans.

    Workflow:
    1. Validate approval status
    2. Execute steps sequentially
    3. Monitor for failures
    4. Rollback if needed
    5. Record execution results
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        **kwargs
    ):
        """
        Initialize execution agent.

        Args:
            tool_registry: Registry of available tools
        """
        config = AgentConfig(
            name="execution",
            description="Remediation execution with rollback support",
            max_tool_calls=50,
            temperature=0.1,
            require_tool_confirmation=True
        )
        super().__init__(config, tool_registry, **kwargs)

    async def execute(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Execute approved remediation plan.

        Args:
            state: Current workflow state

        Returns:
            State updates with execution results
        """
        incident = state["incident"]
        proposal = state.get("proposal")
        approval = state.get("approval")

        # Validate we have an approved proposal
        if not proposal:
            self.logger.error("no_proposal_to_execute")
            return self._error_result(state, "No proposal to execute")

        if not approval or not approval.approved:
            self.logger.error("proposal_not_approved")
            return self._error_result(state, "Proposal not approved")

        self.logger.info(
            "starting_execution",
            incident_id=incident.incident_id,
            steps_count=len(proposal.steps)
        )

        # Audit execution start
        audit.log(
            event_type=AuditEventType.REMEDIATION_EXECUTED,
            action="Starting remediation execution",
            incident_id=incident.incident_id,
            details={
                "steps": len(proposal.steps),
                "approver": approval.approver,
                "proposal_source": proposal.source
            }
        )

        # Execute remediation steps
        execution_result = await self._execute_remediation(proposal, incident)

        # Record metrics
        metrics.workflow_stage_duration.labels(stage="execution").observe(
            sum(s.execution_time_ms for s in execution_result.executed_steps) / 1000
        )

        if execution_result.success:
            metrics.remediation_success.labels(
                job_type=incident.job_type,
                source=proposal.source
            ).inc()
        else:
            metrics.remediation_failure.labels(
                job_type=incident.job_type,
                source=proposal.source
            ).inc()

        self.logger.info(
            "execution_completed",
            success=execution_result.success,
            steps_executed=len(execution_result.executed_steps),
            rollback_performed=execution_result.rollback_performed
        )

        # Audit execution completion
        audit.log(
            event_type=AuditEventType.REMEDIATION_EXECUTED,
            action="Remediation execution completed",
            incident_id=incident.incident_id,
            outcome="success" if execution_result.success else "failure",
            details={
                "steps_executed": len(execution_result.executed_steps),
                "rollback_performed": execution_result.rollback_performed,
                "error": execution_result.error_message
            }
        )

        return {
            "execution_result": execution_result,
            "workflow_stage": WorkflowStage.EXECUTION,
            "messages": self.add_message(
                state,
                "assistant",
                f"Execution {'succeeded' if execution_result.success else 'failed'}: "
                f"{len(execution_result.executed_steps)} steps executed"
            )
        }

    async def _execute_remediation(
        self,
        proposal: RemediationProposal,
        incident: Any
    ) -> ExecutionResult:
        """Execute remediation steps with rollback support."""
        executed_steps: List[ExecutionStep] = []
        rollback_stack: List[Dict[str, Any]] = []

        for step in proposal.steps:
            self.logger.info(
                "executing_step",
                step_name=step.name,
                tool=step.tool
            )

            start_time = datetime.now(timezone.utc)

            try:
                # Execute the step
                result = await self._execute_step(step, incident)

                execution_time_ms = int(
                    (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                )

                execution_step = ExecutionStep(
                    step_name=step.name,
                    tool=step.tool,
                    success=result.success,
                    output=result.data,
                    error=result.error,
                    execution_time_ms=execution_time_ms,
                    executed_at=start_time,
                    rollback_info=step.rollback_params if step.supports_rollback else None
                )
                executed_steps.append(execution_step)

                if not result.success:
                    self.logger.warning(
                        "step_failed",
                        step_name=step.name,
                        error=result.error
                    )

                    # Attempt rollback
                    rollback_steps = await self._rollback(rollback_stack)

                    return ExecutionResult(
                        success=False,
                        executed_steps=executed_steps,
                        rollback_performed=len(rollback_steps) > 0,
                        rollback_steps=rollback_steps,
                        error_message=f"Step {step.name} failed: {result.error}"
                    )

                # Add to rollback stack if reversible
                if step.supports_rollback and result.rollback_action:
                    rollback_stack.append({
                        "step_name": step.name,
                        "rollback_action": result.rollback_action,
                        "params": step.rollback_params or {}
                    })

            except Exception as e:
                self.logger.error(
                    "step_exception",
                    step_name=step.name,
                    error=str(e)
                )

                execution_step = ExecutionStep(
                    step_name=step.name,
                    tool=step.tool,
                    success=False,
                    error=str(e),
                    execution_time_ms=int(
                        (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    ),
                    executed_at=start_time
                )
                executed_steps.append(execution_step)

                # Attempt rollback
                rollback_steps = await self._rollback(rollback_stack)

                return ExecutionResult(
                    success=False,
                    executed_steps=executed_steps,
                    rollback_performed=len(rollback_steps) > 0,
                    rollback_steps=rollback_steps,
                    error_message=f"Exception in {step.name}: {str(e)}"
                )

        # All steps succeeded
        return ExecutionResult(
            success=True,
            executed_steps=executed_steps,
            rollback_performed=False,
            rollback_steps=[]
        )

    async def _execute_step(
        self,
        step: Any,
        incident: Any
    ) -> ToolResult:
        """Execute a single remediation step."""
        tool = self.tool_registry.get(step.tool)

        if not tool:
            # Check if it's a manual step
            if step.tool == "manual":
                self.logger.info(
                    "manual_step_required",
                    description=step.description
                )
                return ToolResult(
                    success=True,
                    data={"message": "Manual step acknowledged", "description": step.description}
                )

            return ToolResult(
                success=False,
                error=f"Tool not found: {step.tool}"
            )

        # Merge incident params with step params
        params = {**self._build_incident_params(incident), **step.params}

        return await self.execute_tool(step.tool, **params)

    def _build_incident_params(self, incident: Any) -> Dict[str, Any]:
        """Build common parameters from incident."""
        params = {}

        if hasattr(incident, "job_name"):
            params["job_name"] = incident.job_name

        if hasattr(incident, "job_run_id") and incident.job_run_id:
            params["run_id"] = incident.job_run_id

        if hasattr(incident, "cluster_id") and incident.cluster_id:
            params["cluster_id"] = incident.cluster_id

        if hasattr(incident, "environment"):
            params["environment"] = incident.environment

        return params

    async def _rollback(
        self,
        rollback_stack: List[Dict[str, Any]]
    ) -> List[str]:
        """Execute rollback for failed remediation."""
        rollback_steps_executed = []

        self.logger.info(
            "starting_rollback",
            steps_to_rollback=len(rollback_stack)
        )

        # Rollback in reverse order
        for rollback_info in reversed(rollback_stack):
            step_name = rollback_info["step_name"]
            rollback_action = rollback_info["rollback_action"]
            params = rollback_info["params"]

            try:
                self.logger.info(
                    "rolling_back_step",
                    step_name=step_name
                )

                # Execute rollback using the rollback manager
                if callable(rollback_action):
                    await rollback_action(**params)
                    rollback_steps_executed.append(step_name)
                elif isinstance(rollback_action, str):
                    # It's a tool name
                    result = await self.execute_tool(rollback_action, **params)
                    if result.success:
                        rollback_steps_executed.append(step_name)
                    else:
                        self.logger.error(
                            "rollback_step_failed",
                            step_name=step_name,
                            error=result.error
                        )

            except Exception as e:
                self.logger.error(
                    "rollback_exception",
                    step_name=step_name,
                    error=str(e)
                )

        self.logger.info(
            "rollback_completed",
            steps_rolled_back=len(rollback_steps_executed)
        )

        return rollback_steps_executed

    def _error_result(
        self,
        state: AppSupportState,
        error_message: str
    ) -> Dict[str, Any]:
        """Create error result."""
        return {
            "execution_result": ExecutionResult(
                success=False,
                executed_steps=[],
                rollback_performed=False,
                rollback_steps=[],
                error_message=error_message
            ),
            "workflow_stage": WorkflowStage.EXECUTION,
            "requires_human_review": True,
            "messages": self.add_message(
                state,
                "assistant",
                f"Execution failed: {error_message}"
            )
        }
