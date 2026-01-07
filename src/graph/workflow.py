"""
LangGraph Workflow Definition.

Defines the StateGraph that orchestrates the support agent workflow:
Intake → Triage → Diagnose → Proposal → Approval → Execution → Verification → Resolution

Includes LangSmith tracing for full observability.
"""
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Literal, Optional, TYPE_CHECKING

from langgraph.graph import END, StateGraph

# Optional import for PostgresSaver (requires psycopg)
try:
    from langgraph.checkpoint.postgres import PostgresSaver
except ImportError:
    PostgresSaver = None  # type: ignore

from src.agents.base_agent import AgentConfig, BaseAgent
from src.graph.state import (
    AppSupportState,
    DeduplicationAction,
    Severity,
    WorkflowStage,
    create_initial_state,
)
from src.integrations.config import get_settings
from src.tools.base import ToolRegistry
from src.observability import (
    get_langsmith,
    metrics,
    audit,
    AuditEventType,
)


# =============================================================================
# Routing Functions
# =============================================================================

def route_after_triage(state: AppSupportState) -> str:
    """
    Route after triage based on classification.

    Routes to:
    - "suppress": Duplicate incident, no action needed
    - "diagnose": Needs investigation
    - "proposal": Known issue with solution
    - "escalate": Requires human review
    """
    triage = state.get("triage_result")
    if not triage:
        return "diagnose"

    # Check deduplication result
    dedup = triage.deduplication
    if dedup.action in [DeduplicationAction.SUPPRESS, DeduplicationAction.DUPLICATE]:
        return "suppress"

    # Check if known issue with high confidence
    if triage.classification.is_known_issue:
        if triage.classification.hypothesis_confidence > 0.9:
            return "proposal"

    # Check severity and routing
    if triage.classification.recommended_action == "escalate_human":
        return "escalate"

    if triage.severity == Severity.P1:
        # P1 always gets diagnosed even if known
        return "diagnose"

    if triage.classification.recommended_action == "auto_fix":
        return "proposal"

    return "diagnose"


def route_after_diagnose(state: AppSupportState) -> str:
    """
    Route after diagnosis.

    Routes to:
    - "proposal": Root cause found with confidence
    - "escalate": Low confidence or no root cause
    """
    diagnostic = state.get("diagnostic_result")
    if not diagnostic:
        return "escalate"

    # Check confidence
    if diagnostic.root_cause.confidence >= 0.6:
        return "proposal"

    # Check retry count
    if state.get("retry_count", 0) < state.get("max_retries", 3):
        # Could retry diagnosis with different approach
        return "escalate"  # For now, escalate low confidence

    return "escalate"


def route_after_proposal(state: AppSupportState) -> str:
    """
    Route after proposal generation.

    Routes to:
    - "auto_approve": Simple, safe fixes
    - "human_approve": Risky or complex fixes
    - "escalate": No valid proposal
    """
    proposal = state.get("proposal")
    if not proposal:
        return "escalate"

    # Check if requires approval
    if not proposal.requires_approval:
        return "auto_approve"

    # Check risk level
    high_risk_steps = [
        step for step in proposal.steps
        if step.risk_level == "high"
    ]
    if high_risk_steps:
        return "human_approve"

    # Check confidence
    if proposal.estimated_success_probability >= 0.9:
        return "auto_approve"

    # Check environment
    incident = state.get("incident")
    if incident and incident.environment == "prod":
        # Production requires human approval for anything non-trivial
        if proposal.estimated_success_probability < 0.95:
            return "human_approve"

    return "auto_approve"


def route_after_approval(state: AppSupportState) -> str:
    """
    Route after approval decision.

    Routes to:
    - "execute": Approved
    - "escalate": Rejected or timeout
    """
    approval = state.get("approval")
    if not approval:
        return "escalate"

    if approval.approved:
        return "execute"

    return "escalate"


def route_after_execution(state: AppSupportState) -> str:
    """
    Route after execution.

    Routes to:
    - "verify": Execution succeeded
    - "rollback": Execution failed
    """
    execution = state.get("execution_result")
    if not execution:
        return "rollback"

    if execution.success:
        return "verify"

    return "rollback"


def route_after_verification(state: AppSupportState) -> str:
    """
    Route after verification.

    Routes to:
    - "resolve": Fix verified working
    - "retry": Fix didn't work, can retry
    - "escalate": Fix failed, max retries reached
    """
    verification = state.get("verification_result")
    if not verification:
        return "escalate"

    if verification.success:
        return "resolve"

    # Check retry count
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if retry_count < max_retries:
        return "retry"

    return "escalate"


# =============================================================================
# Node Functions (Placeholder implementations)
# =============================================================================

async def intake_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Initial intake of incident.

    Validates and enriches the incident data.
    Records metrics and audit events.
    """
    incident = state.get("incident")
    incident_id = incident.incident_id if incident else "unknown"

    # Record metrics
    metrics.incidents_received.labels(
        job_type=incident.job_type if incident else "unknown",
        environment=incident.environment if incident else "unknown",
        source_system=incident.source_system if incident else "unknown"
    ).inc()

    # Record active incident gauge
    severity = incident.priority_hint if incident and incident.priority_hint else "P3"
    metrics.active_incidents.labels(severity=severity).inc()

    # Audit the incident intake
    audit.log(
        event_type=AuditEventType.INCIDENT_RECEIVED,
        action="Incident received for processing",
        incident_id=incident_id,
        details={
            "job_name": incident.job_name if incident else None,
            "job_type": incident.job_type if incident else None,
            "environment": incident.environment if incident else None,
            "error_code": incident.error_code if incident else None
        }
    )

    return {
        "workflow_stage": WorkflowStage.TRIAGE,
        "current_agent": "triage",
        "updated_at": datetime.now(timezone.utc)
    }


async def suppress_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Suppress duplicate incident.

    Links to parent and closes.
    """
    triage = state.get("triage_result")
    parent_id = triage.deduplication.parent_id if triage else "unknown"

    return {
        "workflow_stage": WorkflowStage.RESOLUTION,
        "resolution_summary": f"Duplicate of {parent_id} - suppressed",
        "incident_closed": True,
        "closed_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }


async def escalate_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Escalate to human review.

    Sets flags and notifies support team.
    """
    return {
        "workflow_stage": WorkflowStage.ESCALATED,
        "requires_human_review": True,
        "updated_at": datetime.now(timezone.utc),
        "messages": state.get("messages", []) + [{
            "role": "system",
            "content": "Incident escalated to human review"
        }]
    }


async def auto_approve_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Auto-approve safe proposals.
    """
    from src.graph.state import ApprovalDecision

    return {
        "approval": ApprovalDecision(
            approved=True,
            approver="auto",
            reason="Auto-approved: Low risk, high confidence",
            approved_at=datetime.now(timezone.utc)
        ),
        "workflow_stage": WorkflowStage.EXECUTION,
        "updated_at": datetime.now(timezone.utc)
    }


async def human_approve_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Request human approval.

    In production, this would:
    - Send notification (Teams, email)
    - Wait for response (with timeout)
    - Return approval decision
    """
    return {
        "awaiting_approval": True,
        "workflow_stage": WorkflowStage.APPROVAL,
        "updated_at": datetime.now(timezone.utc),
        "messages": state.get("messages", []) + [{
            "role": "system",
            "content": "Awaiting human approval for remediation"
        }]
    }


async def rollback_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Handle rollback after failed execution.
    """
    execution = state.get("execution_result")
    rollback_performed = execution.rollback_performed if execution else False

    return {
        "retry_count": state.get("retry_count", 0) + 1,
        "updated_at": datetime.now(timezone.utc),
        "messages": state.get("messages", []) + [{
            "role": "system",
            "content": f"Execution failed. Rollback {'completed' if rollback_performed else 'not performed'}."
        }]
    }


async def retry_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Prepare for retry after verification failure.
    """
    return {
        "retry_count": state.get("retry_count", 0) + 1,
        "workflow_stage": WorkflowStage.DIAGNOSE,
        "updated_at": datetime.now(timezone.utc),
        "messages": state.get("messages", []) + [{
            "role": "system",
            "content": "Verification failed. Retrying diagnosis."
        }]
    }


async def resolve_node(state: AppSupportState) -> Dict[str, Any]:
    """
    Resolve and close the incident.
    Records resolution metrics and feedback in LangSmith.
    """
    incident = state.get("incident")
    incident_id = incident.incident_id if incident else "unknown"
    diagnostic = state.get("diagnostic_result")
    root_cause = diagnostic.root_cause.description if diagnostic else "Unknown"
    start_time = state.get("created_at", datetime.now(timezone.utc))

    # Calculate resolution duration
    end_time = datetime.now(timezone.utc)
    duration_seconds = (end_time - start_time).total_seconds()

    # Record resolution metrics
    job_type = incident.job_type if incident else "unknown"
    resolution_type = "automated" if not state.get("requires_human_review") else "assisted"
    metrics.incidents_resolved.labels(
        job_type=job_type,
        resolution_type=resolution_type,
        automated="true" if resolution_type == "automated" else "false"
    ).inc()

    metrics.incident_duration.labels(
        job_type=job_type,
        resolution_type=resolution_type
    ).observe(duration_seconds)

    # Decrement active incidents
    severity = state.get("triage_result").severity.value if state.get("triage_result") else "P3"
    metrics.active_incidents.labels(severity=severity).dec()

    # Audit the resolution
    audit.log(
        event_type=AuditEventType.INCIDENT_RESOLVED,
        action="Incident resolved",
        incident_id=incident_id,
        details={
            "root_cause": root_cause[:200] if root_cause else None,
            "resolution_type": resolution_type,
            "duration_seconds": duration_seconds,
            "required_human": state.get("requires_human_review", False)
        }
    )

    # Record resolution feedback in LangSmith for learning
    langsmith = get_langsmith()
    if langsmith.enabled:
        langsmith.record_resolution_outcome(
            run_id=state.get("langsmith_run_id", "unknown"),
            success=True,
            resolution_type=resolution_type,
            human_override=state.get("requires_human_review", False)
        )

    return {
        "workflow_stage": WorkflowStage.RESOLUTION,
        "resolution_summary": f"Resolved. Root cause: {root_cause}",
        "incident_closed": True,
        "closed_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }


# =============================================================================
# Workflow Builder
# =============================================================================

def create_workflow(
    triage_agent: BaseAgent,
    diagnose_agent: BaseAgent,
    proposal_agent: BaseAgent,
    execution_agent: BaseAgent,
    verification_agent: BaseAgent,
    checkpointer: Optional[PostgresSaver] = None
) -> StateGraph:
    """
    Create the LangGraph workflow.

    Args:
        triage_agent: Agent for triage
        diagnose_agent: Agent for diagnosis
        proposal_agent: Agent for proposal generation
        execution_agent: Agent for execution
        verification_agent: Agent for verification
        checkpointer: Optional PostgreSQL checkpointer

    Returns:
        Compiled StateGraph
    """
    # Create graph
    workflow = StateGraph(AppSupportState)

    # Add nodes
    workflow.add_node("intake", intake_node)
    workflow.add_node("triage", triage_agent)
    workflow.add_node("suppress", suppress_node)
    workflow.add_node("diagnose", diagnose_agent)
    workflow.add_node("proposal", proposal_agent)
    workflow.add_node("auto_approve", auto_approve_node)
    workflow.add_node("human_approve", human_approve_node)
    workflow.add_node("execute", execution_agent)
    workflow.add_node("verify", verification_agent)
    workflow.add_node("rollback", rollback_node)
    workflow.add_node("retry", retry_node)
    workflow.add_node("resolve", resolve_node)
    workflow.add_node("escalate", escalate_node)

    # Set entry point
    workflow.set_entry_point("intake")

    # Add edges
    workflow.add_edge("intake", "triage")

    # Conditional routing after triage
    workflow.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "suppress": "suppress",
            "diagnose": "diagnose",
            "proposal": "proposal",
            "escalate": "escalate"
        }
    )

    # Suppress goes to end
    workflow.add_edge("suppress", END)

    # Conditional routing after diagnose
    workflow.add_conditional_edges(
        "diagnose",
        route_after_diagnose,
        {
            "proposal": "proposal",
            "escalate": "escalate"
        }
    )

    # Conditional routing after proposal
    workflow.add_conditional_edges(
        "proposal",
        route_after_proposal,
        {
            "auto_approve": "auto_approve",
            "human_approve": "human_approve",
            "escalate": "escalate"
        }
    )

    # After approval nodes
    workflow.add_conditional_edges(
        "auto_approve",
        route_after_approval,
        {
            "execute": "execute",
            "escalate": "escalate"
        }
    )

    workflow.add_conditional_edges(
        "human_approve",
        route_after_approval,
        {
            "execute": "execute",
            "escalate": "escalate"
        }
    )

    # Conditional routing after execution
    workflow.add_conditional_edges(
        "execute",
        route_after_execution,
        {
            "verify": "verify",
            "rollback": "rollback"
        }
    )

    # After rollback
    workflow.add_edge("rollback", "escalate")

    # Conditional routing after verification
    workflow.add_conditional_edges(
        "verify",
        route_after_verification,
        {
            "resolve": "resolve",
            "retry": "retry",
            "escalate": "escalate"
        }
    )

    # Retry goes back to diagnose
    workflow.add_edge("retry", "diagnose")

    # End states
    workflow.add_edge("resolve", END)
    workflow.add_edge("escalate", END)

    # Compile with checkpointer
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)

    return workflow.compile()


def create_checkpointer() -> Optional[PostgresSaver]:
    """
    Create PostgreSQL checkpointer for workflow state persistence.

    Returns:
        PostgresSaver if configured, None otherwise
    """
    settings = get_settings()

    if not settings.database_url:
        return None

    try:
        return PostgresSaver.from_conn_string(settings.database_url)
    except Exception:
        return None


# =============================================================================
# Workflow Runner
# =============================================================================

class WorkflowRunner:
    """
    High-level interface for running the support workflow.

    Provides LangSmith tracing for complete incident lifecycle.
    """

    def __init__(
        self,
        workflow: StateGraph,
        tool_registry: ToolRegistry
    ):
        """
        Initialize runner.

        Args:
            workflow: Compiled workflow
            tool_registry: Tool registry
        """
        self.workflow = workflow
        self.tool_registry = tool_registry
        self.langsmith = get_langsmith()

    async def process_incident(
        self,
        incident_data: Dict[str, Any]
    ) -> AppSupportState:
        """
        Process an incident through the workflow with full LangSmith tracing.

        Args:
            incident_data: Raw incident data from Service Bus

        Returns:
            Final workflow state
        """
        from src.graph.state import Incident

        # Create incident object
        incident = Incident(**incident_data)

        # Create initial state
        initial_state = create_initial_state(incident)

        # Run workflow with LangSmith tracing
        with self.langsmith.trace_incident(
            incident_id=incident.incident_id,
            job_name=incident.job_name,
            job_type=incident.job_type,
            environment=incident.environment,
            source_system=incident.source_system
        ) as run:
            try:
                config = {"configurable": {"thread_id": incident.incident_id}}

                # Store run ID in state for later reference
                initial_state["langsmith_run_id"] = run.run_id

                final_state = await self.workflow.ainvoke(initial_state, config)

                # Record classification info in LangSmith
                triage = final_state.get("triage_result")
                if triage:
                    run.record_classification(
                        category=triage.classification.category.value,
                        confidence=triage.classification.hypothesis_confidence,
                        is_known_issue=triage.classification.is_known_issue
                    )
                    run.record_severity(triage.severity.value)

                # Record remediation outcome
                if final_state.get("incident_closed"):
                    run.record_remediation(
                        actions=[],  # Could populate from execution_result
                        success=True,
                        automated=not final_state.get("requires_human_review", False)
                    )

                run.add_outputs({
                    "resolution_summary": final_state.get("resolution_summary"),
                    "incident_closed": final_state.get("incident_closed"),
                    "requires_human_review": final_state.get("requires_human_review")
                })

                return final_state

            except Exception as e:
                run.set_error(str(e))
                raise

    async def resume_workflow(
        self,
        thread_id: str,
        updates: Optional[Dict[str, Any]] = None
    ) -> AppSupportState:
        """
        Resume a paused workflow (e.g., after human approval).

        Args:
            thread_id: Workflow thread ID
            updates: Optional state updates (e.g., approval decision)

        Returns:
            Final workflow state
        """
        config = {"configurable": {"thread_id": thread_id}}

        # Get current state
        current_state = await self.workflow.aget_state(config)

        # Apply updates
        if updates:
            current_state.update(updates)

        # Continue workflow
        final_state = await self.workflow.ainvoke(current_state, config)

        return final_state

    async def get_workflow_state(
        self,
        thread_id: str
    ) -> Optional[AppSupportState]:
        """
        Get current state of a workflow.

        Args:
            thread_id: Workflow thread ID

        Returns:
            Current state or None
        """
        config = {"configurable": {"thread_id": thread_id}}
        try:
            return await self.workflow.aget_state(config)
        except Exception:
            return None
