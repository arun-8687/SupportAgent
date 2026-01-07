"""
Workflow Service - High-level interface for the support agent.

Provides a simplified interface for:
- Processing incidents
- Managing approvals
- Getting status and metrics
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from src.agents.base_agent import AgentConfig
from src.agents.diagnose_agent import DiagnoseAgent
from src.agents.triage_agent import TriageAgent
from src.graph.state import AppSupportState, Incident, WorkflowStage, create_initial_state
from src.graph.workflow import (
    WorkflowRunner,
    create_checkpointer,
    create_workflow,
)
from src.integrations.config import get_settings
from src.integrations.embedding_client import EmbeddingClient
from src.intelligence.correlation import CorrelationEngine, DependencyGraph, ITSMClient
from src.intelligence.deduplication import IncidentDeduplicator
from src.intelligence.knowledge_retrieval import KnowledgeRetriever
from src.storage.vector_store import VectorStore
from src.tools.base import ToolRegistry
from src.tools.databricks_tools import register_databricks_tools


logger = structlog.get_logger()


class WorkflowService:
    """
    High-level service for managing the support agent workflow.
    """

    def __init__(self):
        """Initialize the workflow service with all dependencies."""
        self.settings = get_settings()
        self.logger = logger.bind(service="workflow")

        # Initialize components lazily
        self._initialized = False
        self._workflow = None
        self._runner = None
        self._tool_registry = None
        self._vector_store = None
        self._embedding_client = None

    async def _ensure_initialized(self) -> None:
        """Ensure all components are initialized."""
        if self._initialized:
            return

        self.logger.info("initializing_workflow_service")

        # Initialize embedding client
        self._embedding_client = EmbeddingClient()

        # Initialize vector store
        self._vector_store = VectorStore(
            connection_string=self.settings.database_url,
            embedding_client=self._embedding_client
        )
        await self._vector_store.initialize()

        # Initialize tool registry
        self._tool_registry = ToolRegistry()
        register_databricks_tools(self._tool_registry)

        # Initialize intelligence components
        deduplicator = IncidentDeduplicator(
            embedding_client=self._embedding_client,
            vector_store=self._vector_store,
            similarity_threshold=self.settings.dedup_similarity_threshold,
            time_window_minutes=self.settings.dedup_time_window_minutes,
            storm_threshold=self.settings.event_storm_threshold
        )

        knowledge_retriever = KnowledgeRetriever(
            vector_store=self._vector_store,
            embedding_client=self._embedding_client,
            itsm_client=ITSMClient(
                base_url=self.settings.itsm_base_url,
                username=self.settings.itsm_username,
                password=self.settings.itsm_password
            )
        )

        correlation_engine = CorrelationEngine(
            dependency_graph=DependencyGraph(),
            itsm_client=ITSMClient(
                base_url=self.settings.itsm_base_url,
                username=self.settings.itsm_username,
                password=self.settings.itsm_password
            ),
            time_window_minutes=self.settings.correlation_time_window_minutes
        )

        # Initialize agents
        triage_agent = TriageAgent(
            tool_registry=self._tool_registry,
            deduplicator=deduplicator,
            knowledge_retriever=knowledge_retriever,
            correlation_engine=correlation_engine
        )

        diagnose_agent = DiagnoseAgent(
            tool_registry=self._tool_registry
        )

        # Create placeholder agents for proposal, execution, verification
        # These would be implemented similarly to triage/diagnose
        from src.agents.base_agent import BaseAgent

        class PlaceholderAgent(BaseAgent):
            async def execute(self, state):
                return {"workflow_stage": self.name}

        proposal_agent = PlaceholderAgent(
            AgentConfig(name="proposal", description="Proposal generation"),
            self._tool_registry
        )
        execution_agent = PlaceholderAgent(
            AgentConfig(name="execution", description="Execution"),
            self._tool_registry
        )
        verification_agent = PlaceholderAgent(
            AgentConfig(name="verification", description="Verification"),
            self._tool_registry
        )

        # Create workflow
        checkpointer = create_checkpointer()
        self._workflow = create_workflow(
            triage_agent=triage_agent,
            diagnose_agent=diagnose_agent,
            proposal_agent=proposal_agent,
            execution_agent=execution_agent,
            verification_agent=verification_agent,
            checkpointer=checkpointer
        )

        self._runner = WorkflowRunner(
            workflow=self._workflow,
            tool_registry=self._tool_registry
        )

        self._initialized = True
        self.logger.info("workflow_service_initialized")

    async def process_incident(
        self,
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process an incident through the workflow.

        Args:
            incident_data: Raw incident data from Service Bus or API

        Returns:
            Processing result with incident_id and status
        """
        await self._ensure_initialized()

        # Generate incident ID if not provided
        if "incident_id" not in incident_data:
            incident_data["incident_id"] = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid4())[:8]}"

        # Set timestamp if not provided
        if "failure_timestamp" not in incident_data:
            incident_data["failure_timestamp"] = datetime.utcnow()

        self.logger.info(
            "processing_incident",
            incident_id=incident_data["incident_id"],
            job_name=incident_data.get("job_name")
        )

        try:
            # Run workflow
            final_state = await self._runner.process_incident(incident_data)

            # Store incident in vector store for future similarity search
            await self._vector_store.store_incident(
                incident_id=incident_data["incident_id"],
                job_name=incident_data.get("job_name", ""),
                job_type=incident_data.get("job_type", "unknown"),
                error_message=incident_data.get("error_message", ""),
                error_code=incident_data.get("error_code"),
                metadata=incident_data
            )

            return {
                "incident_id": incident_data["incident_id"],
                "workflow_stage": final_state.get("workflow_stage", WorkflowStage.INTAKE).value
                    if hasattr(final_state.get("workflow_stage"), "value")
                    else str(final_state.get("workflow_stage")),
                "requires_human_review": final_state.get("requires_human_review", False),
                "resolution_summary": final_state.get("resolution_summary"),
                "incident_closed": final_state.get("incident_closed", False)
            }

        except Exception as e:
            self.logger.error(
                "incident_processing_failed",
                incident_id=incident_data["incident_id"],
                error=str(e),
                exc_info=True
            )
            raise

    async def get_incident_status(
        self,
        incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get current status of an incident.

        Args:
            incident_id: The incident ID

        Returns:
            Status dict or None if not found
        """
        await self._ensure_initialized()

        state = await self._runner.get_workflow_state(incident_id)
        if state is None:
            return None

        return {
            "incident_id": incident_id,
            "workflow_stage": state.get("workflow_stage", "unknown"),
            "current_agent": state.get("current_agent"),
            "requires_human_review": state.get("requires_human_review", False),
            "awaiting_approval": state.get("awaiting_approval", False),
            "resolution_summary": state.get("resolution_summary"),
            "incident_closed": state.get("incident_closed", False),
            "created_at": state.get("created_at"),
            "updated_at": state.get("updated_at")
        }

    async def submit_approval(
        self,
        incident_id: str,
        approved: bool,
        approver_id: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Submit approval decision for an incident.

        Args:
            incident_id: The incident ID
            approved: Whether to approve
            approver_id: ID of the approver
            reason: Optional reason

        Returns:
            Updated status
        """
        await self._ensure_initialized()

        from src.graph.state import ApprovalDecision

        approval = ApprovalDecision(
            approved=approved,
            approver="human",
            approver_id=approver_id,
            reason=reason,
            approved_at=datetime.utcnow()
        )

        # Resume workflow with approval
        final_state = await self._runner.resume_workflow(
            thread_id=incident_id,
            updates={
                "approval": approval,
                "awaiting_approval": False
            }
        )

        return {
            "incident_id": incident_id,
            "approval_submitted": True,
            "approved": approved,
            "workflow_stage": str(final_state.get("workflow_stage", "unknown"))
        }

    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """
        Get list of incidents awaiting approval.

        Returns:
            List of pending approval incidents
        """
        await self._ensure_initialized()

        # In production, query database for awaiting_approval=True
        # For now, return empty list
        return []

    async def get_metrics(self) -> Dict[str, Any]:
        """
        Get support agent metrics.

        Returns:
            Metrics dict
        """
        await self._ensure_initialized()

        # In production, calculate real metrics
        return {
            "total_incidents_today": 0,
            "auto_resolved": 0,
            "pending_approval": 0,
            "escalated": 0,
            "average_resolution_time_seconds": 0,
            "automation_rate": 0.0
        }

    async def close(self) -> None:
        """Clean up resources."""
        if self._vector_store:
            await self._vector_store.close()
        if self._embedding_client:
            await self._embedding_client.close()
