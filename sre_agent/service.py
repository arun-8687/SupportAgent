"""
SREAgentService — the high-level API over the graph.

Two entry points, both event-shaped:

  handle_alert(payload)                -> run a new investigation; if the
                                          permission gate pauses for human
                                          approval, returns the approval
                                          request instead of a final state.
  submit_approval(incident_id, ...)    -> resume a paused investigation
                                          with the human decision.

The Service Bus listener, the Azure Functions trigger, and the CLI all go
through this service, so every trigger surface behaves identically.
"""
import logging
from typing import Any, Dict, Optional

from langgraph.types import Command

from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.graph.state import create_initial_state
from sre_agent.graph.workflow import build_workflow
from sre_agent.integrations.normalizers import normalize, to_incident

logger = logging.getLogger(__name__)


class SREAgentService:
    """Singleton-style facade used by all triggers."""

    def __init__(self, nodes: Optional[SREAgentNodes] = None, checkpointer=None) -> None:
        self.graph = build_workflow(nodes=nodes, checkpointer=checkpointer)

    async def handle_alert(
        self, payload: Dict[str, Any], source_hint: str = ""
    ) -> Dict[str, Any]:
        """Normalize an alert payload and run the investigation graph."""
        alert = normalize(payload, source_hint)
        incident = to_incident(alert)
        logger.info(
            "Handling alert %s -> incident %s (%s)",
            alert.alert_id, incident.incident_id, incident.service_name,
        )

        config = {"configurable": {"thread_id": incident.incident_id}}
        state = await self.graph.ainvoke(create_initial_state(incident), config)

        interrupts = state.get("__interrupt__")
        if interrupts:
            request = interrupts[0].value
            logger.info(
                "Incident %s awaiting approval (%d proposed actions)",
                incident.incident_id, len(request.get("actions", [])),
            )
            return {
                "incident_id": incident.incident_id,
                "status": "awaiting_approval",
                "approval_request": request,
            }

        return self._final_view(incident.incident_id, state)

    async def submit_approval(
        self,
        incident_id: str,
        approved: bool,
        approver: str = "unknown",
        reason: str = "",
        channel: str = "http",
    ) -> Dict[str, Any]:
        """Resume an investigation paused at the permission gate."""
        config = {"configurable": {"thread_id": incident_id}}
        state = await self.graph.ainvoke(
            Command(
                resume={
                    "approved": approved,
                    "approver": approver,
                    "reason": reason,
                    "channel": channel,
                }
            ),
            config,
        )
        return self._final_view(incident_id, state)

    async def get_status(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Inspect a running/paused/finished incident thread."""
        config = {"configurable": {"thread_id": incident_id}}
        snapshot = await self.graph.aget_state(config)
        if snapshot is None or not snapshot.values:
            return None
        values = snapshot.values
        return {
            "incident_id": incident_id,
            "status": str(values.get("status", "unknown")),
            "pending": bool(snapshot.next),
            "resolution_summary": values.get("resolution_summary"),
        }

    @staticmethod
    def _final_view(incident_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        rca = state.get("root_cause")
        ticket = state.get("ticket")
        return {
            "incident_id": incident_id,
            "status": str(getattr(state.get("status"), "value", state.get("status"))),
            "root_cause": rca.hypothesis if rca else None,
            "root_cause_confidence": rca.confidence if rca else None,
            "ticket_id": ticket.ticket_id if ticket else None,
            "resolution_summary": state.get("resolution_summary"),
            "knowledge_record_id": state.get("knowledge_record_id"),
        }
