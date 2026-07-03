"""
SREAgentService — the high-level API over the graph.

Entry points, all event-shaped:

  handle_alert(payload)              -> idempotent intake (duplicate and
                                        storm-suppressed alerts never spawn
                                        investigations), then run the graph;
                                        pauses at the permission gate return
                                        the approval request.
  submit_approval(incident_id, ...)  -> resume a paused investigation with
                                        the human decision (graceful when
                                        the incident is unknown/expired).
  sweep_expired_approvals()          -> escalate investigations that waited
                                        longer than the approval timeout.

The Service Bus listener, the Azure Functions triggers, and the CLI all go
through this service, so every trigger surface behaves identically.
"""
import logging
from typing import Any, Dict, List, Optional

from langgraph.types import Command

from sre_agent.config import get_settings
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.graph.state import create_initial_state
from sre_agent.graph.workflow import build_workflow
from sre_agent.integrations.normalizers import normalize, to_incident
from sre_agent.stores import create_alert_ledger, create_pending_approval_store

logger = logging.getLogger(__name__)


class SREAgentService:
    """Singleton-style facade used by all triggers."""

    def __init__(
        self,
        nodes: Optional[SREAgentNodes] = None,
        checkpointer=None,
        alert_ledger=None,
        pending_approvals=None,
    ) -> None:
        self.graph = build_workflow(nodes=nodes, checkpointer=checkpointer)
        self.alert_ledger = alert_ledger or create_alert_ledger()
        self.pending_approvals = pending_approvals or create_pending_approval_store()

    async def handle_alert(
        self, payload: Dict[str, Any], source_hint: str = ""
    ) -> Dict[str, Any]:
        """Normalize an alert payload and run the investigation graph."""
        alert = normalize(payload, source_hint)
        incident = to_incident(alert)

        # Idempotent intake: Service Bus delivers at-least-once, so the same
        # alert_id can arrive again (lock expiry, crash, retry). The ledger
        # claim is atomic — redeliveries map back to the original incident
        # instead of spawning a duplicate investigation and ticket.
        storm_key = f"{incident.service_name}:{alert.title[:80].lower()}"
        claim = self.alert_ledger.claim(alert.alert_id, incident.incident_id, storm_key)
        if claim.status == "duplicate":
            logger.info(
                "Alert %s already claimed by incident %s; skipping",
                alert.alert_id, claim.incident_id,
            )
            return {
                "incident_id": claim.incident_id,
                "status": "duplicate",
                "note": "Alert already processed; no new investigation started.",
            }
        if claim.status == "storm":
            logger.warning(
                "Alert storm on %s; suppressing (parent incident %s)",
                storm_key, claim.incident_id,
            )
            return {
                "incident_id": claim.incident_id,
                "status": "storm_suppressed",
                "note": (
                    "Storm threshold exceeded for this service+alert; suppressed. "
                    f"See parent incident {claim.incident_id}."
                ),
            }

        logger.info(
            "Handling alert %s -> incident %s (%s)",
            alert.alert_id, incident.incident_id, incident.service_name,
        )
        config = {"configurable": {"thread_id": incident.incident_id}}
        state = await self.graph.ainvoke(create_initial_state(incident), config)

        interrupts = state.get("__interrupt__")
        if interrupts:
            request = interrupts[0].value
            # Register for the timeout sweeper so a paused investigation
            # can't hang forever waiting for a human.
            self.pending_approvals.add(incident.incident_id)
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
        approver_verified: bool = False,
    ) -> Dict[str, Any]:
        """Resume an investigation paused at the permission gate."""
        settings = get_settings()
        if settings.verified_identity_required and not approver_verified:
            return {
                "incident_id": incident_id,
                "status": "rejected_unverified_approver",
                "note": (
                    "Approval requires a verified identity (Entra/Easy Auth). "
                    "Client-supplied approver names are not accepted."
                ),
            }

        config = {"configurable": {"thread_id": incident_id}}
        # Graceful handling for unknown/expired incidents: an approval
        # message for a thread that never paused (or was already resumed)
        # must not crash the trigger.
        try:
            snapshot = await self.graph.aget_state(config)
        except Exception:
            snapshot = None
        if snapshot is None or not snapshot.values or not snapshot.next:
            logger.warning("Approval for unknown/not-pending incident %s", incident_id)
            return {
                "incident_id": incident_id,
                "status": "unknown_or_not_pending",
                "note": "No investigation is awaiting approval under this id.",
            }

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
        self.pending_approvals.remove(incident_id)
        return self._final_view(incident_id, state)

    async def sweep_expired_approvals(self) -> List[Dict[str, Any]]:
        """Escalate investigations that outlived the approval timeout.

        Called periodically (timer trigger / listener loop). Timing out is
        a rejection with a clear reason — the escalation path updates the
        ticket and fires on_escalation hooks so a human gets re-paged.
        """
        settings = get_settings()
        results = []
        for incident_id in self.pending_approvals.expired(
            settings.approval_timeout_seconds
        ):
            logger.warning("Approval timed out for incident %s; escalating", incident_id)
            result = await self.submit_approval(
                incident_id=incident_id,
                approved=False,
                approver="approval-timeout-sweeper",
                reason=(
                    f"No human decision within {settings.approval_timeout_seconds}s; "
                    "auto-escalated."
                ),
                channel="sweeper",
                approver_verified=True,  # system principal, not client input
            )
            # Whatever the outcome, stop tracking it.
            self.pending_approvals.remove(incident_id)
            results.append(result)
        return results

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
