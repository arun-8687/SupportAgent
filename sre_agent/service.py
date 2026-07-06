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
from sre_agent.incident_index import create_incident_index
from sre_agent.integrations.normalizers import normalize, to_incident
from sre_agent.observability import configure_telemetry, log_step
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
        incident_index=None,
    ) -> None:
        configure_telemetry()  # idempotent; every trigger surface passes here
        self.graph = build_workflow(nodes=nodes, checkpointer=checkpointer)
        self.alert_ledger = alert_ledger or create_alert_ledger()
        self.pending_approvals = pending_approvals or create_pending_approval_store()
        # Queryable list-all-incidents surface for the monitoring UI. Mirrors
        # pending_approvals: sync upserts at the intake/approval chokepoints.
        self.incident_index = incident_index or create_incident_index()

    def register_alert(
        self, payload: Dict[str, Any], source_hint: str = ""
    ) -> Dict[str, Any]:
        """Phase 1 of intake: normalize + claim (fast, no LLM/graph work).

        Split from the investigation so triggers can acknowledge the
        message only AFTER the alert is durably claimed (with its payload
        stored for crash recovery), closing the ack-then-crash loss window.

        Returns {"action": "investigate", "incident": ...} or
        {"action": "skip", "response": {...}}.
        """
        alert = normalize(payload, source_hint)
        incident = to_incident(alert)

        # Idempotent intake: Service Bus delivers at-least-once. The claim
        # is atomic and stores the raw payload until the investigation
        # reaches a durable state, so no crash window drops the alert.
        storm_key = f"{incident.service_name}:{alert.title[:80].lower()}"
        claim = self.alert_ledger.claim(
            alert.alert_id, incident.incident_id, storm_key, payload=payload
        )

        if claim.status == "duplicate" and not claim.processed:
            # The earlier attempt crashed mid-investigation. Reclaim under
            # a fresh incident and investigate again — a redelivered alert
            # must never be silently dropped as "duplicate".
            self.alert_ledger.reclaim(alert.alert_id, incident.incident_id)
            log_step(
                "alert_intake", "reclaimed", incident.incident_id,
                alert_id=alert.alert_id, previous_incident=claim.incident_id,
                level=logging.WARNING,
            )
            self._index_intake(incident, alert, "received")
            return {"action": "investigate", "incident": incident, "alert": alert}

        if claim.status == "duplicate":
            log_step(
                "alert_intake", "duplicate", claim.incident_id,
                alert_id=alert.alert_id, service_name=incident.service_name,
            )
            return {
                "action": "skip",
                "response": {
                    "incident_id": claim.incident_id,
                    "status": "duplicate",
                    "note": "Alert already processed; no new investigation started.",
                },
            }
        if claim.status == "storm":
            log_step(
                "alert_intake", "storm_suppressed", claim.incident_id,
                alert_id=alert.alert_id, storm_key=storm_key,
                level=logging.WARNING,
            )
            note = "Storm threshold exceeded for this service+alert; suppressed."
            if claim.incident_id:
                note += f" See parent incident {claim.incident_id}."
            return {
                "action": "skip",
                "response": {
                    "incident_id": claim.incident_id,
                    "status": "storm_suppressed",
                    "note": note,
                },
            }

        log_step(
            "alert_intake", "accepted", incident.incident_id,
            alert_id=alert.alert_id, service_name=incident.service_name,
            source=alert.source.value, environment=incident.environment,
        )
        self._index_intake(incident, alert, "received")
        return {"action": "investigate", "incident": incident, "alert": alert}

    def _index_intake(self, incident, alert, status: str) -> None:
        """Upsert the descriptive index row at intake (best-effort).

        The index is a UI convenience surface, never on the investigation's
        critical path — a failure here must not drop an alert.
        """
        try:
            self.incident_index.upsert(
                incident.incident_id,
                app_code=incident.app_code,
                service_name=incident.service_name,
                severity=getattr(incident.severity, "value", incident.severity),
                environment=incident.environment,
                title=alert.title,
                status=status,
            )
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to upsert incident index for %s", incident.incident_id)

    def _index_status(self, incident_id: str, **fields_: Any) -> None:
        """Upsert terminal/awaiting-approval status onto the index row."""
        try:
            self.incident_index.upsert(incident_id, **fields_)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to upsert incident index for %s", incident_id)

    def _index_terminal(self, incident_id: str, view: Dict[str, Any]) -> None:
        """Upsert the resolved/terminal state from a final view."""
        self._index_status(
            incident_id,
            status=view.get("status"),
            awaiting_approval=False,
            ticket_id=view.get("ticket_id"),
            resolution_summary=view.get("resolution_summary"),
        )

    async def run_registered(self, registration: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2 of intake: run the investigation for a claimed alert."""
        if registration["action"] == "skip":
            return registration["response"]

        incident = registration["incident"]
        alert = registration["alert"]
        config = {"configurable": {"thread_id": incident.incident_id}}
        state = await self.graph.ainvoke(create_initial_state(incident), config)

        interrupts = state.get("__interrupt__")
        if interrupts:
            request = interrupts[0].value
            # Register for the timeout sweeper so a paused investigation
            # can't hang forever waiting for a human. The checkpoint is
            # durable, so the claim counts as processed.
            self.pending_approvals.add(incident.incident_id)
            self.alert_ledger.mark_processed(alert.alert_id)
            log_step(
                "approval_request", "pending", incident.incident_id,
                actions=len(request.get("actions", [])),
            )
            self._index_status(
                incident.incident_id,
                status="awaiting_approval", awaiting_approval=True,
            )
            return {
                "incident_id": incident.incident_id,
                "status": "awaiting_approval",
                "approval_request": request,
            }

        self.alert_ledger.mark_processed(alert.alert_id)
        view = self._final_view(incident.incident_id, state)
        self._index_terminal(incident.incident_id, view)
        return view

    async def handle_alert(
        self, payload: Dict[str, Any], source_hint: str = ""
    ) -> Dict[str, Any]:
        """Normalize, claim, and investigate in one call (Functions/CLI)."""
        return await self.run_registered(self.register_alert(payload, source_hint))

    async def recover_stalled_intakes(self) -> List[Dict[str, Any]]:
        """Re-run claims that never reached a durable state.

        Covers the message-already-acked crash: the graph died mid-run, no
        redelivery will come, but the claim kept the raw payload. Called by
        the same sweeps as approval timeouts.
        """
        settings = get_settings()
        results = []
        for intake in self.alert_ledger.stalled(settings.intake_stale_seconds):
            if not intake.payload:
                # Nothing to replay from; surface loudly instead of looping.
                log_step(
                    "alert_intake", "unrecoverable", intake.incident_id,
                    alert_id=intake.alert_id, level=logging.ERROR,
                )
                self.alert_ledger.mark_processed(intake.alert_id)
                continue
            log_step(
                "alert_intake", "recovering_stalled", intake.incident_id,
                alert_id=intake.alert_id, level=logging.WARNING,
            )
            # handle_alert sees duplicate-unprocessed -> reclaims -> re-runs.
            results.append(await self.handle_alert(intake.payload))
        return results

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

        log_step(
            "approval_decision", "approved" if approved else "rejected",
            incident_id, approver=approver, channel=channel,
            verified=approver_verified,
        )
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
        view = self._final_view(incident_id, state)
        self._index_terminal(incident_id, view)
        return view

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
            log_step(
                "approval_timeout", "escalating", incident_id,
                timeout_seconds=settings.approval_timeout_seconds,
                level=logging.WARNING,
            )
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
