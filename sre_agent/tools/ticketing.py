"""
Incident-platform ticketing.

Creates/updates tickets with the full investigation summary and proposed
mitigations, mirroring how Azure SRE Agent surfaces its work in ServiceNow,
PagerDuty, or an incident channel. The console backend prints the ticket,
useful for local dev and as the default sink.
"""
import logging
import uuid
from typing import Optional

from sre_agent.config import get_settings
from sre_agent.models import TicketRecord

logger = logging.getLogger(__name__)


class TicketClient:
    """Create and update incident tickets on the configured platform."""

    def __init__(self, platform: Optional[str] = None) -> None:
        self.platform = platform or get_settings().ticket_platform

    async def create_ticket(self, title: str, body: str, severity: str) -> TicketRecord:
        if self.platform == "servicenow":
            return await self._servicenow_create(title, body, severity)
        if self.platform == "pagerduty":
            return await self._pagerduty_create(title, body, severity)
        return self._console_create(title, body, severity)

    async def update_ticket(self, ticket: TicketRecord, note: str, status: str) -> TicketRecord:
        if self.platform == "servicenow":
            return await self._servicenow_update(ticket, note, status)
        logger.info("[ticket %s] status=%s\n%s", ticket.ticket_id, status, note)
        ticket.status = status
        return ticket

    # ------------------------------------------------------------------ #

    def _console_create(self, title: str, body: str, severity: str) -> TicketRecord:
        ticket_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        logger.info("[ticket %s] (%s) %s\n%s", ticket_id, severity, title, body)
        return TicketRecord(ticket_id=ticket_id, platform="console", status="open")

    async def _servicenow_create(self, title: str, body: str, severity: str) -> TicketRecord:
        settings = get_settings()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"https://{settings.servicenow_instance}.service-now.com/api/now/table/incident",
                    auth=(settings.servicenow_user or "", settings.servicenow_password or ""),
                    json={
                        "short_description": title,
                        "description": body,
                        "urgency": {"sev1": "1", "sev2": "2"}.get(severity, "3"),
                    },
                )
                resp.raise_for_status()
                record = resp.json()["result"]
                return TicketRecord(
                    ticket_id=record["number"],
                    platform="servicenow",
                    url=f"https://{settings.servicenow_instance}.service-now.com/incident.do?sys_id={record['sys_id']}",
                    status="open",
                )
        except Exception:
            logger.exception("ServiceNow ticket creation failed; using console fallback")
            return self._console_create(title, body, severity)

    async def _servicenow_update(self, ticket: TicketRecord, note: str, status: str) -> TicketRecord:
        settings = get_settings()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.patch(
                    f"https://{settings.servicenow_instance}.service-now.com/api/now/table/incident/{ticket.ticket_id}",
                    auth=(settings.servicenow_user or "", settings.servicenow_password or ""),
                    json={"work_notes": note, "state": "6" if status == "resolved" else "2"},
                )
                resp.raise_for_status()
        except Exception:
            logger.exception("ServiceNow ticket update failed")
        ticket.status = status
        return ticket

    async def _pagerduty_create(self, title: str, body: str, severity: str) -> TicketRecord:
        settings = get_settings()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.pagerduty.com/incidents",
                    headers={
                        "Authorization": f"Token token={settings.pagerduty_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "incident": {
                            "type": "incident",
                            "title": title,
                            "service": {
                                "id": settings.pagerduty_service_id,
                                "type": "service_reference",
                            },
                            "urgency": "high" if severity in ("sev1", "sev2") else "low",
                            "body": {"type": "incident_body", "details": body},
                        }
                    },
                )
                resp.raise_for_status()
                incident = resp.json()["incident"]
                return TicketRecord(
                    ticket_id=incident["id"],
                    platform="pagerduty",
                    url=incident.get("html_url"),
                    status="open",
                )
        except Exception:
            logger.exception("PagerDuty incident creation failed; using console fallback")
            return self._console_create(title, body, severity)
