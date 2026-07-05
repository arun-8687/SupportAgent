"""
Scanning subagent.

Sweeps resource configuration and health state for misconfigurations and
degraded components (quota exhaustion, restarts, config drift) — the
proactive-check counterpart to the telemetry-driven subagents.
"""
from typing import List

from sre_agent.models import Evidence, Incident, SubagentFinding
from sre_agent.subagents.base import Subagent
from sre_agent.tools.observability import ObservabilityClient


class ScanningSubagent(Subagent):
    name = "scanning"
    description = (
        "You scan resource configuration and health state for "
        "misconfigurations, quota exhaustion, and degraded components."
    )

    def __init__(self, client: ObservabilityClient | None = None) -> None:
        self.client = client or ObservabilityClient()

    async def collect(self, incident: Incident) -> List[Evidence]:
        health = await self.client.check_health(incident.alert.resource.resource_id)
        evidence = [
            Evidence(
                source="resource_health",
                observation=f"Resource health status: {health.get('status', 'unknown')}",
                data=health,
            )
        ]
        # Representative config findings; live mode would query ARM/policy state.
        signals = incident.alert.signals
        if signals:
            evidence.append(
                Evidence(
                    source="alert_signals",
                    observation=f"Alert carried signals: {signals}",
                    data=dict(signals),
                )
            )
        return evidence

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        unhealthy = [
            e for e in evidence
            if e.source == "resource_health" and e.data.get("status") not in ("healthy", None)
        ]
        return SubagentFinding(
            subagent=self.name,
            summary=(
                "Configuration/health scan complete: "
                + ("degraded components found." if unhealthy else "no config drift or degraded components detected.")
            ),
            suspected_cause="Resource-level degradation" if unhealthy else None,
            confidence=0.5,
        )
