"""
Logs & metrics subagent.

Queries the observability stack (Azure Monitor metrics + Log Analytics)
for the incident window, looking for anomalous trends and error bursts —
the "identifies a memory trend that started 40 minutes before the alert"
part of the investigation.
"""
from typing import List

from sre_agent.models import Evidence, Incident, SubagentFinding
from sre_agent.subagents.base import Subagent
from sre_agent.tools.observability import ObservabilityClient

DEFAULT_METRICS = ["MemoryWorkingSet", "CpuPercentage", "Http5xx", "ResponseTime"]

ERROR_LOG_QUERY = """
AppTraces
| where SeverityLevel >= 3
| summarize count() by Message = tostring(Message), bin(TimeGenerated, 5m)
| order by TimeGenerated desc
| take 50
"""


class LogsMetricsSubagent(Subagent):
    name = "logs_metrics"
    description = (
        "You investigate telemetry: metric trends, error-log bursts, and "
        "anomalies in the window before the alert fired."
    )

    def __init__(self, client: ObservabilityClient | None = None) -> None:
        self.client = client or ObservabilityClient()

    async def collect(self, incident: Incident) -> List[Evidence]:
        evidence: List[Evidence] = []
        resource_id = incident.alert.resource.resource_id

        metrics = await self.client.query_metrics(resource_id, DEFAULT_METRICS)
        for name, series in metrics.items():
            if not series:
                continue
            first, last = series[0]["value"], series[-1]["value"]
            trend = "rising" if last > first * 1.3 else "flat"
            evidence.append(
                Evidence(
                    source="azure_monitor",
                    observation=(
                        f"Metric {name}: {first} -> {last} over window ({trend})"
                    ),
                    data={"metric": name, "first": first, "last": last, "points": len(series)},
                )
            )

        logs = await self.client.query_logs(resource_id, ERROR_LOG_QUERY)
        for row in logs[:10]:
            evidence.append(
                Evidence(
                    source="log_analytics",
                    observation=f"{row.get('level', 'Error')}: {row.get('message', '')} (x{row.get('count', 1)})",
                    data=row,
                )
            )
        return evidence

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        rising = [e for e in evidence if "rising" in e.observation]
        errors = [e for e in evidence if e.source == "log_analytics"]
        memory_signals = [
            e for e in evidence
            if "memory" in e.observation.lower() or "oom" in e.observation.lower()
        ]
        if memory_signals:
            return SubagentFinding(
                subagent=self.name,
                summary=(
                    f"Detected {len(rising)} rising metric trend(s) and "
                    f"{len(errors)} error-log signal(s); memory pressure indicators present "
                    f"(e.g. '{memory_signals[0].observation[:120]}')."
                ),
                suspected_cause="Memory pressure / leak in the service leading to OOM restarts",
                confidence=0.75,
            )
        if rising:
            return SubagentFinding(
                subagent=self.name,
                summary=f"{len(rising)} metric(s) trending upward before the alert window.",
                suspected_cause="Resource saturation trend preceding the alert",
                confidence=0.5,
            )
        return super().heuristic_finding(incident, evidence)
