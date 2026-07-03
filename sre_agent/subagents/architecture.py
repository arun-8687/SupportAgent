"""
Architecture subagent.

Maps the affected resource's place in the topology: what it depends on,
what depends on it, and the blast radius if it degrades. Live mode would
walk Azure Resource Graph / service maps; mock mode uses a representative
topology so investigations run end-to-end locally.
"""
from typing import Dict, List

from sre_agent.models import Evidence, Incident, SubagentFinding
from sre_agent.subagents.base import Subagent

# Representative dependency map used when no live topology source is wired up.
MOCK_TOPOLOGY: Dict[str, Dict[str, List[str]]] = {
    "default": {
        "depends_on": ["azure-sql-orders", "redis-cache", "servicebus-orders"],
        "consumed_by": ["checkout-frontend", "order-history-api"],
    }
}


class ArchitectureSubagent(Subagent):
    name = "architecture"
    description = (
        "You understand the system topology: dependencies, consumers, and "
        "blast radius of the affected resource."
    )

    async def collect(self, incident: Incident) -> List[Evidence]:
        topology = MOCK_TOPOLOGY.get(incident.service_name, MOCK_TOPOLOGY["default"])
        return [
            Evidence(
                source="resource_graph",
                observation=(
                    f"{incident.service_name} depends on: {', '.join(topology['depends_on'])}"
                ),
                data={"depends_on": topology["depends_on"]},
            ),
            Evidence(
                source="resource_graph",
                observation=(
                    f"{incident.service_name} is consumed by: {', '.join(topology['consumed_by'])}"
                ),
                data={"consumed_by": topology["consumed_by"]},
            ),
        ]

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        consumers: List[str] = []
        for item in evidence:
            consumers.extend(item.data.get("consumed_by", []))
        return SubagentFinding(
            subagent=self.name,
            summary=(
                f"Blast radius: {len(consumers)} downstream consumer(s) "
                f"({', '.join(consumers) or 'none'}) are affected if "
                f"{incident.service_name} degrades."
            ),
            suspected_cause=None,
            confidence=0.6,
        )
