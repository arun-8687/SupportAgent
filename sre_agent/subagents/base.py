"""
Subagent base class.

Subagents are purpose-built investigators for one operational domain.
Each follows the same two-phase shape:

  collect()  -> gather raw evidence with domain tools (deterministic)
  analyze()  -> turn evidence into a finding (LLM-backed, with a
                deterministic heuristic fallback so the workflow runs
                without an LLM configured)

Custom subagents subclass this and register themselves in the
SubagentRegistry — the planner can then select them for investigations.
"""
import json
import logging
from abc import ABC, abstractmethod
from typing import List

from sre_agent.llm import generate_structured
from sre_agent.models import Evidence, Incident, SubagentFinding

logger = logging.getLogger(__name__)


class Subagent(ABC):
    """Base class for all investigation subagents."""

    name: str = "subagent"
    description: str = ""

    async def investigate(self, incident: Incident) -> SubagentFinding:
        """Run the full collect -> analyze pipeline for one incident."""
        logger.info("[%s] investigating incident %s", self.name, incident.incident_id)
        try:
            evidence = await self.collect(incident)
        except Exception as exc:
            logger.exception("[%s] evidence collection failed", self.name)
            return SubagentFinding(
                subagent=self.name,
                summary=f"Evidence collection failed: {exc}",
                confidence=0.0,
            )

        finding = await self.analyze(incident, evidence)
        finding.subagent = self.name
        finding.evidence = evidence
        return finding

    @abstractmethod
    async def collect(self, incident: Incident) -> List[Evidence]:
        """Gather raw evidence using domain tools."""

    async def analyze(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        """Default LLM analysis over collected evidence."""
        evidence_text = "\n".join(
            f"- [{e.source}] {e.observation} | data: {json.dumps(e.data, default=str)[:400]}"
            for e in evidence
        )
        return await generate_structured(
            system_prompt=(
                f"You are the '{self.name}' subagent of an SRE incident-response "
                f"system. {self.description} Analyze the evidence and produce a "
                "concise finding with a suspected cause and confidence."
            ),
            user_prompt=(
                f"Incident: {incident.alert.title}\n"
                f"Service: {incident.service_name} ({incident.environment})\n"
                f"Description: {incident.alert.description}\n\n"
                f"Evidence:\n{evidence_text or '(none collected)'}"
            ),
            schema=SubagentFinding,
            fallback=lambda: self.heuristic_finding(incident, evidence),
        )

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        """Deterministic fallback when no LLM is available."""
        return SubagentFinding(
            subagent=self.name,
            summary=f"Collected {len(evidence)} evidence items for {incident.service_name}.",
            confidence=0.3 if evidence else 0.0,
        )
