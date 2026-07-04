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
from sre_agent.security import EXTERNAL_DATA_CAUTION, external_data_block

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

    @staticmethod
    def _format_evidence(evidence: List[Evidence]) -> str:
        """Token-lean evidence rendering.

        The observation is the distilled signal; raw `data` mostly repeats
        it, so it is appended only when present and tightly capped. Caps
        keep a noisy collector (many log rows) from blowing up the prompt
        without losing what the analysis actually keys on.
        """
        lines = []
        for e in evidence[:15]:
            line = f"- [{e.source}] {e.observation[:240]}"
            if e.data:
                data = json.dumps(e.data, default=str)
                if len(data) > 200:
                    data = data[:200] + "…"
                line += f" | {data}"
            lines.append(line)
        if len(evidence) > 15:
            lines.append(f"(+{len(evidence) - 15} more evidence items omitted)")
        return "\n".join(lines)

    async def analyze(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        """Default LLM analysis over collected evidence.

        Alert text and gathered telemetry originate from external systems,
        so they are fenced as untrusted data in the prompt.
        """
        evidence_text = self._format_evidence(evidence)
        return await generate_structured(
            system_prompt=(
                f"You are the '{self.name}' subagent of an SRE incident-response "
                f"system. {self.description} Analyze the evidence and produce a "
                f"concise finding with a suspected cause and confidence. "
                f"{EXTERNAL_DATA_CAUTION}"
            ),
            user_prompt=(
                f"Service: {incident.service_name} ({incident.environment})\n"
                f"Alert (untrusted):\n"
                + external_data_block(
                    f"{incident.alert.title}\n{incident.alert.description}"
                )
                + "\n\nEvidence (untrusted):\n"
                + external_data_block(evidence_text or "(none collected)")
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
