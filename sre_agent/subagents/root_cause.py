"""
Root cause analysis subagent.

Unlike the investigators, this subagent synthesizes: it takes all other
subagents' findings and produces a single root-cause hypothesis with
confidence, contributing factors, and the correlated change (if any).
"""
import json
from datetime import datetime
from typing import List, Optional

from sre_agent.llm import generate_structured
from sre_agent.models import (
    CorrelatedChange,
    Incident,
    RootCauseAnalysis,
    SubagentFinding,
)
from sre_agent.security import EXTERNAL_DATA_CAUTION, external_data_block


class RootCauseSubagent:
    """Synthesizes subagent findings into a root cause hypothesis."""

    name = "root_cause"

    # Each subagent already distilled its evidence into summary +
    # suspected_cause; synthesis needs only the strongest supporting lines,
    # not a second full copy of every observation.
    MAX_EVIDENCE_PER_FINDING = 5
    MAX_OBSERVATION_CHARS = 180

    def _format_findings(self, findings: List[SubagentFinding]) -> str:
        sections = []
        for f in findings:
            lines = [
                f"## {f.subagent} (confidence {f.confidence})",
                f.summary[:400],
                f"Suspected cause: {(f.suspected_cause or 'n/a')[:240]}",
            ]
            for e in f.evidence[: self.MAX_EVIDENCE_PER_FINDING]:
                lines.append(f"- [{e.source}] {e.observation[: self.MAX_OBSERVATION_CHARS]}")
            omitted = len(f.evidence) - self.MAX_EVIDENCE_PER_FINDING
            if omitted > 0:
                lines.append(f"(+{omitted} more evidence items)")
            sections.append("\n".join(lines))
        return "\n\n".join(sections)

    async def synthesize(
        self, incident: Incident, findings: List[SubagentFinding]
    ) -> RootCauseAnalysis:
        findings_text = self._format_findings(findings)
        return await generate_structured(
            system_prompt=(
                "You are the root-cause-analysis subagent of an SRE "
                "incident-response system. Synthesize the domain findings into "
                "one hypothesis. Correlate telemetry anomalies with recent "
                f"changes; state impact and contributing factors. "
                f"{EXTERNAL_DATA_CAUTION}"
            ),
            user_prompt=(
                f"Service: {incident.service_name} ({incident.environment}), "
                f"severity {incident.severity.value}\n"
                f"Alert (untrusted):\n{external_data_block(incident.alert.title)}\n\n"
                f"Findings (contain untrusted telemetry):\n"
                + external_data_block(findings_text)
            ),
            schema=RootCauseAnalysis,
            fallback=lambda: self._heuristic(incident, findings),
        )

    def _heuristic(
        self, incident: Incident, findings: List[SubagentFinding]
    ) -> RootCauseAnalysis:
        """Deterministic synthesis: join the strongest suspected causes."""
        causes = [
            (f.confidence, f.suspected_cause, f.subagent)
            for f in findings
            if f.suspected_cause
        ]
        causes.sort(reverse=True, key=lambda item: item[0])

        change = self._extract_change(findings)
        if causes:
            top_conf, top_cause, _ = causes[0]
            hypothesis = top_cause or "Unknown"
            if change and "change" not in (top_cause or "").lower():
                hypothesis += f"; likely introduced by {change.description or change.identifier}"
            confidence = min(0.9, top_conf + 0.05 * (len(causes) - 1))
        else:
            hypothesis = "Insufficient evidence to determine root cause"
            confidence = 0.2

        blast = next(
            (f.summary for f in findings if f.subagent == "architecture"), ""
        )
        return RootCauseAnalysis(
            hypothesis=hypothesis,
            confidence=round(confidence, 2),
            contributing_factors=[c for _, c, _ in causes[1:] if c],
            correlated_change=change,
            impact_assessment=blast,
            evidence_summary=[
                f"{f.subagent}: {f.summary}" for f in findings
            ],
        )

    @staticmethod
    def _extract_change(findings: List[SubagentFinding]) -> Optional[CorrelatedChange]:
        for finding in findings:
            if finding.subagent != "source_code":
                continue
            for evidence in finding.evidence:
                if evidence.source == "deployments":
                    data = evidence.data
                    occurred = None
                    raw_ts = data.get("created_at")
                    if raw_ts:
                        try:
                            occurred = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                        except ValueError:
                            occurred = None
                    return CorrelatedChange(
                        kind="deployment",
                        identifier=str(data.get("id", data.get("sha", "unknown"))),
                        description=str(data.get("description", "")),
                        occurred_at=occurred,
                        author=data.get("author"),
                    )
        return None
