"""
LangGraph state for the SRE incident workflow.

`findings` and `hook_results` use additive reducers so parallel subagent
executions (fan-out via the Send API) merge cleanly.
"""
import operator
from typing import Annotated, List, Optional, TypedDict

from sre_agent.models import (
    ApprovalRecord,
    ExecutionReport,
    GateDecision,
    HookResult,
    Incident,
    IncidentStatus,
    InvestigationPlan,
    MitigationPlan,
    RootCauseAnalysis,
    SubagentFinding,
    TicketRecord,
    TriageAssessment,
    VerificationReport,
)


class SREState(TypedDict, total=False):
    """State flowing through the incident-response graph."""

    incident: Incident
    status: IncidentStatus

    triage: TriageAssessment
    plan: InvestigationPlan
    findings: Annotated[List[SubagentFinding], operator.add]
    root_cause: RootCauseAnalysis

    mitigation_plan: MitigationPlan
    gate_decisions: List[GateDecision]
    approval: Optional[ApprovalRecord]
    execution: ExecutionReport
    verification: VerificationReport

    ticket: TicketRecord
    knowledge_record_id: str
    hook_results: Annotated[List[HookResult], operator.add]

    resolution_summary: str
    error: str


def create_initial_state(incident: Incident) -> SREState:
    return SREState(
        incident=incident,
        status=IncidentStatus.RECEIVED,
        findings=[],
        hook_results=[],
    )
