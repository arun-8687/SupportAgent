"""
Core data models for the SRE Agent.

Models mirror the Azure SRE Agent domain: incoming alerts from monitoring /
incident platforms, triage assessments, subagent investigation findings,
root cause analysis, mitigation plans gated by a permission layer, and
institutional knowledge records.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================

class AlertSource(str, Enum):
    """Where the alert originated."""
    AZURE_MONITOR = "azure_monitor"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    GRAFANA = "grafana"
    CUSTOM = "custom"


class Severity(str, Enum):
    """Incident severity levels."""
    SEV1 = "sev1"  # Critical - customer facing outage
    SEV2 = "sev2"  # High - degraded service
    SEV3 = "sev3"  # Medium - partial impact
    SEV4 = "sev4"  # Low - informational


class IncidentStatus(str, Enum):
    """Lifecycle status of an incident inside the workflow."""
    RECEIVED = "received"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    ANALYZING = "analyzing"
    PROPOSING = "proposing"
    AWAITING_APPROVAL = "awaiting_approval"
    MITIGATING = "mitigating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"


class RiskLevel(str, Enum):
    """Risk classification for a mitigation action."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class GateOutcome(str, Enum):
    """Permission gate decision for a proposed action."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class HookEvent(str, Enum):
    """Events where agent hooks fire.

    Stop and PostToolUse are the two core hook events; the lifecycle
    events extend them so operators can also automate around workflow
    milestones (before investigation / after resolution).
    """
    STOP = "Stop"                 # agent about to finalize its response
    POST_TOOL_USE = "PostToolUse" # a tool/skill finished executing
    INVESTIGATION_STARTED = "investigation_started"
    BEFORE_MITIGATION = "before_mitigation"
    AFTER_RESOLUTION = "after_resolution"
    ON_ESCALATION = "on_escalation"


# =============================================================================
# Alert / Incident
# =============================================================================

class ResourceRef(BaseModel):
    """The Azure (or other) resource an alert points at."""
    resource_id: Optional[str] = None
    resource_group: Optional[str] = None
    subscription_id: Optional[str] = None
    service_name: str = "unknown"
    resource_type: Optional[str] = None
    region: Optional[str] = None
    environment: Literal["prod", "staging", "dev"] = "prod"
    # Owning application/team code. "UNMAPPED" is the quarantine default:
    # an untagged resource must never inherit another app's pre-approvals.
    app_code: str = "UNMAPPED"


class IncidentAlert(BaseModel):
    """Normalized alert from any connected monitoring/incident platform."""
    alert_id: str
    source: AlertSource
    title: str
    description: str = ""
    severity_hint: Optional[Severity] = None
    resource: ResourceRef = Field(default_factory=ResourceRef)
    signals: Dict[str, Any] = Field(default_factory=dict)  # metric values, thresholds
    fired_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw: Dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Enriched incident tracked through the workflow."""
    incident_id: str
    alert: IncidentAlert
    severity: Severity = Severity.SEV3
    service_name: str = "unknown"
    environment: Literal["prod", "staging", "dev"] = "prod"
    app_code: str = "UNMAPPED"
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Triage
# =============================================================================

class KnowledgeMatch(BaseModel):
    """A relevant record retrieved from institutional knowledge."""
    record_id: str
    title: str
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    similarity: float = Field(ge=0.0, le=1.0, default=0.0)


class TriageAssessment(BaseModel):
    """Output of the triage step."""
    severity: Severity
    category: str = "unknown"  # e.g. memory, latency, deployment, dependency
    summary: str = ""
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    requires_investigation: bool = True
    knowledge_matches: List[KnowledgeMatch] = Field(default_factory=list)
    # Unified memory search hits (past incidents, user memories, knowledge
    # base, synthesized files) with citations.
    memory_matches: List["MemorySearchResult"] = Field(default_factory=list)


class InvestigationPlan(BaseModel):
    """Which subagents the planner selected and why."""
    subagents: List[str] = Field(default_factory=list)
    reasoning: str = ""


# =============================================================================
# Investigation findings
# =============================================================================

class Evidence(BaseModel):
    """A single piece of evidence collected by a subagent."""
    source: str  # e.g. "app_insights", "github", "log_analytics"
    observation: str
    data: Dict[str, Any] = Field(default_factory=dict)


class SubagentFinding(BaseModel):
    """The result of one subagent's investigation."""
    subagent: str
    summary: str
    evidence: List[Evidence] = Field(default_factory=list)
    suspected_cause: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class CorrelatedChange(BaseModel):
    """A deployment/commit correlated with the incident window."""
    kind: Literal["deployment", "commit", "config_change"] = "deployment"
    identifier: str
    description: str = ""
    occurred_at: Optional[datetime] = None
    author: Optional[str] = None
    repo: Optional[str] = None


class RootCauseAnalysis(BaseModel):
    """Synthesized root cause across all subagent findings."""
    hypothesis: str
    confidence: float = Field(ge=0.0, le=1.0)
    contributing_factors: List[str] = Field(default_factory=list)
    correlated_change: Optional[CorrelatedChange] = None
    impact_assessment: str = ""
    evidence_summary: List[str] = Field(default_factory=list)


# =============================================================================
# Mitigation
# =============================================================================

class MitigationAction(BaseModel):
    """One proposed mitigation, usually backed by a skill tool."""
    action_id: str
    name: str
    kind: Literal["skill", "python_tool", "manual"] = "skill"
    skill_name: Optional[str] = None
    tool_name: Optional[str] = None  # tool within the skill; first tool if unset
    parameters: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    risk: RiskLevel = RiskLevel.MEDIUM
    supports_rollback: bool = False


class MitigationPlan(BaseModel):
    """The full proposed mitigation plan."""
    actions: List[MitigationAction] = Field(default_factory=list)
    reasoning: str = ""
    expected_outcome: str = ""


class GateDecision(BaseModel):
    """Permission gate evaluation for one action."""
    action_id: str
    outcome: GateOutcome
    matched_rule: Optional[str] = None
    reason: str = ""


class ApprovalRecord(BaseModel):
    """Human or automatic approval of the mitigation plan."""
    approved: bool
    approver: str = "auto"
    channel: str = "auto"  # auto | http | service_bus | chat
    reason: str = ""
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActionResult(BaseModel):
    """Execution result for one mitigation action."""
    action_id: str
    success: bool
    output: str = ""
    error: Optional[str] = None
    dry_run: bool = True
    duration_ms: int = 0


class ExecutionReport(BaseModel):
    """Results of executing the approved plan."""
    success: bool
    results: List[ActionResult] = Field(default_factory=list)


class VerificationReport(BaseModel):
    """Post-mitigation health verification."""
    healthy: bool
    checks: List[Dict[str, Any]] = Field(default_factory=list)
    notes: str = ""


# =============================================================================
# Ticketing / hooks / knowledge
# =============================================================================

class TicketRecord(BaseModel):
    """Ticket created/updated in the connected incident platform."""
    ticket_id: str
    platform: str  # servicenow | pagerduty | console
    url: Optional[str] = None
    status: str = "open"


class HookResult(BaseModel):
    """Outcome of one agent hook execution."""
    hook: str
    event: HookEvent
    hook_type: Literal["command", "prompt"]
    success: bool
    output: str = ""
    decision: Optional[Dict[str, Any]] = None  # prompt hooks return structured JSON


class SessionInsight(BaseModel):
    """Structured learnings extracted after a thread completes.

    Mirrors the session-insight capture: symptoms observed, resolution
    steps that worked, root cause, and pitfalls to avoid — all of which
    become searchable memory.
    """
    insight_id: str
    incident_id: str
    service_name: str
    symptoms_observed: List[str] = Field(default_factory=list)
    resolution_steps: List[str] = Field(default_factory=list)
    root_cause: str = ""
    pitfalls_to_avoid: List[str] = Field(default_factory=list)
    outcome: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserMemory(BaseModel):
    """A discrete fact saved via #remember."""
    memory_id: str
    fact: str
    saved_by: str = "user"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MemorySearchResult(BaseModel):
    """One hit from unified memory search, with its citation."""
    source: Literal["past_incident", "user_memory", "knowledge_base", "synthesized"]
    citation: str  # record id / file name the answer is grounded in
    title: str
    content: str
    similarity: float = Field(ge=0.0, le=1.0, default=0.0)


class KnowledgeRecord(BaseModel):
    """Institutional knowledge captured after an investigation."""
    record_id: str
    incident_id: str
    service_name: str
    title: str
    category: str = "unknown"
    root_cause: str = ""
    mitigations: List[str] = Field(default_factory=list)
    outcome: str = ""
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
