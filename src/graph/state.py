"""
LangGraph State Schema for App Support AI Agent.

Defines the TypedDict state that flows through the workflow,
containing all incident context, diagnostic findings, and workflow state.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, TypedDict

from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================

class Severity(str, Enum):
    """Incident severity levels."""
    P1 = "P1"  # Critical - immediate attention
    P2 = "P2"  # High - urgent
    P3 = "P3"  # Medium - normal priority
    P4 = "P4"  # Low - can wait


class FailureCategory(str, Enum):
    """Categories of failures."""
    DATA_PIPELINE = "data_pipeline"
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    INTEGRATION = "integration"
    UNKNOWN = "unknown"


class WorkflowStage(str, Enum):
    """Current stage in the workflow."""
    INTAKE = "intake"
    TRIAGE = "triage"
    DIAGNOSE = "diagnose"
    PROPOSAL = "proposal"
    APPROVAL = "approval"
    EXECUTION = "execution"
    VERIFICATION = "verification"
    RESOLUTION = "resolution"
    ESCALATED = "escalated"


class DeduplicationAction(str, Enum):
    """Actions from deduplication check."""
    NEW = "NEW"
    DUPLICATE = "DUPLICATE"
    RELATED = "RELATED"
    STORM = "STORM"
    SUPPRESS = "SUPPRESS"


# =============================================================================
# Pydantic Models for Structured Data
# =============================================================================

class Incident(BaseModel):
    """Core incident data from source systems."""
    incident_id: str
    job_name: str
    job_type: str  # Generic: "databricks", "sql_server", "azure_sql", "adf", "api", etc.
    source_system: str
    environment: Literal["prod", "uat", "dev"]

    error_message: str
    error_code: Optional[str] = None
    stack_trace: Optional[str] = None

    failure_timestamp: datetime
    job_run_id: Optional[str] = None
    cluster_id: Optional[str] = None
    workstation: Optional[str] = None
    notebook_path: Optional[str] = None

    affected_tables: Optional[List[str]] = None
    upstream_jobs: Optional[List[str]] = None
    owner_team: Optional[str] = None
    priority_hint: Optional[Literal["P1", "P2", "P3", "P4"]] = None


class DeduplicationResult(BaseModel):
    """Result of deduplication analysis."""
    action: DeduplicationAction
    parent_id: Optional[str] = None
    reason: str = ""  # Make optional with default
    confidence: float = 0.0  # Add confidence field
    similar_past_incidents: Optional[List[str]] = None
    storm_id: Optional[str] = None


class Correlation(BaseModel):
    """A single correlation finding."""
    type: Literal[
        "UPSTREAM_FAILURE",
        "DOWNSTREAM_IMPACT",
        "TEMPORAL",
        "INFRASTRUCTURE",
        "RECENT_CHANGE"
    ]
    related_incident_id: Optional[str] = None
    change_record_id: Optional[str] = None
    relationship: str
    confidence: float = Field(ge=0.0, le=1.0)
    details: Optional[Dict[str, Any]] = None


class CorrelationResult(BaseModel):
    """Result of correlation analysis."""
    correlations: List[Correlation] = []
    root_cause_hypothesis: Optional[str] = None
    blast_radius: int = 0
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class KnownError(BaseModel):
    """A known error from KEDB."""
    id: str
    title: str
    error_pattern: str
    root_cause: str
    workaround: Optional[str] = None
    permanent_fix: Optional[str] = None
    linked_runbook: Optional[str] = None
    match_confidence: float = Field(ge=0.0, le=1.0)


class PastIncident(BaseModel):
    """A similar past incident with resolution."""
    incident_id: str
    error_message: str
    root_cause: Optional[str] = None
    resolution_summary: Optional[str] = None
    resolution_verified: bool = False
    similarity: float = Field(ge=0.0, le=1.0)
    resolved_at: Optional[datetime] = None


class KnowledgeContext(BaseModel):
    """Retrieved knowledge for diagnosis."""
    known_errors: List[KnownError] = []
    similar_incidents: List[PastIncident] = []
    applicable_runbooks: List[str] = []
    relevant_docs: List[Dict[str, Any]] = []
    recent_changes: List[Dict[str, Any]] = []
    suggested_resolution: Optional[str] = None


class Classification(BaseModel):
    """Triage classification result."""
    category: FailureCategory
    issue_type: str
    root_cause_hypothesis: str
    hypothesis_confidence: float = Field(ge=0.0, le=1.0)
    business_impact: Literal["critical", "high", "medium", "low"]
    is_known_issue: bool = False
    matched_known_error_id: Optional[str] = None
    recommended_action: Literal["auto_fix", "diagnose_further", "escalate_human"]


class TriageResult(BaseModel):
    """Complete triage result."""
    classification: Classification
    severity: Severity
    deduplication: DeduplicationResult
    correlations: Optional[CorrelationResult] = None
    knowledge_context: Optional[KnowledgeContext] = None
    routing_decision: str = ""


class Hypothesis(BaseModel):
    """A diagnostic hypothesis."""
    id: str
    description: str
    prior_probability: float = Field(ge=0.0, le=1.0)
    evidence_needed: List[str] = []
    tools_to_use: List[str] = []


class Evidence(BaseModel):
    """Evidence gathered during diagnosis."""
    source: str
    tool_used: str
    raw_data: Optional[Any] = None
    analysis: Optional[str] = None
    supports_hypothesis: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    error: Optional[str] = None


class RootCause(BaseModel):
    """Determined root cause."""
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: List[str] = []
    remaining_uncertainty: Optional[str] = None
    recommended_approach: str


class DiagnosticResult(BaseModel):
    """Complete diagnostic result."""
    root_cause: RootCause
    evidence: List[Evidence] = []
    hypotheses_tested: List[Hypothesis] = []
    reasoning_chain: List[Dict[str, Any]] = []
    affected_systems: List[str] = []


class RemediationStep(BaseModel):
    """A single remediation step."""
    name: str
    tool: str
    params: Dict[str, Any] = {}
    description: str
    risk_level: Literal["low", "medium", "high"] = "low"
    supports_rollback: bool = False
    rollback_params: Optional[Dict[str, Any]] = None


class RemediationProposal(BaseModel):
    """Proposed remediation plan."""
    source: Literal["known_error", "past_incident", "novel"]
    steps: List[RemediationStep] = []
    estimated_success_probability: float = Field(ge=0.0, le=1.0)
    risk_assessment: str
    rollback_plan: Optional[str] = None
    requires_approval: bool = True
    reasoning: str


class ApprovalDecision(BaseModel):
    """Approval decision for remediation."""
    approved: bool
    approver: Literal["auto", "human"]
    approver_id: Optional[str] = None
    reason: Optional[str] = None
    approved_at: Optional[datetime] = None
    modifications: Optional[List[str]] = None


class ExecutionStep(BaseModel):
    """Record of an executed step."""
    step_name: str
    tool: str
    success: bool
    output: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: int
    executed_at: datetime
    rollback_info: Optional[Dict[str, Any]] = None


class ExecutionResult(BaseModel):
    """Result of remediation execution."""
    success: bool
    executed_steps: List[ExecutionStep] = []
    rollback_performed: bool = False
    rollback_steps: List[str] = []
    error_message: Optional[str] = None


class VerificationResult(BaseModel):
    """Result of fix verification."""
    success: bool
    verification_checks: List[Dict[str, Any]] = []
    checks_performed: List[str] = []  # List of check names performed
    job_status: Optional[str] = None
    verified_at: Optional[datetime] = None
    notes: Optional[str] = None
    confidence: float = 0.0  # Confidence in the verification result
    error: Optional[str] = None  # Error message if verification failed
    evidence: List[str] = []  # Evidence supporting the verification result


class ToolCallRecord(BaseModel):
    """Record of a tool call."""
    tool_name: str
    input_params: Dict[str, Any]
    output: Optional[Any] = None
    success: bool
    error: Optional[str] = None
    execution_time_ms: int
    timestamp: datetime


# =============================================================================
# Main LangGraph State
# =============================================================================

class AppSupportState(TypedDict, total=False):
    """
    Main state object that flows through the LangGraph workflow.

    All agent nodes read from and write to this state.
    Uses TypedDict for LangGraph compatibility.
    """

    # -------------------------------------------------------------------------
    # Incident Information
    # -------------------------------------------------------------------------
    incident: Incident
    incident_embedding: List[float]  # Vector embedding of incident for similarity

    # -------------------------------------------------------------------------
    # Deduplication & Correlation
    # -------------------------------------------------------------------------
    deduplication_result: DeduplicationResult
    correlation_result: CorrelationResult

    # -------------------------------------------------------------------------
    # Triage Results
    # -------------------------------------------------------------------------
    triage_result: TriageResult
    knowledge_context: KnowledgeContext

    # -------------------------------------------------------------------------
    # Diagnosis Results
    # -------------------------------------------------------------------------
    diagnostic_result: DiagnosticResult

    # -------------------------------------------------------------------------
    # Remediation
    # -------------------------------------------------------------------------
    proposal: RemediationProposal
    approval: ApprovalDecision
    execution_result: ExecutionResult
    verification_result: VerificationResult

    # -------------------------------------------------------------------------
    # Workflow Control
    # -------------------------------------------------------------------------
    workflow_stage: WorkflowStage
    current_agent: str
    requires_human_review: bool
    awaiting_approval: bool
    retry_count: int
    max_retries: int

    # -------------------------------------------------------------------------
    # Resolution
    # -------------------------------------------------------------------------
    resolution_summary: str
    incident_closed: bool
    closed_at: datetime

    # -------------------------------------------------------------------------
    # Tool Execution History
    # -------------------------------------------------------------------------
    tool_calls: List[ToolCallRecord]

    # -------------------------------------------------------------------------
    # Messages (for LLM context)
    # -------------------------------------------------------------------------
    messages: List[Dict[str, Any]]

    # -------------------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------------------
    created_at: datetime
    updated_at: datetime
    processing_time_ms: int


def create_initial_state(incident: Incident) -> AppSupportState:
    """
    Create initial state from an incoming incident.

    Args:
        incident: The incident to process

    Returns:
        Initial AppSupportState with defaults
    """
    now = datetime.now(timezone.utc)
    return AppSupportState(
        incident=incident,
        workflow_stage=WorkflowStage.INTAKE,
        current_agent="intake",
        requires_human_review=False,
        awaiting_approval=False,
        retry_count=0,
        max_retries=3,
        incident_closed=False,
        tool_calls=[],
        messages=[],
        created_at=now,
        updated_at=now,
        processing_time_ms=0,
    )
