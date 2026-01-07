"""
Triage Agent - AI-powered incident triage.

Performs intelligent triage using:
- Deduplication with semantic similarity
- Correlation analysis
- Knowledge retrieval (RAG)
- LLM-powered classification
- LangSmith tracing for observability
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.agents.base_agent import AgentConfig, BaseAgent
from src.graph.state import (
    AppSupportState,
    Classification,
    CorrelationResult,
    FailureCategory,
    KnowledgeContext,
    Severity,
    TriageResult,
    WorkflowStage,
)
from src.integrations.config import get_settings
from src.intelligence.correlation import CorrelationEngine
from src.intelligence.deduplication import IncidentDeduplicator
from src.intelligence.knowledge_retrieval import KnowledgeRetriever
from src.tools.base import ToolRegistry
from src.observability import (
    get_langsmith,
    metrics,
    audit,
    AuditEventType,
)


class TriageAgent(BaseAgent):
    """
    AI-powered triage agent.

    Performs:
    1. Deduplication check (noise reduction)
    2. Knowledge retrieval (similar issues, known errors)
    3. Correlation analysis (related failures)
    4. LLM-powered classification and severity assessment
    5. Routing decision
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        deduplicator: IncidentDeduplicator,
        knowledge_retriever: KnowledgeRetriever,
        correlation_engine: CorrelationEngine,
        **kwargs
    ):
        """
        Initialize triage agent.

        Args:
            tool_registry: Registry of available tools
            deduplicator: Incident deduplication service
            knowledge_retriever: RAG knowledge retriever
            correlation_engine: Cross-system correlation
        """
        config = AgentConfig(
            name="triage",
            description="AI-powered incident triage and classification",
            temperature=0.2  # Low temperature for consistent classification
        )
        super().__init__(config, tool_registry, **kwargs)

        self.deduplicator = deduplicator
        self.knowledge_retriever = knowledge_retriever
        self.correlation_engine = correlation_engine
        self.settings = get_settings()

    async def execute(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Execute triage workflow.

        Args:
            state: Current workflow state

        Returns:
            State updates with triage results
        """
        incident = state["incident"]
        self.logger.info("starting_triage", job_name=incident.job_name)

        # 1. Run deduplication check
        dedup_result = await self.deduplicator.process_incoming_incident(incident)
        self.logger.info(
            "deduplication_complete",
            action=dedup_result.action.value,
            parent_id=dedup_result.parent_id
        )

        # Record deduplication metric
        metrics.deduplication_results.labels(result=dedup_result.action.value).inc()

        # If suppressed, return early
        if dedup_result.action.value == "SUPPRESS":
            return self._create_suppressed_result(dedup_result)

        # 2. Retrieve relevant knowledge (parallel with correlation)
        import asyncio
        knowledge_task = self.knowledge_retriever.retrieve_relevant_knowledge(incident)
        correlation_task = self.correlation_engine.correlate_incident(incident)

        knowledge, correlations = await asyncio.gather(
            knowledge_task, correlation_task
        )

        self.logger.info(
            "context_gathered",
            known_errors=len(knowledge.known_errors),
            similar_incidents=len(knowledge.similar_incidents),
            correlations=len(correlations.correlations)
        )

        # 3. AI-powered classification with LLM
        classification = await self._classify_with_llm(
            incident=incident,
            knowledge=knowledge,
            correlations=correlations
        )

        # Record classification in LangSmith
        langsmith = get_langsmith()
        if langsmith.enabled:
            # This will be captured in the parent run context
            pass

        # Record classification metrics
        metrics.error_classifications.labels(
            category=classification.category.value,
            strategy=classification.recommended_action
        ).inc()

        # Audit the classification
        audit.log(
            event_type=AuditEventType.INCIDENT_CLASSIFIED,
            action="Triage classification complete",
            incident_id=incident.incident_id,
            details={
                "category": classification.category.value,
                "confidence": classification.hypothesis_confidence,
                "is_known_issue": classification.is_known_issue,
                "recommended_action": classification.recommended_action
            }
        )

        # 4. Calculate severity
        severity = self._assess_severity(
            incident=incident,
            correlations=correlations,
            classification=classification
        )

        # 5. Determine routing
        routing = self._determine_routing(
            classification=classification,
            severity=severity,
            knowledge=knowledge
        )

        # Build triage result
        triage_result = TriageResult(
            classification=classification,
            severity=severity,
            deduplication=dedup_result,
            correlations=correlations,
            knowledge_context=knowledge,
            routing_decision=routing
        )

        return {
            "triage_result": triage_result,
            "knowledge_context": knowledge,
            "workflow_stage": WorkflowStage.TRIAGE,
            "messages": self.add_message(
                state,
                "assistant",
                f"Triage complete: {classification.category.value} - {severity.value}"
            )
        }

    async def _classify_with_llm(
        self,
        incident: Any,
        knowledge: KnowledgeContext,
        correlations: Any
    ) -> Classification:
        """
        Use LLM for intelligent classification with retrieved context.
        """
        # Format context for LLM
        prompt = self._build_classification_prompt(incident, knowledge, correlations)

        # Get LLM response
        response = await self.chat_completion(
            messages=[
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2
        )

        # Parse response
        try:
            result = json.loads(response)
            return Classification(
                category=FailureCategory(result.get("category", "unknown")),
                issue_type=result.get("issue_type", "Unknown"),
                root_cause_hypothesis=result.get("root_cause_hypothesis", "Unable to determine"),
                hypothesis_confidence=float(result.get("confidence", 0.5)),
                business_impact=result.get("business_impact", "medium"),
                is_known_issue=result.get("is_known_issue", False),
                matched_known_error_id=result.get("known_error_id"),
                recommended_action=result.get("recommended_action", "diagnose_further")
            )
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error("classification_parse_error", error=str(e))
            return Classification(
                category=FailureCategory.UNKNOWN,
                issue_type="Parse Error",
                root_cause_hypothesis="Unable to classify",
                hypothesis_confidence=0.0,
                business_impact="medium",
                is_known_issue=False,
                recommended_action="escalate_human"
            )

    def _get_system_prompt(self) -> str:
        """Get system prompt for classification."""
        return """You are an expert IT support triage agent. Your job is to analyze incidents
and classify them accurately based on the error details and context provided.

You must respond with a JSON object containing:
- category: one of "data_pipeline", "infrastructure", "application", "integration", "unknown"
- issue_type: specific type of issue (be precise)
- root_cause_hypothesis: your best guess at the root cause
- confidence: your confidence in the hypothesis (0.0 to 1.0)
- business_impact: one of "critical", "high", "medium", "low"
- is_known_issue: true if this matches a known error from the database
- known_error_id: ID of matching known error (if applicable)
- recommended_action: one of "auto_fix", "diagnose_further", "escalate_human"

Be precise and base your analysis on the evidence provided."""

    def _build_classification_prompt(
        self,
        incident: Any,
        knowledge: KnowledgeContext,
        correlations: Any
    ) -> str:
        """Build the classification prompt with all context."""
        # Format known errors
        known_errors_text = ""
        if knowledge.known_errors:
            known_errors_text = "\n".join([
                f"- [{ke.id}] {ke.title}: {ke.error_pattern} (confidence: {ke.match_confidence:.2f})"
                for ke in knowledge.known_errors[:3]
            ])
        else:
            known_errors_text = "No matching known errors found."

        # Format similar incidents
        similar_text = ""
        if knowledge.similar_incidents:
            similar_text = "\n".join([
                f"- [{inc.incident_id}] {inc.error_message[:100]}... "
                f"(similarity: {inc.similarity:.2f}, resolution: {inc.resolution_summary or 'N/A'})"
                for inc in knowledge.similar_incidents[:3]
            ])
        else:
            similar_text = "No similar past incidents found."

        # Format correlations
        correlation_text = ""
        if correlations.correlations:
            correlation_text = "\n".join([
                f"- [{c.type}] {c.relationship} (confidence: {c.confidence:.2f})"
                for c in correlations.correlations[:5]
            ])
        else:
            correlation_text = "No correlated failures found."

        return f"""## Incident Details
Job: {incident.job_name}
Type: {incident.job_type}
Environment: {incident.environment}
Error Code: {incident.error_code or 'N/A'}
Error Message: {incident.error_message}

Stack Trace (first 1000 chars):
{incident.stack_trace[:1000] if incident.stack_trace else 'N/A'}

## Known Similar Errors (from KEDB)
{known_errors_text}

## Similar Past Incidents
{similar_text}

## Correlated Failures
{correlation_text}
Root Cause Hypothesis from Correlation: {correlations.root_cause_hypothesis or 'None'}

## Recent Changes
{self._format_changes(knowledge.recent_changes)}

Based on this analysis, classify this incident and provide your assessment."""

    def _format_changes(self, changes: List[Dict]) -> str:
        """Format recent changes for prompt."""
        if not changes:
            return "No recent changes found."

        return "\n".join([
            f"- [{c.get('type', 'unknown')}] {c.get('title', 'No title')} "
            f"({c.get('completed_at', 'Unknown time')})"
            for c in changes[:3]
        ])

    def _assess_severity(
        self,
        incident: Any,
        correlations: Any,
        classification: Classification
    ) -> Severity:
        """
        Multi-factor severity assessment.
        """
        score = 0

        # Factor 1: Business impact from classification
        impact_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        score += impact_scores.get(classification.business_impact, 10)

        # Factor 2: Blast radius (correlated failures)
        blast_radius = len(correlations.correlations)
        score += min(blast_radius * 5, 20)

        # Factor 3: Source hint (if app indicated priority)
        if incident.priority_hint:
            hint_scores = {"P1": 30, "P2": 20, "P3": 10, "P4": 0}
            score += hint_scores.get(incident.priority_hint, 0)

        # Factor 4: Environment sensitivity
        if incident.environment == "prod":
            score += 15

        # Factor 5: Confidence discount (less confident = more severe to be safe)
        if classification.hypothesis_confidence < 0.5:
            score += 10

        # Map to severity
        if score >= self.settings.severity_p1_threshold:
            return Severity.P1
        elif score >= self.settings.severity_p2_threshold:
            return Severity.P2
        elif score >= self.settings.severity_p3_threshold:
            return Severity.P3
        else:
            return Severity.P4

    def _determine_routing(
        self,
        classification: Classification,
        severity: Severity,
        knowledge: KnowledgeContext
    ) -> str:
        """Determine routing based on classification and context."""
        # Known issue with high confidence -> proposal
        if classification.is_known_issue and classification.hypothesis_confidence > 0.9:
            return "proposal"

        # Auto-fix recommended with high confidence -> proposal
        if classification.recommended_action == "auto_fix":
            if classification.hypothesis_confidence > 0.8:
                return "proposal"

        # Escalate recommended -> escalate
        if classification.recommended_action == "escalate_human":
            return "escalate"

        # P1 with low confidence -> escalate
        if severity == Severity.P1 and classification.hypothesis_confidence < 0.7:
            return "escalate"

        # Default -> diagnose further
        return "diagnose"

    def _create_suppressed_result(self, dedup_result: Any) -> Dict[str, Any]:
        """Create result for suppressed duplicate."""
        return {
            "triage_result": TriageResult(
                classification=Classification(
                    category=FailureCategory.UNKNOWN,
                    issue_type="Duplicate",
                    root_cause_hypothesis="Duplicate incident",
                    hypothesis_confidence=1.0,
                    business_impact="low",
                    is_known_issue=True,
                    recommended_action="auto_fix"
                ),
                severity=Severity.P4,
                deduplication=dedup_result,
                correlations=CorrelationResult(
                    correlations=[],
                    root_cause_hypothesis=None,
                    blast_radius=0,
                    confidence=0.0
                ),
                knowledge_context=KnowledgeContext(),
                routing_decision="suppress"
            ),
            "workflow_stage": WorkflowStage.RESOLUTION,
            "resolution_summary": f"Suppressed as duplicate of {dedup_result.parent_id}",
            "incident_closed": True
        }
