"""
Proposal Agent - Generates remediation proposals based on diagnosis.

Analyzes diagnostic results and creates actionable remediation plans with:
- Step-by-step remediation actions
- Risk assessment
- Rollback procedures
- Success probability estimation
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.agents.base_agent import AgentConfig, RemediationAgent
from src.graph.state import (
    AppSupportState,
    DiagnosticResult,
    RemediationProposal,
    RemediationStep,
    WorkflowStage,
)
from src.tools.base import ToolRegistry
from src.observability import (
    metrics,
    audit,
    AuditEventType,
)
from src.integrations.config import get_settings


class ProposalAgent(RemediationAgent):
    """
    Generates remediation proposals from diagnostic results.

    Workflow:
    1. Analyze root cause and confidence
    2. Check for known fixes (KEDB, past incidents)
    3. Generate remediation steps
    4. Assess risks and create rollback plan
    5. Determine approval requirements
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        **kwargs
    ):
        """
        Initialize proposal agent.

        Args:
            tool_registry: Registry of available tools
        """
        config = AgentConfig(
            name="proposal",
            description="Remediation proposal generation",
            max_tool_calls=5,
            temperature=0.2
        )
        super().__init__(config, tool_registry, **kwargs)
        self.settings = get_settings()

    async def execute(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Execute proposal generation workflow.

        Args:
            state: Current workflow state

        Returns:
            State updates with remediation proposal
        """
        incident = state["incident"]
        diagnostic = state.get("diagnostic_result")
        knowledge = state.get("knowledge_context")
        triage = state.get("triage_result")

        self.logger.info(
            "generating_proposal",
            job_name=incident.job_name,
            root_cause=diagnostic.root_cause.description[:100] if diagnostic else "unknown"
        )

        # Audit proposal start
        audit.log(
            event_type=AuditEventType.PROPOSAL_GENERATED,
            action="Starting proposal generation",
            incident_id=incident.incident_id,
            details={"job_name": incident.job_name}
        )

        # 1. Determine proposal source and base strategy
        source, base_steps = await self._determine_strategy(
            incident, diagnostic, knowledge, triage
        )

        # 2. Generate detailed remediation steps
        steps = await self._generate_remediation_steps(
            incident, diagnostic, base_steps, source
        )

        # 3. Assess risks
        risk_assessment = await self._assess_risks(steps, incident)

        # 4. Create rollback plan
        rollback_plan = self._create_rollback_plan(steps)

        # 5. Estimate success probability
        success_probability = self._estimate_success_probability(
            diagnostic, source, steps, knowledge
        )

        # 6. Determine if approval is required
        requires_approval = self._requires_approval(
            incident, risk_assessment, success_probability
        )

        # Build proposal
        proposal = RemediationProposal(
            source=source,
            steps=steps,
            estimated_success_probability=success_probability,
            risk_assessment=risk_assessment,
            rollback_plan=rollback_plan,
            requires_approval=requires_approval,
            reasoning=self._build_reasoning(diagnostic, source, steps)
        )

        self.logger.info(
            "proposal_generated",
            source=source,
            steps_count=len(steps),
            success_probability=success_probability,
            requires_approval=requires_approval
        )

        # Audit proposal completion
        audit.log(
            event_type=AuditEventType.PROPOSAL_GENERATED,
            action="Proposal generated",
            incident_id=incident.incident_id,
            details={
                "source": source,
                "steps": len(steps),
                "success_probability": success_probability,
                "requires_approval": requires_approval
            }
        )

        return {
            "proposal": proposal,
            "workflow_stage": WorkflowStage.PROPOSAL,
            "awaiting_approval": requires_approval,
            "messages": self.add_message(
                state,
                "assistant",
                f"Proposal generated: {len(steps)} steps, {success_probability:.0%} success probability"
            )
        }

    async def _determine_strategy(
        self,
        incident: Any,
        diagnostic: Optional[DiagnosticResult],
        knowledge: Any,
        triage: Any
    ) -> tuple[str, List[Dict[str, Any]]]:
        """
        Determine remediation strategy based on available information.

        Returns:
            Tuple of (source, base_steps)
        """
        # Check for known error match first
        if knowledge and knowledge.known_errors:
            best_match = max(knowledge.known_errors, key=lambda x: x.match_confidence)
            if best_match.match_confidence >= 0.8:
                if best_match.workaround or best_match.permanent_fix:
                    self.logger.info(
                        "using_known_error",
                        error_id=best_match.id,
                        confidence=best_match.match_confidence
                    )
                    return "known_error", self._parse_known_error_steps(best_match)

        # Check for similar past incident with verified resolution
        if knowledge and knowledge.similar_incidents:
            verified = [i for i in knowledge.similar_incidents if i.resolution_verified]
            if verified:
                best = max(verified, key=lambda x: x.similarity)
                if best.similarity >= 0.85 and best.resolution_summary:
                    self.logger.info(
                        "using_past_incident",
                        incident_id=best.incident_id,
                        similarity=best.similarity
                    )
                    return "past_incident", self._parse_past_resolution(best)

        # Generate novel solution based on diagnosis
        return "novel", []

    def _parse_known_error_steps(self, known_error: Any) -> List[Dict[str, Any]]:
        """Parse remediation steps from known error."""
        steps = []

        # Try workaround first
        if known_error.workaround:
            steps.extend(self._parse_remediation_text(known_error.workaround))

        # Add permanent fix if available
        if known_error.permanent_fix:
            steps.extend(self._parse_remediation_text(known_error.permanent_fix))

        return steps

    def _parse_past_resolution(self, past_incident: Any) -> List[Dict[str, Any]]:
        """Parse remediation steps from past incident resolution."""
        if past_incident.resolution_summary:
            return self._parse_remediation_text(past_incident.resolution_summary)
        return []

    def _parse_remediation_text(self, text: str) -> List[Dict[str, Any]]:
        """Parse remediation text into structured steps."""
        steps = []

        # Simple parsing - look for numbered steps or bullet points
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Remove numbering
            if line[0].isdigit() and '.' in line[:3]:
                line = line.split('.', 1)[1].strip()
            elif line.startswith('-') or line.startswith('*'):
                line = line[1:].strip()

            if line:
                steps.append({
                    "description": line,
                    "tool": self._infer_tool_from_description(line)
                })

        return steps if steps else [{"description": text, "tool": "manual"}]

    def _infer_tool_from_description(self, description: str) -> str:
        """Infer which tool to use from step description."""
        desc_lower = description.lower()

        tool_keywords = {
            "restart_job": ["restart", "rerun", "re-run", "retry"],
            "scale_cluster": ["scale", "increase", "memory", "nodes"],
            "clear_cache": ["cache", "clear", "invalidate"],
            "check_upstream": ["upstream", "dependency", "dependencies"],
            "run_health_check": ["health", "check", "verify", "validate"],
            "get_job_run_logs": ["log", "logs"],
            "notify_team": ["notify", "alert", "escalate", "contact"]
        }

        for tool, keywords in tool_keywords.items():
            if any(kw in desc_lower for kw in keywords):
                return tool

        return "manual"

    async def _generate_remediation_steps(
        self,
        incident: Any,
        diagnostic: Optional[DiagnosticResult],
        base_steps: List[Dict[str, Any]],
        source: str
    ) -> List[RemediationStep]:
        """Generate detailed remediation steps."""

        if base_steps:
            # Convert base steps to RemediationStep objects
            return [
                self._create_remediation_step(step, i, incident)
                for i, step in enumerate(base_steps)
            ]

        # Generate novel remediation using LLM
        return await self._generate_novel_remediation(incident, diagnostic)

    def _create_remediation_step(
        self,
        step: Dict[str, Any],
        index: int,
        incident: Any
    ) -> RemediationStep:
        """Create a RemediationStep from parsed data."""
        tool_name = step.get("tool", "manual")
        tool = self.tool_registry.get(tool_name)

        # Build params based on tool and incident
        params = self._build_tool_params(tool_name, incident)

        # Check if tool supports rollback
        supports_rollback = tool.supports_rollback if tool else False

        return RemediationStep(
            name=f"step_{index + 1}",
            tool=tool_name,
            params=params,
            description=step.get("description", f"Execute {tool_name}"),
            risk_level=self._assess_step_risk(tool_name),
            supports_rollback=supports_rollback,
            rollback_params=params if supports_rollback else None
        )

    def _build_tool_params(self, tool_name: str, incident: Any) -> Dict[str, Any]:
        """Build tool parameters from incident context."""
        params = {}

        if hasattr(incident, "job_name"):
            params["job_name"] = incident.job_name

        if hasattr(incident, "job_run_id") and incident.job_run_id:
            params["run_id"] = incident.job_run_id

        if hasattr(incident, "cluster_id") and incident.cluster_id:
            params["cluster_id"] = incident.cluster_id

        if hasattr(incident, "environment"):
            params["environment"] = incident.environment

        return params

    async def _generate_novel_remediation(
        self,
        incident: Any,
        diagnostic: Optional[DiagnosticResult]
    ) -> List[RemediationStep]:
        """Generate novel remediation steps using LLM."""

        # Get available tools
        available_tools = self.tool_registry.list_tools()

        prompt = f"""Generate remediation steps for this incident.

## Incident
Job: {incident.job_name}
Type: {incident.job_type}
Error: {incident.error_message[:500]}

## Root Cause
{diagnostic.root_cause.description if diagnostic else 'Unknown'}
Confidence: {diagnostic.root_cause.confidence if diagnostic else 0}

## Available Tools
{', '.join(available_tools[:20])}

Generate 2-5 remediation steps as JSON:
{{
    "steps": [
        {{
            "name": "step_1",
            "tool": "tool_name",
            "description": "What this step does",
            "params": {{}},
            "risk_level": "low|medium|high"
        }}
    ]
}}

Prefer automated tools over manual steps. Order steps from safest to most impactful."""

        try:
            response = await self.chat_completion(
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.2
            )

            result = json.loads(response)
            return [
                RemediationStep(
                    name=step.get("name", f"step_{i}"),
                    tool=step.get("tool", "manual"),
                    params=step.get("params", {}),
                    description=step.get("description", ""),
                    risk_level=step.get("risk_level", "medium"),
                    supports_rollback=step.get("supports_rollback", False)
                )
                for i, step in enumerate(result.get("steps", []))
            ]
        except Exception as e:
            self.logger.error("novel_remediation_generation_failed", error=str(e))
            # Return safe default
            return [
                RemediationStep(
                    name="step_1",
                    tool="restart_job",
                    params={"job_name": incident.job_name},
                    description=f"Restart job {incident.job_name}",
                    risk_level="low",
                    supports_rollback=False
                )
            ]

    def _get_system_prompt(self) -> str:
        """Get system prompt for proposal generation."""
        return """You are an expert incident remediation planner. Your job is to create
safe, effective remediation plans based on incident diagnosis.

Guidelines:
1. Prefer automated, reversible actions
2. Start with low-risk diagnostic steps
3. Escalate to more impactful actions only if needed
4. Always consider rollback options
5. Be specific about parameters and expected outcomes"""

    async def _assess_risks(
        self,
        steps: List[RemediationStep],
        incident: Any
    ) -> str:
        """Assess overall risk of remediation plan."""
        high_risk_count = sum(1 for s in steps if s.risk_level == "high")
        medium_risk_count = sum(1 for s in steps if s.risk_level == "medium")

        # Environment affects risk
        is_prod = incident.environment == "prod"

        if high_risk_count > 0 and is_prod:
            return "HIGH - Contains high-risk steps in production environment"
        elif high_risk_count > 0 or (medium_risk_count > 2 and is_prod):
            return "MEDIUM - Contains elevated risk steps"
        else:
            return "LOW - All steps are low risk"

    def _assess_step_risk(self, tool_name: str) -> str:
        """Assess risk level of a single step."""
        high_risk = ["scale_cluster", "modify_config", "delete_data", "force_terminate"]
        medium_risk = ["restart_job", "clear_cache", "modify_permissions"]

        if tool_name in high_risk:
            return "high"
        elif tool_name in medium_risk:
            return "medium"
        return "low"

    def _create_rollback_plan(self, steps: List[RemediationStep]) -> str:
        """Create rollback plan for remediation steps."""
        rollback_steps = []

        for step in reversed(steps):
            if step.supports_rollback:
                rollback_steps.append(f"- Rollback {step.name}: {step.description}")
            else:
                rollback_steps.append(f"- {step.name}: Manual intervention required")

        if not rollback_steps:
            return "No automated rollback available. Manual intervention may be required."

        return "Rollback sequence:\n" + "\n".join(rollback_steps)

    def _estimate_success_probability(
        self,
        diagnostic: Optional[DiagnosticResult],
        source: str,
        steps: List[RemediationStep],
        knowledge: Any
    ) -> float:
        """Estimate probability of remediation success."""
        base_probability = 0.5

        # Adjust based on source
        source_boost = {
            "known_error": 0.25,
            "past_incident": 0.20,
            "novel": 0.0
        }
        base_probability += source_boost.get(source, 0)

        # Adjust based on diagnostic confidence
        if diagnostic and diagnostic.root_cause:
            base_probability += diagnostic.root_cause.confidence * 0.2

        # Adjust based on similar incident success
        if knowledge and knowledge.similar_incidents:
            verified = [i for i in knowledge.similar_incidents if i.resolution_verified]
            if verified:
                base_probability += 0.1

        # Penalty for high-risk steps
        high_risk_count = sum(1 for s in steps if s.risk_level == "high")
        base_probability -= high_risk_count * 0.05

        return min(0.95, max(0.1, base_probability))

    def _requires_approval(
        self,
        incident: Any,
        risk_assessment: str,
        success_probability: float
    ) -> bool:
        """Determine if human approval is required."""
        settings = self.settings

        # P1 incidents in prod always require approval
        if incident.environment == "prod":
            if incident.priority_hint == "P1":
                return True

        # High risk always requires approval
        if risk_assessment.startswith("HIGH"):
            return True

        # Low success probability requires approval
        if success_probability < settings.auto_fix_confidence_threshold:
            return True

        # Auto-fix disabled
        if not settings.auto_fix_enabled:
            return True

        return False

    def _build_reasoning(
        self,
        diagnostic: Optional[DiagnosticResult],
        source: str,
        steps: List[RemediationStep]
    ) -> str:
        """Build reasoning explanation for the proposal."""
        parts = []

        if diagnostic:
            parts.append(f"Root cause identified: {diagnostic.root_cause.description}")
            parts.append(f"Confidence: {diagnostic.root_cause.confidence:.0%}")

        source_explanation = {
            "known_error": "Using proven fix from Known Error Database",
            "past_incident": "Applying resolution from similar past incident",
            "novel": "Generated novel remediation based on diagnosis"
        }
        parts.append(source_explanation.get(source, ""))

        parts.append(f"Proposed {len(steps)} remediation steps")

        return ". ".join(parts)
