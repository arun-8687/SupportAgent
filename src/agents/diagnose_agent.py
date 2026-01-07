"""
Diagnosis Agent - Chain-of-thought incident diagnosis.

Performs intelligent diagnosis using:
- Hypothesis generation
- Evidence gathering via tools
- Chain-of-thought reasoning
- Root cause synthesis
- LangSmith tracing for observability
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from src.agents.base_agent import AgentConfig, DiagnosticAgent
from src.graph.state import (
    AppSupportState,
    DiagnosticResult,
    Evidence,
    Hypothesis,
    RootCause,
    WorkflowStage,
)
from src.tools.base import ToolRegistry
from src.observability import (
    get_langsmith,
    metrics,
    audit,
    AuditEventType,
)


class DiagnoseAgent(DiagnosticAgent):
    """
    Chain-of-thought diagnosis agent.

    Performs multi-step diagnosis:
    1. Generate hypotheses based on triage context
    2. Plan investigation for each hypothesis
    3. Gather evidence using tools
    4. Evaluate hypotheses against evidence
    5. Synthesize root cause conclusion
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        **kwargs
    ):
        """
        Initialize diagnosis agent.

        Args:
            tool_registry: Registry of available tools
        """
        config = AgentConfig(
            name="diagnose",
            description="Chain-of-thought incident diagnosis",
            max_tool_calls=20,
            temperature=0.3
        )
        super().__init__(config, tool_registry, **kwargs)

    async def execute(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Execute diagnosis workflow.

        Args:
            state: Current workflow state

        Returns:
            State updates with diagnostic results
        """
        incident = state["incident"]
        triage = state.get("triage_result")
        knowledge = state.get("knowledge_context")

        self.logger.info("starting_diagnosis", job_name=incident.job_name)

        # Audit diagnosis start
        audit.log(
            event_type=AuditEventType.DIAGNOSIS_STARTED,
            action="Starting diagnosis",
            incident_id=incident.incident_id,
            details={"job_name": incident.job_name, "job_type": incident.job_type}
        )

        reasoning_chain = []

        # 1. Generate initial hypotheses
        hypotheses = await self._generate_hypotheses(incident, triage, knowledge)
        reasoning_chain.append({
            "step": "hypothesis_generation",
            "count": len(hypotheses),
            "hypotheses": [h.description for h in hypotheses]
        })

        self.logger.info("hypotheses_generated", count=len(hypotheses))

        # 2. Plan investigation for each hypothesis
        investigation_plan = await self._plan_investigation(hypotheses, incident)
        reasoning_chain.append({
            "step": "investigation_planning",
            "tools_planned": investigation_plan
        })

        # 3. Execute investigation (gather evidence)
        evidence = await self._gather_evidence_for_hypotheses(
            investigation_plan, incident, state
        )
        reasoning_chain.append({
            "step": "evidence_gathering",
            "evidence_count": len(evidence),
            "successful": sum(1 for e in evidence if not e.error)
        })

        self.logger.info("evidence_gathered", count=len(evidence))

        # 4. Evaluate hypotheses against evidence
        evaluated = await self._evaluate_hypotheses(hypotheses, evidence)
        reasoning_chain.append({
            "step": "hypothesis_evaluation",
            "rankings": [
                {"hypothesis": h.description, "score": score}
                for h, score in evaluated[:3]
            ]
        })

        # 5. Synthesize root cause conclusion
        root_cause = await self._synthesize_root_cause(
            evaluated, evidence, knowledge
        )
        reasoning_chain.append({
            "step": "root_cause_synthesis",
            "conclusion": root_cause.description,
            "confidence": root_cause.confidence
        })

        self.logger.info(
            "diagnosis_complete",
            root_cause=root_cause.description[:100],
            confidence=root_cause.confidence
        )

        # Audit diagnosis completion
        audit.log(
            event_type=AuditEventType.DIAGNOSIS_COMPLETED,
            action="Diagnosis complete",
            incident_id=incident.incident_id,
            details={
                "root_cause": root_cause.description[:200],
                "confidence": root_cause.confidence,
                "hypotheses_tested": len(evaluated),
                "evidence_gathered": len(evidence)
            }
        )

        # Build diagnostic result
        diagnostic_result = DiagnosticResult(
            root_cause=root_cause,
            evidence=evidence,
            hypotheses_tested=[h for h, _ in evaluated],
            reasoning_chain=reasoning_chain,
            affected_systems=self._identify_affected_systems(evidence)
        )

        return {
            "diagnostic_result": diagnostic_result,
            "workflow_stage": WorkflowStage.DIAGNOSE,
            "messages": self.add_message(
                state,
                "assistant",
                f"Diagnosis complete: {root_cause.description} (confidence: {root_cause.confidence:.0%})"
            )
        }

    async def _generate_hypotheses(
        self,
        incident: Any,
        triage: Any,
        knowledge: Any
    ) -> List[Hypothesis]:
        """
        Generate ranked hypotheses using LLM with retrieved context.
        """
        # Build context from triage and knowledge
        context = self._build_hypothesis_context(incident, triage, knowledge)

        prompt = f"""Generate diagnostic hypotheses for this incident.

{context}

Generate 3-5 ranked hypotheses for the root cause. For each hypothesis provide:
1. A unique ID (e.g., "H1", "H2")
2. Description of the potential root cause
3. Prior probability (0.0-1.0) based on similar cases
4. Evidence needed to confirm or refute
5. Tools/queries to gather that evidence

Respond in JSON format with a "hypotheses" array."""

        response = await self.chat_completion(
            messages=[
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.4
        )

        try:
            result = json.loads(response)
            return [
                Hypothesis(
                    id=h.get("id", f"H{i}"),
                    description=h.get("description", "Unknown"),
                    prior_probability=float(h.get("prior_probability", 0.5)),
                    evidence_needed=h.get("evidence_needed", []),
                    tools_to_use=h.get("tools_to_use", [])
                )
                for i, h in enumerate(result.get("hypotheses", []))
            ]
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error("hypothesis_parse_error", error=str(e))
            # Return default hypothesis
            return [
                Hypothesis(
                    id="H1",
                    description=f"Error in {incident.job_name}",
                    prior_probability=0.5,
                    evidence_needed=["Job logs", "Error details"],
                    tools_to_use=["get_job_logs"]
                )
            ]

    def _get_system_prompt(self) -> str:
        """Get system prompt for diagnosis."""
        return """You are an expert incident diagnosis agent. Your job is to analyze
incidents systematically using chain-of-thought reasoning.

You follow the scientific method:
1. Form hypotheses based on evidence
2. Design investigations to test hypotheses
3. Gather and analyze evidence
4. Update beliefs based on evidence
5. Synthesize conclusions

Be thorough but efficient. Focus on the most likely root causes first."""

    def _build_hypothesis_context(
        self,
        incident: Any,
        triage: Any,
        knowledge: Any
    ) -> str:
        """Build context string for hypothesis generation."""
        parts = [
            f"## Incident",
            f"Job: {incident.job_name}",
            f"Type: {incident.job_type}",
            f"Error: {incident.error_message}",
        ]

        if triage:
            parts.extend([
                f"\n## Triage Classification",
                f"Category: {triage.classification.category.value}",
                f"Initial hypothesis: {triage.classification.root_cause_hypothesis}",
                f"Confidence: {triage.classification.hypothesis_confidence:.0%}"
            ])

            if triage.correlations and triage.correlations.correlations:
                parts.append("\n## Correlated Failures")
                for c in triage.correlations.correlations[:3]:
                    parts.append(f"- {c.type}: {c.relationship}")

        if knowledge:
            if knowledge.known_errors:
                parts.append("\n## Matching Known Errors")
                for ke in knowledge.known_errors[:2]:
                    parts.append(f"- {ke.title}: {ke.root_cause or 'No root cause documented'}")

            if knowledge.similar_incidents:
                parts.append("\n## Similar Past Incidents")
                for inc in knowledge.similar_incidents[:2]:
                    parts.append(
                        f"- {inc.incident_id}: {inc.root_cause or inc.error_message[:100]}"
                    )

        return "\n".join(parts)

    async def _plan_investigation(
        self,
        hypotheses: List[Hypothesis],
        incident: Any
    ) -> List[Dict[str, Any]]:
        """
        Plan investigation steps for hypotheses.
        """
        investigation_plan = []

        # Get available tools for this job type
        available_tools = self.tool_registry.list_tools()

        for hypothesis in hypotheses:
            for tool_name in hypothesis.tools_to_use:
                if tool_name in available_tools:
                    investigation_plan.append({
                        "hypothesis_id": hypothesis.id,
                        "tool": tool_name,
                        "reason": f"Testing: {hypothesis.description[:50]}..."
                    })

        # Add default investigation tools based on job type
        default_tools = self._get_default_tools(incident.job_type)
        for tool in default_tools:
            if tool not in [p["tool"] for p in investigation_plan]:
                investigation_plan.append({
                    "hypothesis_id": "general",
                    "tool": tool,
                    "reason": "Standard diagnostic tool"
                })

        return investigation_plan

    def _get_default_tools(self, job_type: str) -> List[str]:
        """Get default investigation tools for job type."""
        default_tools = {
            "databricks": [
                "get_job_run_details",
                "get_job_run_logs",
                "get_cluster_status"
            ],
            "iws": [
                "get_iws_job_status",
                "get_iws_job_log"
            ],
            "adf": [
                "get_pipeline_run",
                "get_activity_logs"
            ]
        }
        return default_tools.get(job_type, ["get_job_logs"])

    async def _gather_evidence_for_hypotheses(
        self,
        investigation_plan: List[Dict[str, Any]],
        incident: Any,
        state: AppSupportState
    ) -> List[Evidence]:
        """
        Execute investigation plan to gather evidence.
        """
        evidence = []

        for investigation in investigation_plan:
            tool_name = investigation["tool"]
            tool = self.tool_registry.get(tool_name)

            if not tool:
                evidence.append(Evidence(
                    source=tool_name,
                    tool_used=tool_name,
                    error=f"Tool not found: {tool_name}",
                    confidence=0.0
                ))
                continue

            # Build parameters from incident context
            params = self._build_tool_params(tool_name, incident)

            try:
                result = await self.execute_tool(tool_name, **params)

                # Record in state
                tool_calls = self.record_tool_call(
                    state, tool_name, params, result
                )

                if result.success:
                    # Analyze the evidence
                    analysis = await self._analyze_evidence(
                        investigation, result.data
                    )

                    evidence.append(Evidence(
                        source=investigation["reason"],
                        tool_used=tool_name,
                        raw_data=result.data,
                        analysis=analysis.get("analysis", ""),
                        supports_hypothesis=analysis.get("supports_hypothesis"),
                        confidence=analysis.get("confidence", 0.5)
                    ))
                else:
                    evidence.append(Evidence(
                        source=investigation["reason"],
                        tool_used=tool_name,
                        error=result.error,
                        confidence=0.0
                    ))

            except Exception as e:
                evidence.append(Evidence(
                    source=investigation["reason"],
                    tool_used=tool_name,
                    error=str(e),
                    confidence=0.0
                ))

        return evidence

    async def _analyze_evidence(
        self,
        investigation: Dict[str, Any],
        data: Any
    ) -> Dict[str, Any]:
        """
        Analyze evidence from tool execution.
        """
        prompt = f"""Analyze this evidence for incident investigation.

Investigation reason: {investigation['reason']}
Tool used: {investigation['tool']}

Data returned:
{json.dumps(data, indent=2, default=str)[:2000]}

Provide your analysis in JSON format:
- analysis: brief summary of what the evidence shows
- supports_hypothesis: ID of hypothesis this supports (or null)
- confidence: confidence in this evidence (0.0-1.0)
- key_findings: list of important findings"""

        try:
            response = await self.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.2
            )
            return json.loads(response)
        except Exception:
            return {
                "analysis": "Unable to analyze evidence",
                "confidence": 0.3
            }

    async def _evaluate_hypotheses(
        self,
        hypotheses: List[Hypothesis],
        evidence: List[Evidence]
    ) -> List[tuple[Hypothesis, float]]:
        """
        Evaluate hypotheses based on gathered evidence.
        """
        evaluated = []

        for hypothesis in hypotheses:
            # Count supporting and refuting evidence
            supporting = 0
            refuting = 0
            total_confidence = 0

            for e in evidence:
                if e.supports_hypothesis == hypothesis.id:
                    supporting += 1
                    total_confidence += e.confidence
                elif e.supports_hypothesis and e.supports_hypothesis != hypothesis.id:
                    refuting += 1

            # Calculate posterior probability using simple Bayesian update
            prior = hypothesis.prior_probability

            if supporting + refuting > 0:
                # Simplified: adjust prior based on evidence ratio
                evidence_ratio = supporting / (supporting + refuting + 1)
                avg_confidence = total_confidence / max(supporting, 1)

                posterior = prior * (0.5 + evidence_ratio * avg_confidence)
                posterior = min(0.95, max(0.05, posterior))
            else:
                posterior = prior * 0.8  # Slight discount if no evidence

            evaluated.append((hypothesis, posterior))

        # Sort by posterior probability
        return sorted(evaluated, key=lambda x: x[1], reverse=True)

    async def _synthesize_root_cause(
        self,
        evaluated: List[tuple[Hypothesis, float]],
        evidence: List[Evidence],
        knowledge: Any
    ) -> RootCause:
        """
        Synthesize final root cause from evaluation.
        """
        # Get top hypothesis
        if not evaluated:
            return RootCause(
                description="Unable to determine root cause",
                confidence=0.0,
                supporting_evidence=[],
                recommended_approach="escalate_human"
            )

        top_hypothesis, top_score = evaluated[0]

        # Gather supporting evidence
        supporting_evidence = [
            e.analysis for e in evidence
            if e.supports_hypothesis == top_hypothesis.id and e.analysis
        ]

        # Use LLM to synthesize conclusion
        prompt = f"""Synthesize the root cause conclusion.

Top Hypothesis: {top_hypothesis.description}
Confidence Score: {top_score:.0%}

Supporting Evidence:
{chr(10).join(f'- {e}' for e in supporting_evidence[:5])}

Alternative Hypotheses:
{chr(10).join(f'- {h.description} ({s:.0%})' for h, s in evaluated[1:3])}

Provide your conclusion:
1. Precise root cause description
2. Key supporting evidence
3. Any remaining uncertainty
4. Recommended remediation approach"""

        try:
            response = await self.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )

            return RootCause(
                description=f"{top_hypothesis.description}",
                confidence=top_score,
                supporting_evidence=supporting_evidence[:3],
                remaining_uncertainty=self._extract_uncertainty(response),
                recommended_approach=self._determine_approach(top_score)
            )
        except Exception:
            return RootCause(
                description=top_hypothesis.description,
                confidence=top_score,
                supporting_evidence=supporting_evidence[:3],
                recommended_approach=self._determine_approach(top_score)
            )

    def _extract_uncertainty(self, response: str) -> Optional[str]:
        """Extract uncertainty from LLM response."""
        if "uncertain" in response.lower() or "unclear" in response.lower():
            # Find sentence containing uncertainty
            sentences = response.split(".")
            for s in sentences:
                if "uncertain" in s.lower() or "unclear" in s.lower():
                    return s.strip()
        return None

    def _determine_approach(self, confidence: float) -> str:
        """Determine recommended approach based on confidence."""
        if confidence >= 0.8:
            return "auto_fix"
        elif confidence >= 0.6:
            return "propose_fix"
        else:
            return "manual_investigation"

    def _identify_affected_systems(self, evidence: List[Evidence]) -> List[str]:
        """Identify affected systems from evidence."""
        systems = set()

        for e in evidence:
            if e.raw_data and isinstance(e.raw_data, dict):
                # Look for system identifiers in data
                for key in ["cluster_id", "job_name", "database", "service"]:
                    if key in e.raw_data:
                        systems.add(str(e.raw_data[key]))

        return list(systems)
