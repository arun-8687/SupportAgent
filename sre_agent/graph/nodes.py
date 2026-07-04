"""
Workflow nodes for the SRE incident-response graph.

Each node is a method on SREAgentNodes so tool clients, registries, the
permission gate, hooks, and the knowledge store are injectable — swap any
of them for live implementations without touching the graph shape.
"""
import logging
import uuid
from typing import Any, Dict, List

from langgraph.types import interrupt

from sre_agent.config import get_settings
from sre_agent.gate.permission_gate import PermissionGate
from sre_agent.graph.state import SREState
from sre_agent.hooks.engine import HookEngine
from sre_agent.llm import generate_structured
from sre_agent.memory.knowledge_store import KnowledgeStore
from sre_agent.memory.unified import AgentMemory
from sre_agent.models import (
    ActionResult,
    ApprovalRecord,
    ExecutionReport,
    GateOutcome,
    HookEvent,
    Incident,
    IncidentStatus,
    InvestigationPlan,
    KnowledgeMatch,
    KnowledgeRecord,
    MitigationAction,
    MitigationPlan,
    RiskLevel,
    SessionInsight,
    Severity,
    SubagentFinding,
    TriageAssessment,
    VerificationReport,
)
from sre_agent.security import EXTERNAL_DATA_CAUTION, external_data_block
from sre_agent.skills.executor import SkillExecutor
from sre_agent.skills.registry import SkillRegistry
from sre_agent.subagents.registry import SubagentRegistry
from sre_agent.tools.observability import ObservabilityClient
from sre_agent.tools.ticketing import TicketClient

logger = logging.getLogger(__name__)

CATEGORY_KEYWORDS = {
    "memory": ("memory", "oom", "heap", "leak"),
    "availability": ("5xx", "unavailable", "outage", "down", "error rate"),
    "latency": ("latency", "slow", "timeout", "response time"),
    "deployment": ("deploy", "release", "rollout"),
    "capacity": ("cpu", "throttl", "quota", "saturat"),
}


def _detect_category(text: str) -> str:
    lowered = text.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            return category
    return "unknown"


class SREAgentNodes:
    """All graph nodes with injectable dependencies."""

    def __init__(
        self,
        subagents: SubagentRegistry | None = None,
        skills: SkillRegistry | None = None,
        gate: PermissionGate | None = None,
        hooks: HookEngine | None = None,
        knowledge: KnowledgeStore | None = None,
        memory: AgentMemory | None = None,
        tickets: TicketClient | None = None,
        executor: SkillExecutor | None = None,
        observability: ObservabilityClient | None = None,
    ) -> None:
        self.skills = skills or SkillRegistry()
        self.subagents = subagents or SubagentRegistry(skills=self.skills)
        self.gate = gate or PermissionGate()
        self.hooks = hooks or HookEngine()
        self.knowledge = knowledge or KnowledgeStore()
        # Unified memory: past incidents + user memories + knowledge base +
        # synthesized markdown files, all searched together.
        self.memory = memory or AgentMemory(incidents=self.knowledge)
        self.tickets = tickets or TicketClient()
        self.executor = executor or SkillExecutor(registry=self.skills, hooks=self.hooks)
        self.observability = observability or ObservabilityClient()
        # Operator instructions for how incidents are handled here.
        plan_file = get_settings().response_plan_file
        self.response_plan = (
            plan_file.read_text(encoding="utf-8") if plan_file.exists() else ""
        )

    # ------------------------------------------------------------------ #
    # Intake & triage
    # ------------------------------------------------------------------ #

    async def intake(self, state: SREState) -> Dict[str, Any]:
        """Fire investigation_started hooks and move to triage."""
        incident = state["incident"]
        hook_results = await self.hooks.fire(
            HookEvent.INVESTIGATION_STARTED,
            {
                "incident_id": incident.incident_id,
                "service": incident.service_name,
                "title": incident.alert.title,
            },
        )
        return {"status": IncidentStatus.TRIAGING, "hook_results": hook_results}

    async def triage(self, state: SREState) -> Dict[str, Any]:
        """Classify severity/category; search unified memory for context."""
        incident = state["incident"]
        alert = incident.alert
        text = f"{alert.title} {alert.description}"

        category = _detect_category(text)
        severity = alert.severity_hint or (
            Severity.SEV1
            if any(kw in text.lower() for kw in ("outage", "down"))
            else Severity.SEV2 if incident.environment == "prod" else Severity.SEV3
        )
        # One query across all sources: past incidents (same-resource
        # prioritized), user memories, knowledge base, synthesized files.
        # knowledge_matches is derived from the same results — no second
        # pass over the incident store.
        memory_matches = self.memory.search(text, service_name=incident.service_name)
        knowledge_matches = [
            KnowledgeMatch(
                record_id=m.citation,
                title=m.title,
                resolution=m.content,
                similarity=m.similarity,
            )
            for m in memory_matches
            if m.source == "past_incident"
        ]

        assessment = TriageAssessment(
            severity=severity,
            category=category,
            summary=(
                f"{alert.title} on {incident.service_name} ({incident.environment}); "
                f"category={category}, severity={severity.value}."
            ),
            requires_investigation="[test]" not in alert.title.lower(),
            knowledge_matches=knowledge_matches,
            memory_matches=memory_matches,
        )
        incident.severity = severity
        return {
            "incident": incident,
            "triage": assessment,
            "status": IncidentStatus.INVESTIGATING,
        }

    # ------------------------------------------------------------------ #
    # Planning & subagent fan-out
    # ------------------------------------------------------------------ #

    async def plan_investigation(self, state: SREState) -> Dict[str, Any]:
        """Select which subagents to run for this incident."""
        incident = state["incident"]
        triage = state["triage"]

        def heuristic() -> InvestigationPlan:
            selected = ["logs_metrics", "source_code"]
            if incident.environment == "prod" or triage.severity in (Severity.SEV1, Severity.SEV2):
                selected.append("architecture")
            selected.append("scanning")
            return InvestigationPlan(
                subagents=selected,
                reasoning=(
                    f"Category '{triage.category}' at {triage.severity.value}: telemetry and "
                    "change correlation always run; topology and config scan added for "
                    "high-severity/production incidents."
                ),
            )

        overview = self.memory.system_context()
        memory_context = "\n".join(
            f"- [{m.source}:{m.citation}] {m.content[:160]}"
            for m in triage.memory_matches[:3]
        )
        # Prompt layout: fully static content first (identical across
        # incidents -> provider prompt-prefix caching), per-incident
        # context last. The response plan is mitigation/escalation
        # guidance — it belongs to the proposer, not to subagent selection.
        plan = await generate_structured(
            system_prompt=(
                "You are the investigation planner of an SRE agent. Choose which "
                "subagents to run for this incident. Available subagents "
                "(handoff descriptions):\n" + self.subagents.descriptions()
                + f"\n\n{EXTERNAL_DATA_CAUTION}"
                + (f"\n\nEnvironment overview:\n{overview}" if overview else "")
            ),
            user_prompt=(
                f"Incident: {triage.summary}\n"
                f"Alert (untrusted):\n{external_data_block(incident.alert.description)}"
                + (f"\n\nRelevant memory:\n{memory_context}" if memory_context else "")
            ),
            schema=InvestigationPlan,
            fallback=heuristic,
        )
        # Guard against hallucinated subagent names.
        valid = [name for name in plan.subagents if name in self.subagents.names()]
        plan.subagents = valid or heuristic().subagents
        return {"plan": plan}

    async def run_subagent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Worker node: run one subagent (invoked via Send fan-out)."""
        incident: Incident = payload["incident"]
        name: str = payload["subagent"]
        finding = await self.subagents.get(name).investigate(incident)
        return {"findings": [finding]}

    async def analyze_root_cause(self, state: SREState) -> Dict[str, Any]:
        """Synthesize all findings into a root cause hypothesis."""
        rca = await self.subagents.root_cause.synthesize(
            state["incident"], state.get("findings", [])
        )
        return {"root_cause": rca, "status": IncidentStatus.ANALYZING}

    # ------------------------------------------------------------------ #
    # Mitigation proposal & ticketing
    # ------------------------------------------------------------------ #

    async def propose_mitigation(self, state: SREState) -> Dict[str, Any]:
        """Propose mitigations, preferring registered skills."""
        incident = state["incident"]
        triage = state["triage"]
        rca = state["root_cause"]

        # Load the most relevant skills: their SKILL.md guidance steers the
        # plan, and their attached tools become the executable actions.
        query = f"{triage.category} {rca.hypothesis} {incident.alert.title}"
        relevant_skills = self.skills.find_relevant(query)
        for skill in relevant_skills:
            self.skills.activate(skill.name)

        def heuristic() -> MitigationPlan:
            actions: List[MitigationAction] = []
            for skill in relevant_skills[:2]:
                # The first tool in a skill manifest is its primary action.
                tool = skill.tools[0] if skill.tools else None
                if tool is None:
                    continue
                actions.append(
                    MitigationAction(
                        action_id=f"act-{uuid.uuid4().hex[:8]}",
                        name=tool.name,
                        kind="skill",
                        skill_name=skill.name,
                        tool_name=tool.name,
                        parameters=self._default_parameters(tool.parameters, incident),
                        description=tool.description or skill.description,
                        risk=tool.risk,
                        supports_rollback=tool.supports_rollback,
                    )
                )
            if rca.correlated_change:
                actions.append(
                    MitigationAction(
                        action_id=f"act-{uuid.uuid4().hex[:8]}",
                        name="review_correlated_change",
                        kind="manual",
                        description=(
                            f"Review/rollback correlated change "
                            f"{rca.correlated_change.identifier}: "
                            f"{rca.correlated_change.description}"
                        ),
                        risk=RiskLevel.LOW,
                    )
                )
            return MitigationPlan(
                actions=actions,
                reasoning=f"Derived from root cause: {rca.hypothesis}",
                expected_outcome="Restore service health and stop the failure trend.",
            )

        # Static content (catalog, response plan) leads for prompt-prefix
        # caching; the per-incident skill guidance (capped per skill by the
        # registry) comes last.
        plan = await generate_structured(
            system_prompt=(
                "You are the mitigation planner of an SRE agent. Propose the "
                "smallest safe set of actions. Prefer registered skill tools "
                "(set skill_name and tool_name exactly):\n"
                + self.skills.catalog_text()
                + (f"\n\nIncident response plan:\n{self.response_plan}" if self.response_plan else "")
                + (
                    f"\n\nActive skill guidance:\n{self.skills.active_guidance()}"
                    if relevant_skills else ""
                )
            ),
            user_prompt=(
                f"Root cause: {rca.hypothesis} (confidence {rca.confidence})\n"
                f"Service: {incident.service_name} ({incident.environment})\n"
                f"Impact: {rca.impact_assessment[:400]}"
            ),
            schema=MitigationPlan,
            fallback=heuristic,
        )
        for action in plan.actions:
            if not action.action_id:
                action.action_id = f"act-{uuid.uuid4().hex[:8]}"
        if not plan.actions:
            plan = heuristic()
        return {"mitigation_plan": plan, "status": IncidentStatus.PROPOSING}

    @staticmethod
    def _default_parameters(names: List[str], incident: Incident) -> Dict[str, Any]:
        """Fill skill parameters from incident context (best effort)."""
        defaults = {
            "resource_group": incident.alert.resource.resource_group or "unknown-rg",
            "app_name": incident.service_name,
            "namespace": incident.environment,
            "deployment": incident.service_name,
            "hpa_name": f"{incident.service_name}-hpa",
            "max_replicas": 10,
        }
        return {name: defaults.get(name, "") for name in names}

    async def open_ticket(self, state: SREState) -> Dict[str, Any]:
        """Create the incident ticket prefilled with the investigation."""
        incident = state["incident"]
        ticket = await self.tickets.create_ticket(
            title=f"[{incident.severity.value.upper()}] {incident.alert.title}",
            body=self._investigation_summary(state),
            severity=incident.severity.value,
        )
        return {"ticket": ticket}

    @staticmethod
    def _investigation_summary(state: SREState) -> str:
        incident = state["incident"]
        rca = state.get("root_cause")
        plan = state.get("mitigation_plan")
        lines = [
            f"Service: {incident.service_name} ({incident.environment})",
            f"Alert: {incident.alert.title} [{incident.alert.source.value}]",
            "",
            "== Root cause hypothesis ==",
            f"{rca.hypothesis} (confidence {rca.confidence})" if rca else "n/a",
        ]
        if rca and rca.correlated_change:
            lines.append(
                f"Correlated change: {rca.correlated_change.identifier} - "
                f"{rca.correlated_change.description}"
            )
        if rca and rca.impact_assessment:
            lines.append(f"Impact: {rca.impact_assessment}")
        lines += ["", "== Findings =="]
        for finding in state.get("findings", []):
            lines.append(f"- [{finding.subagent}] {finding.summary}")
        if plan:
            lines += ["", "== Proposed mitigations =="]
            for action in plan.actions:
                lines.append(
                    f"- {action.name} ({action.risk.value} risk, {action.kind}): "
                    f"{action.description}"
                )
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Permission gate & approval
    # ------------------------------------------------------------------ #

    async def permission_gate(self, state: SREState) -> Dict[str, Any]:
        """Evaluate every proposed action; fire before_mitigation hooks."""
        incident = state["incident"]
        plan = state["mitigation_plan"]

        hook_results = await self.hooks.fire(
            HookEvent.BEFORE_MITIGATION,
            {
                "incident_id": incident.incident_id,
                "root_cause": state["root_cause"].hypothesis,
                "actions": [a.model_dump(mode="json") for a in plan.actions],
            },
        )
        veto = self.hooks.blocked_by(hook_results)
        if veto:
            return {
                "hook_results": hook_results,
                "gate_decisions": [],
                "error": f"Blocked by hook '{veto.hook}': {veto.decision.get('reason', '')}",
            }

        decisions = self.gate.evaluate_plan(plan.actions, incident.environment)
        return {"gate_decisions": decisions, "hook_results": hook_results}

    async def await_approval(self, state: SREState) -> Dict[str, Any]:
        """Pause the graph for human sign-off (LangGraph interrupt)."""
        plan = state["mitigation_plan"]
        pending = [
            d.action_id
            for d in state["gate_decisions"]
            if d.outcome == GateOutcome.REQUIRE_APPROVAL
        ]
        response = interrupt(
            {
                "type": "approval_request",
                "incident_id": state["incident"].incident_id,
                "ticket_id": state.get("ticket").ticket_id if state.get("ticket") else None,
                "root_cause": state["root_cause"].hypothesis,
                "actions": [
                    a.model_dump(mode="json")
                    for a in plan.actions
                    if a.action_id in pending
                ],
            }
        )
        approval = ApprovalRecord(
            approved=bool(response.get("approved", False)),
            approver=response.get("approver", "unknown"),
            channel=response.get("channel", "http"),
            reason=response.get("reason", ""),
        )
        return {
            "approval": approval,
            "status": IncidentStatus.MITIGATING if approval.approved else IncidentStatus.ESCALATED,
        }

    async def auto_approve(self, state: SREState) -> Dict[str, Any]:
        """All gated actions were allowed by policy — record it."""
        return {
            "approval": ApprovalRecord(
                approved=True,
                approver="permission-gate",
                channel="auto",
                reason="All actions allowed by gate policy",
            ),
            "status": IncidentStatus.MITIGATING,
        }

    # ------------------------------------------------------------------ #
    # Execution, verification, resolution
    # ------------------------------------------------------------------ #

    async def execute_mitigation(self, state: SREState) -> Dict[str, Any]:
        """Run approved (non-denied) actions through the skill executor."""
        incident_id = state["incident"].incident_id
        denied = {
            d.action_id
            for d in state.get("gate_decisions", [])
            if d.outcome == GateOutcome.DENY
        }
        results: List[ActionResult] = []
        for action in state["mitigation_plan"].actions:
            if action.action_id in denied:
                results.append(
                    ActionResult(
                        action_id=action.action_id,
                        success=False,
                        error="Denied by permission gate",
                        dry_run=True,
                    )
                )
                continue
            results.append(
                await self.executor.execute(action, incident_id=incident_id)
            )

        executed = [r for r in results if r.error != "Denied by permission gate"]
        success = bool(executed) and all(r.success for r in executed)
        return {
            "execution": ExecutionReport(success=success, results=results),
            "status": IncidentStatus.VERIFYING,
        }

    async def verify(self, state: SREState) -> Dict[str, Any]:
        """Probe service health after mitigation."""
        incident = state["incident"]
        health = await self.observability.check_health(
            incident.alert.resource.resource_id
        )
        healthy = health.get("status") == "healthy"
        return {
            "verification": VerificationReport(
                healthy=healthy,
                checks=[health],
                notes="Post-mitigation health probe",
            )
        }

    def _build_session_insight(self, state: SREState, outcome: str) -> SessionInsight:
        """Extract structured learnings from the finished thread."""
        incident = state["incident"]
        rca = state.get("root_cause")
        symptoms = [
            e.observation
            for f in state.get("findings", [])
            for e in f.evidence
            if e.source in ("log_analytics", "azure_monitor", "alert_signals")
        ][:5]
        resolution_steps, pitfalls = [], []
        plan = state.get("mitigation_plan")
        execution = state.get("execution")
        if plan and execution:
            for action, result in zip(plan.actions, execution.results):
                if result.success:
                    resolution_steps.append(f"{action.name}: {action.description}")
                else:
                    pitfalls.append(f"{action.name} did not work: {result.error}")
        return SessionInsight(
            insight_id=self.memory.new_insight_id(),
            incident_id=incident.incident_id,
            service_name=incident.service_name,
            symptoms_observed=symptoms,
            resolution_steps=resolution_steps,
            root_cause=rca.hypothesis if rca else "",
            pitfalls_to_avoid=pitfalls,
            outcome=outcome,
        )

    async def resolve(self, state: SREState) -> Dict[str, Any]:
        """Close the loop: validate via Stop hooks, update ticket, learn."""
        incident = state["incident"]
        rca = state["root_cause"]
        executed = [
            f"{a.name}: {r.output or r.error}"
            for a, r in zip(
                state["mitigation_plan"].actions,
                state["execution"].results,
            )
        ]
        summary = (
            f"Resolved. Root cause: {rca.hypothesis}. "
            f"Mitigations executed: {len(executed)}."
        )

        # Stop hooks validate the final response before it reaches users;
        # a rejection makes the agent amend the summary with what's missing.
        stop_results = await self.hooks.fire(
            HookEvent.STOP,
            {
                "hook_event_name": "Stop",
                "agent_name": "sre_agent",
                "final_output": summary,
                "stop_hook_active": True,
            },
        )
        veto = self.hooks.blocked_by(stop_results)
        if veto:
            reason = (veto.decision or {}).get("reason", "")
            summary += (
                f" Additional detail (Stop hook '{veto.hook}'): {reason} "
                f"Actions taken: {'; '.join(executed)}."
            )

        record = self.knowledge.save(
            KnowledgeRecord(
                record_id=self.knowledge.new_record_id(),
                incident_id=incident.incident_id,
                service_name=incident.service_name,
                title=incident.alert.title,
                category=state["triage"].category,
                root_cause=rca.hypothesis,
                mitigations=[a.name for a in state["mitigation_plan"].actions],
                outcome="resolved",
                tags=[incident.environment, state["triage"].category],
            )
        )
        # Session insight -> insight log + synthesized knowledge md files.
        self.memory.capture_session_insight(
            self._build_session_insight(state, outcome="resolved")
        )

        ticket = state.get("ticket")
        if ticket:
            ticket = await self.tickets.update_ticket(ticket, summary, "resolved")

        hook_results = await self.hooks.fire(
            HookEvent.AFTER_RESOLUTION,
            {"incident_id": incident.incident_id, "summary": summary},
        )
        return {
            "status": IncidentStatus.RESOLVED,
            "resolution_summary": summary,
            "knowledge_record_id": record.record_id,
            "ticket": ticket,
            "hook_results": stop_results + hook_results,
        }

    async def escalate(self, state: SREState) -> Dict[str, Any]:
        """Hand off to a human with everything the agent learned so far."""
        incident = state["incident"]
        reason = state.get("error") or (
            "Approval rejected" if state.get("approval") and not state["approval"].approved
            else "Automated mitigation could not proceed"
        )
        summary = f"Escalated to on-call: {reason}"

        record_id = ""
        if state.get("root_cause"):
            record = self.knowledge.save(
                KnowledgeRecord(
                    record_id=self.knowledge.new_record_id(),
                    incident_id=incident.incident_id,
                    service_name=incident.service_name,
                    title=incident.alert.title,
                    category=state["triage"].category if state.get("triage") else "unknown",
                    root_cause=state["root_cause"].hypothesis,
                    mitigations=[],
                    outcome="escalated",
                    tags=[incident.environment],
                )
            )
            record_id = record.record_id
            # Escalations teach the agent too: what didn't work matters.
            self.memory.capture_session_insight(
                self._build_session_insight(state, outcome="escalated")
            )

        ticket = state.get("ticket")
        if ticket:
            ticket = await self.tickets.update_ticket(ticket, summary, "escalated")

        hook_results = await self.hooks.fire(
            HookEvent.ON_ESCALATION,
            {"incident_id": incident.incident_id, "reason": reason},
        )
        return {
            "status": IncidentStatus.ESCALATED,
            "resolution_summary": summary,
            "knowledge_record_id": record_id,
            "ticket": ticket,
            "hook_results": hook_results,
        }

    async def suppress(self, state: SREState) -> Dict[str, Any]:
        """Duplicate/test alerts end here without investigation."""
        return {
            "status": IncidentStatus.SUPPRESSED,
            "resolution_summary": "Alert suppressed at triage (test or duplicate).",
        }
