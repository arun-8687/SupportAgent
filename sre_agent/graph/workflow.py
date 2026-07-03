"""
The SRE incident-response graph.

    intake ── triage ──┬── suppress ── END
                       │
                       └── plan_investigation
                              │  (Send fan-out: one task per selected subagent)
                        run_subagent ×N
                              │  (findings merge via additive reducer)
                        analyze_root_cause
                              │
                        propose_mitigation ── open_ticket ── permission_gate
                                                                  │
                    ┌─────────────────────────┬───────────────────┤
              auto_approve             await_approval          escalate
                    │                  (interrupt: human)          │
                    └────────────┬─────────┘                       │
                          execute_mitigation                       │
                                 │                                 │
                              verify ──── unhealthy/failed ────────┤
                                 │                                 │
                              resolve ── END              escalate ── END
"""
import logging
from typing import List, Optional, Union

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, StateGraph
from langgraph.types import Send

from sre_agent.config import get_settings
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.graph.state import SREState
from sre_agent.models import GateOutcome

logger = logging.getLogger(__name__)


def _serializer() -> JsonPlusSerializer:
    """Serde with our state models explicitly registered.

    Future langgraph versions block deserializing unregistered types from
    checkpoints; registering sre_agent.models keeps resume working across
    upgrades (and silences the current warnings).
    """
    import enum

    import pydantic

    import sre_agent.models as models

    allowed = [
        ("sre_agent.models", name)
        for name, obj in vars(models).items()
        if isinstance(obj, type)
        and issubclass(obj, (pydantic.BaseModel, enum.Enum))
        and obj.__module__ == "sre_agent.models"
    ]
    return JsonPlusSerializer(allowed_msgpack_modules=allowed)


def create_checkpointer():
    """
    Build the checkpointer the graph needs for interrupt/resume.

    - SRE_AGENT_DATABASE_URL set -> Postgres (durable: approvals survive
      restarts and resume on any instance).
    - unset in development       -> MemorySaver (single-process only).
    - unset in production        -> hard failure. A silently non-durable
      checkpointer means paused approvals die on scale-in/restart.
    """
    settings = get_settings()
    if settings.database_url:
        try:
            from langgraph.checkpoint.postgres import PostgresSaver
        except ImportError as exc:
            raise RuntimeError(
                "SRE_AGENT_DATABASE_URL is set but langgraph-checkpoint-postgres "
                "is not installed (pip install langgraph-checkpoint-postgres)."
            ) from exc
        checkpointer = PostgresSaver.from_conn_string(settings.database_url)
        # from_conn_string returns a context manager in recent versions;
        # enter it eagerly for a long-lived saver.
        if hasattr(checkpointer, "__enter__") and not hasattr(checkpointer, "get_tuple"):
            checkpointer = checkpointer.__enter__()  # pragma: no cover
        checkpointer.setup()
        return checkpointer

    if settings.is_production:
        raise RuntimeError(
            "Production requires a durable checkpointer: set "
            "SRE_AGENT_DATABASE_URL (Postgres). MemorySaver loses paused "
            "approvals on restart/scale-out."
        )
    return MemorySaver(serde=_serializer())


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #

def route_after_triage(state: SREState) -> str:
    triage = state.get("triage")
    if triage and not triage.requires_investigation:
        return "suppress"
    return "plan_investigation"


def dispatch_subagents(state: SREState) -> List[Send]:
    """Fan out one run_subagent task per planned subagent (map-reduce)."""
    incident = state["incident"]
    return [
        Send("run_subagent", {"incident": incident, "subagent": name})
        for name in state["plan"].subagents
    ]


def route_after_gate(state: SREState) -> str:
    if state.get("error"):
        return "escalate"  # a before_mitigation hook vetoed the plan
    decisions = state.get("gate_decisions", [])
    if not decisions:
        return "escalate"
    if all(d.outcome == GateOutcome.DENY for d in decisions):
        return "escalate"
    if any(d.outcome == GateOutcome.REQUIRE_APPROVAL for d in decisions):
        return "await_approval"
    return "auto_approve"


def route_after_approval(state: SREState) -> str:
    approval = state.get("approval")
    if approval and approval.approved:
        return "execute_mitigation"
    return "escalate"


def route_after_execution(state: SREState) -> str:
    execution = state.get("execution")
    if execution and execution.success:
        return "verify"
    return "escalate"


def route_after_verification(state: SREState) -> str:
    verification = state.get("verification")
    if verification and verification.healthy:
        return "resolve"
    return "escalate"


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #

def build_workflow(
    nodes: Optional[SREAgentNodes] = None,
    checkpointer: Optional[Union[MemorySaver, object]] = None,
):
    """
    Build and compile the SRE incident graph.

    A checkpointer is required because await_approval uses interrupt().
    When none is passed, create_checkpointer() picks one from settings
    (Postgres when SRE_AGENT_DATABASE_URL is set; MemorySaver in dev;
    hard failure in production without a durable store).
    """
    nodes = nodes or SREAgentNodes()
    graph = StateGraph(SREState)

    graph.add_node("intake", nodes.intake)
    graph.add_node("triage", nodes.triage)
    graph.add_node("suppress", nodes.suppress)
    graph.add_node("plan_investigation", nodes.plan_investigation)
    graph.add_node("run_subagent", nodes.run_subagent)
    graph.add_node("analyze_root_cause", nodes.analyze_root_cause)
    graph.add_node("propose_mitigation", nodes.propose_mitigation)
    graph.add_node("open_ticket", nodes.open_ticket)
    graph.add_node("permission_gate", nodes.permission_gate)
    graph.add_node("await_approval", nodes.await_approval)
    graph.add_node("auto_approve", nodes.auto_approve)
    graph.add_node("execute_mitigation", nodes.execute_mitigation)
    graph.add_node("verify", nodes.verify)
    graph.add_node("resolve", nodes.resolve)
    graph.add_node("escalate", nodes.escalate)

    graph.set_entry_point("intake")
    graph.add_edge("intake", "triage")
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {"suppress": "suppress", "plan_investigation": "plan_investigation"},
    )
    graph.add_edge("suppress", END)

    # Dynamic fan-out to selected subagents; findings merge additively,
    # then a single analyze_root_cause reduces them.
    graph.add_conditional_edges("plan_investigation", dispatch_subagents, ["run_subagent"])
    graph.add_edge("run_subagent", "analyze_root_cause")

    graph.add_edge("analyze_root_cause", "propose_mitigation")
    graph.add_edge("propose_mitigation", "open_ticket")
    graph.add_edge("open_ticket", "permission_gate")

    graph.add_conditional_edges(
        "permission_gate",
        route_after_gate,
        {
            "await_approval": "await_approval",
            "auto_approve": "auto_approve",
            "escalate": "escalate",
        },
    )
    graph.add_conditional_edges(
        "await_approval",
        route_after_approval,
        {"execute_mitigation": "execute_mitigation", "escalate": "escalate"},
    )
    graph.add_edge("auto_approve", "execute_mitigation")
    graph.add_conditional_edges(
        "execute_mitigation",
        route_after_execution,
        {"verify": "verify", "escalate": "escalate"},
    )
    graph.add_conditional_edges(
        "verify",
        route_after_verification,
        {"resolve": "resolve", "escalate": "escalate"},
    )
    graph.add_edge("resolve", END)
    graph.add_edge("escalate", END)

    return graph.compile(checkpointer=checkpointer or create_checkpointer())
