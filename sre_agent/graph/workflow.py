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
import time
from typing import Any, Callable, List, Optional, Union

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, StateGraph
from langgraph.types import Send

from sre_agent.config import get_settings
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.graph.state import SREState
from sre_agent.models import GateOutcome
from sre_agent.observability import log_step, span

try:  # interrupt() pauses the graph by raising GraphInterrupt — not an error
    from langgraph.errors import GraphInterrupt
except ImportError:  # pragma: no cover
    GraphInterrupt = ()  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _traced(name: str, fn: Callable) -> Callable:
    """Wrap a node so every execution emits a step record + span.

    One wrapper instruments all nodes uniformly: started/completed/failed
    (or paused, for the approval interrupt) with incident correlation and
    duration — the "agents log at each step" guarantee lives here, not in
    each node body.
    """

    async def wrapper(state: Any) -> Any:
        incident = state.get("incident") if isinstance(state, dict) else None
        incident_id = getattr(incident, "incident_id", None)
        service = getattr(incident, "service_name", None)
        started = time.monotonic()

        with span(
            f"sre_agent.node.{name}",
            node=name,
            incident_id=incident_id,
            service_name=service,
        ):
            try:
                result = await fn(state)
            except GraphInterrupt:
                # await_approval pausing for a human — expected, not a failure.
                log_step(
                    name, "paused", incident_id,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    service_name=service,
                )
                raise
            except Exception as exc:
                log_step(
                    name, "failed", incident_id,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    service_name=service,
                    error=str(exc)[:300],
                    level=logging.ERROR,
                )
                raise

        outcome = None
        if isinstance(result, dict):
            outcome = getattr(result.get("status"), "value", result.get("status"))
        log_step(
            name, "completed", incident_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            service_name=service,
            workflow_status=outcome,
        )
        return result

    wrapper.__name__ = name
    return wrapper


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

    # Every node is wrapped so each step logs start/outcome/duration to
    # App Insights with incident correlation (see _traced).
    for name, fn in (
        ("intake", nodes.intake),
        ("triage", nodes.triage),
        ("suppress", nodes.suppress),
        ("plan_investigation", nodes.plan_investigation),
        ("run_subagent", nodes.run_subagent),
        ("analyze_root_cause", nodes.analyze_root_cause),
        ("propose_mitigation", nodes.propose_mitigation),
        ("open_ticket", nodes.open_ticket),
        ("permission_gate", nodes.permission_gate),
        ("await_approval", nodes.await_approval),
        ("auto_approve", nodes.auto_approve),
        ("execute_mitigation", nodes.execute_mitigation),
        ("verify", nodes.verify),
        ("resolve", nodes.resolve),
        ("escalate", nodes.escalate),
    ):
        graph.add_node(name, _traced(name, fn))

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
