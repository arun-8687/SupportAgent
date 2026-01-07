"""
Observability - Metrics, Structured Logging, and Tracing.

Production-grade observability for:
- LangSmith tracing (primary for LLM operations)
- Prometheus metrics
- Structured JSON logging
- Health checks
- Audit logging
"""
import functools
import json
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar
from uuid import uuid4

import structlog
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST,
    CollectorRegistry
)

# Create a custom registry to avoid conflicts
REGISTRY = CollectorRegistry()


# ============================================================================
# LANGSMITH INTEGRATION (Primary tracing for LLM operations)
# ============================================================================

# Import LangSmith components - these provide the main tracing
try:
    from src.observability.langsmith_integration import (
        langsmith,
        get_langsmith,
        traced_operation,
        traced_agent,
        traced_tool,
        LangSmithObservability
    )
    LANGSMITH_AVAILABLE = True
except ImportError:
    LANGSMITH_AVAILABLE = False
    langsmith = None

    def get_langsmith():
        return None

    def traced_operation(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def traced_agent(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def traced_tool(*args, **kwargs):
        def decorator(func):
            return func
        return decorator


# ============================================================================
# METRICS
# ============================================================================

class MetricsRegistry:
    """
    Prometheus metrics for the Support Agent.
    """

    def __init__(self, registry: CollectorRegistry = REGISTRY):
        self.registry = registry

        # Incident metrics
        self.incidents_received = Counter(
            'support_agent_incidents_received_total',
            'Total number of incidents received',
            ['job_type', 'environment', 'source_system'],
            registry=registry
        )

        self.incidents_resolved = Counter(
            'support_agent_incidents_resolved_total',
            'Total number of incidents resolved',
            ['job_type', 'resolution_type', 'automated'],
            registry=registry
        )

        self.incidents_escalated = Counter(
            'support_agent_incidents_escalated_total',
            'Total number of incidents escalated to humans',
            ['job_type', 'escalation_reason'],
            registry=registry
        )

        self.incident_duration = Histogram(
            'support_agent_incident_duration_seconds',
            'Time to resolve incidents',
            ['job_type', 'resolution_type'],
            buckets=[30, 60, 120, 300, 600, 1800, 3600],
            registry=registry
        )

        self.active_incidents = Gauge(
            'support_agent_active_incidents',
            'Number of currently active incidents',
            ['severity'],
            registry=registry
        )

        # Workflow metrics
        self.workflow_stage_duration = Histogram(
            'support_agent_workflow_stage_seconds',
            'Time spent in each workflow stage',
            ['stage'],
            buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60],
            registry=registry
        )

        self.workflow_transitions = Counter(
            'support_agent_workflow_transitions_total',
            'Workflow state transitions',
            ['from_stage', 'to_stage'],
            registry=registry
        )

        # LLM metrics
        self.llm_requests = Counter(
            'support_agent_llm_requests_total',
            'Total LLM API requests',
            ['model', 'purpose', 'status'],
            registry=registry
        )

        self.llm_latency = Histogram(
            'support_agent_llm_latency_seconds',
            'LLM request latency',
            ['model', 'purpose'],
            buckets=[0.5, 1, 2, 5, 10, 30, 60],
            registry=registry
        )

        self.llm_tokens = Counter(
            'support_agent_llm_tokens_total',
            'Total LLM tokens used',
            ['model', 'token_type'],
            registry=registry
        )

        self.llm_cost = Counter(
            'support_agent_llm_cost_usd_total',
            'Total LLM cost in USD',
            ['model'],
            registry=registry
        )

        # Tool metrics
        self.tool_executions = Counter(
            'support_agent_tool_executions_total',
            'Total tool executions',
            ['tool_name', 'status'],
            registry=registry
        )

        self.tool_latency = Histogram(
            'support_agent_tool_latency_seconds',
            'Tool execution latency',
            ['tool_name'],
            buckets=[0.1, 0.5, 1, 2, 5, 10, 30],
            registry=registry
        )

        # Database metrics
        self.db_queries = Counter(
            'support_agent_db_queries_total',
            'Total database queries',
            ['operation', 'table', 'status'],
            registry=registry
        )

        self.db_latency = Histogram(
            'support_agent_db_latency_seconds',
            'Database query latency',
            ['operation'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1, 5],
            registry=registry
        )

        # Circuit breaker metrics
        self.circuit_breaker_state = Gauge(
            'support_agent_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['job_name'],
            registry=registry
        )

        self.circuit_breaker_trips = Counter(
            'support_agent_circuit_breaker_trips_total',
            'Circuit breaker trip count',
            ['job_name'],
            registry=registry
        )

        # Guardrail metrics
        self.guardrail_violations = Counter(
            'support_agent_guardrail_violations_total',
            'Guardrail violations',
            ['guardrail_type', 'action_taken'],
            registry=registry
        )

        # Deduplication metrics
        self.deduplication_results = Counter(
            'support_agent_deduplication_results_total',
            'Deduplication check results',
            ['result'],  # new, duplicate, related, storm
            registry=registry
        )

        # Error classification metrics
        self.error_classifications = Counter(
            'support_agent_error_classifications_total',
            'Error classifications',
            ['category', 'strategy'],
            registry=registry
        )

        # Remediation metrics
        self.remediation_success = Counter(
            'support_agent_remediation_success_total',
            'Successful remediations',
            ['job_type', 'source'],
            registry=registry
        )

        self.remediation_failure = Counter(
            'support_agent_remediation_failure_total',
            'Failed remediations',
            ['job_type', 'source'],
            registry=registry
        )

        # Verification metrics
        self.verification_success = Counter(
            'support_agent_verification_success_total',
            'Successful verifications',
            ['job_type'],
            registry=registry
        )

        self.verification_failure = Counter(
            'support_agent_verification_failure_total',
            'Failed verifications',
            ['job_type'],
            registry=registry
        )

        # Proposal metrics
        self.proposal_generated = Counter(
            'support_agent_proposal_generated_total',
            'Proposals generated',
            ['source', 'requires_approval'],
            registry=registry
        )

        # Health metrics
        self.health_check_status = Gauge(
            'support_agent_health_check_status',
            'Health check status (1=healthy, 0=unhealthy)',
            ['component'],
            registry=registry
        )

        # Build info
        self.build_info = Info(
            'support_agent_build',
            'Build information',
            registry=registry
        )

    def get_metrics(self) -> bytes:
        """Generate Prometheus metrics output."""
        return generate_latest(self.registry)


# Global metrics instance
metrics = MetricsRegistry()


# ============================================================================
# STRUCTURED LOGGING
# ============================================================================

def configure_logging(
    log_level: str = "INFO",
    json_format: bool = True,
    service_name: str = "support-agent"
) -> None:
    """Configure structured logging."""
    import logging
    import sys

    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure root logger
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper())
    )

    # Add service context to all logs
    structlog.contextvars.bind_contextvars(service=service_name)


class LogContext:
    """Context manager for adding context to logs."""

    def __init__(self, **kwargs):
        self.context = kwargs

    def __enter__(self):
        structlog.contextvars.bind_contextvars(**self.context)
        return self

    def __exit__(self, *args):
        structlog.contextvars.unbind_contextvars(*self.context.keys())


# ============================================================================
# TRACING
# ============================================================================

@dataclass
class Span:
    """A trace span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "ok"
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        if self.end_time is None:
            return 0
        return (self.end_time - self.start_time).total_seconds() * 1000

    def add_event(self, name: str, **attributes) -> None:
        self.events.append({
            "name": name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attributes": attributes
        })

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_status(self, status: str, message: Optional[str] = None) -> None:
        self.status = status
        if message:
            self.attributes["status_message"] = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "operation_name": self.operation_name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "attributes": self.attributes,
            "events": self.events
        }


class Tracer:
    """
    Simple distributed tracer.

    In production, replace with OpenTelemetry.
    """

    def __init__(self, service_name: str = "support-agent"):
        self.service_name = service_name
        self._current_trace_id: Optional[str] = None
        self._current_span_id: Optional[str] = None
        self._spans: List[Span] = []

    def _generate_id(self) -> str:
        return uuid4().hex[:16]

    @contextmanager
    def start_trace(self, operation_name: str, **attributes):
        """Start a new trace."""
        trace_id = self._generate_id()
        span_id = self._generate_id()

        old_trace_id = self._current_trace_id
        old_span_id = self._current_span_id

        self._current_trace_id = trace_id
        self._current_span_id = span_id

        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            operation_name=operation_name,
            start_time=datetime.now(timezone.utc),
            attributes={"service": self.service_name, **attributes}
        )

        logger = structlog.get_logger()
        logger.info(
            "trace_started",
            trace_id=trace_id,
            span_id=span_id,
            operation=operation_name
        )

        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            raise
        finally:
            span.end_time = datetime.now(timezone.utc)
            self._spans.append(span)

            logger.info(
                "trace_completed",
                trace_id=trace_id,
                span_id=span_id,
                duration_ms=span.duration_ms,
                status=span.status
            )

            self._current_trace_id = old_trace_id
            self._current_span_id = old_span_id

    @contextmanager
    def start_span(self, operation_name: str, **attributes):
        """Start a child span within current trace."""
        if self._current_trace_id is None:
            # No active trace, start a new one
            with self.start_trace(operation_name, **attributes) as span:
                yield span
            return

        span_id = self._generate_id()
        parent_span_id = self._current_span_id

        old_span_id = self._current_span_id
        self._current_span_id = span_id

        span = Span(
            trace_id=self._current_trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.now(timezone.utc),
            attributes=attributes
        )

        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            raise
        finally:
            span.end_time = datetime.now(timezone.utc)
            self._spans.append(span)
            self._current_span_id = old_span_id

    @property
    def current_trace_id(self) -> Optional[str]:
        return self._current_trace_id

    @property
    def current_span_id(self) -> Optional[str]:
        return self._current_span_id

    def get_recent_spans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent spans for debugging."""
        return [s.to_dict() for s in self._spans[-limit:]]

    def clear_spans(self) -> None:
        """Clear stored spans."""
        self._spans.clear()


# Global tracer instance
tracer = Tracer()


# ============================================================================
# AUDIT LOGGING
# ============================================================================

class AuditEventType(Enum):
    """Types of audit events."""
    INCIDENT_RECEIVED = "incident_received"
    INCIDENT_CLASSIFIED = "incident_classified"
    INCIDENT_DEDUPLICATED = "incident_deduplicated"
    DIAGNOSIS_STARTED = "diagnosis_started"
    DIAGNOSIS_COMPLETED = "diagnosis_completed"
    PROPOSAL_GENERATED = "proposal_generated"
    REMEDIATION_PROPOSED = "remediation_proposed"
    REMEDIATION_APPROVED = "remediation_approved"
    REMEDIATION_REJECTED = "remediation_rejected"
    REMEDIATION_EXECUTED = "remediation_executed"
    REMEDIATION_ROLLED_BACK = "remediation_rolled_back"
    VERIFICATION_COMPLETED = "verification_completed"
    INCIDENT_RESOLVED = "incident_resolved"
    INCIDENT_ESCALATED = "incident_escalated"
    GUARDRAIL_TRIGGERED = "guardrail_triggered"
    CIRCUIT_BREAKER_OPENED = "circuit_breaker_opened"
    HUMAN_OVERRIDE = "human_override"


@dataclass
class AuditEvent:
    """An audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    incident_id: Optional[str]
    actor: str  # "system" or user ID
    action: str
    details: Dict[str, Any]
    outcome: str  # "success", "failure", "pending"
    trace_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "incident_id": self.incident_id,
            "actor": self.actor,
            "action": self.action,
            "details": self.details,
            "outcome": self.outcome,
            "trace_id": self.trace_id
        }


class AuditLogger:
    """
    Audit logger for compliance and debugging.

    Records all significant actions for:
    - Compliance requirements
    - Debugging incidents
    - Understanding system behavior
    - Security auditing
    """

    def __init__(self):
        self._logger = structlog.get_logger("audit")
        self._events: List[AuditEvent] = []  # In-memory buffer
        self._db = None  # Set this to persist to database

    def set_database(self, db) -> None:
        """Set database for persistent audit logging."""
        self._db = db

    def log(
        self,
        event_type: AuditEventType,
        action: str,
        incident_id: Optional[str] = None,
        actor: str = "system",
        details: Optional[Dict[str, Any]] = None,
        outcome: str = "success"
    ) -> AuditEvent:
        """Log an audit event."""
        event = AuditEvent(
            event_id=uuid4().hex,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            incident_id=incident_id,
            actor=actor,
            action=action,
            details=details or {},
            outcome=outcome,
            trace_id=tracer.current_trace_id
        )

        # Log to structured logger
        self._logger.info(
            "audit_event",
            event_type=event_type.value,
            incident_id=incident_id,
            actor=actor,
            action=action,
            outcome=outcome,
            **event.details
        )

        # Buffer in memory
        self._events.append(event)
        if len(self._events) > 10000:
            self._events = self._events[-5000:]

        # Persist to database if available
        if self._db:
            # Async persistence would go here
            pass

        return event

    def get_incident_audit_trail(self, incident_id: str) -> List[AuditEvent]:
        """Get all audit events for an incident."""
        return [e for e in self._events if e.incident_id == incident_id]

    def get_recent_events(
        self,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """Get recent audit events."""
        events = self._events
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]


# Global audit logger
audit = AuditLogger()


# ============================================================================
# HEALTH CHECKS
# ============================================================================

@dataclass
class HealthCheckResult:
    """Result of a health check."""
    component: str
    healthy: bool
    message: str
    latency_ms: float
    details: Dict[str, Any] = field(default_factory=dict)


class HealthChecker:
    """
    Health check manager.
    """

    def __init__(self):
        self._checks: Dict[str, Callable] = {}

    def register(self, component: str, check_func: Callable) -> None:
        """Register a health check."""
        self._checks[component] = check_func

    async def check_all(self) -> Dict[str, HealthCheckResult]:
        """Run all health checks."""
        results = {}

        for component, check_func in self._checks.items():
            start = time.time()
            try:
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()

                latency_ms = (time.time() - start) * 1000

                if isinstance(result, dict):
                    healthy = result.get("healthy", True)
                    message = result.get("message", "OK")
                    details = result
                else:
                    healthy = bool(result)
                    message = "OK" if healthy else "Failed"
                    details = {}

                results[component] = HealthCheckResult(
                    component=component,
                    healthy=healthy,
                    message=message,
                    latency_ms=latency_ms,
                    details=details
                )

                # Update metric
                metrics.health_check_status.labels(component=component).set(1 if healthy else 0)

            except Exception as e:
                latency_ms = (time.time() - start) * 1000
                results[component] = HealthCheckResult(
                    component=component,
                    healthy=False,
                    message=str(e),
                    latency_ms=latency_ms
                )
                metrics.health_check_status.labels(component=component).set(0)

        return results

    async def is_healthy(self) -> bool:
        """Check if all components are healthy."""
        results = await self.check_all()
        return all(r.healthy for r in results.values())

    def get_status(self, results: Dict[str, HealthCheckResult]) -> Dict[str, Any]:
        """Get health status summary."""
        all_healthy = all(r.healthy for r in results.values())
        return {
            "status": "healthy" if all_healthy else "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                name: {
                    "healthy": r.healthy,
                    "message": r.message,
                    "latency_ms": r.latency_ms
                }
                for name, r in results.items()
            }
        }


# Global health checker
health = HealthChecker()


# ============================================================================
# DECORATORS
# ============================================================================

F = TypeVar('F', bound=Callable)


def traced(operation_name: Optional[str] = None):
    """Decorator to trace function execution."""
    def decorator(func: F) -> F:
        op_name = operation_name or func.__name__

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            with tracer.start_span(op_name) as span:
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.set_status("error", str(e))
                    raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            with tracer.start_span(op_name) as span:
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.set_status("error", str(e))
                    raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def metered(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to record metrics for function execution."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start
                metrics.tool_latency.labels(tool_name=metric_name).observe(duration)
                metrics.tool_executions.labels(tool_name=metric_name, status="success").inc()
                return result
            except Exception as e:
                metrics.tool_executions.labels(tool_name=metric_name, status="error").inc()
                raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start
                metrics.tool_latency.labels(tool_name=metric_name).observe(duration)
                metrics.tool_executions.labels(tool_name=metric_name, status="success").inc()
                return result
            except Exception as e:
                metrics.tool_executions.labels(tool_name=metric_name, status="error").inc()
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def audited(event_type: AuditEventType, action: str):
    """Decorator to audit function execution."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            incident_id = kwargs.get("incident_id") or (args[0] if args else None)
            try:
                result = await func(*args, **kwargs)
                audit.log(
                    event_type=event_type,
                    action=action,
                    incident_id=incident_id,
                    outcome="success"
                )
                return result
            except Exception as e:
                audit.log(
                    event_type=event_type,
                    action=action,
                    incident_id=incident_id,
                    outcome="failure",
                    details={"error": str(e)}
                )
                raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            incident_id = kwargs.get("incident_id") or (args[0] if args else None)
            try:
                result = func(*args, **kwargs)
                audit.log(
                    event_type=event_type,
                    action=action,
                    incident_id=incident_id,
                    outcome="success"
                )
                return result
            except Exception as e:
                audit.log(
                    event_type=event_type,
                    action=action,
                    incident_id=incident_id,
                    outcome="failure",
                    details={"error": str(e)}
                )
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# Need asyncio for decorator checks
import asyncio
