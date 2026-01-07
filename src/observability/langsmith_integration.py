"""
LangSmith Integration for Observability.

LangSmith provides:
- Automatic tracing of LLM calls
- Token usage and cost tracking
- Latency monitoring
- Run debugging and replay
- Dataset management for evaluation
- Feedback collection
"""
import functools
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TypeVar
from uuid import uuid4

import structlog
from langsmith import Client, traceable
from langsmith.run_helpers import get_current_run_tree, trace
from langsmith.run_trees import RunTree

from src.integrations.config import get_settings

logger = structlog.get_logger()

F = TypeVar('F', bound=Callable)


class LangSmithObservability:
    """
    LangSmith-based observability for the Support Agent.

    Provides:
    - Automatic tracing of all LLM calls
    - Custom span creation for non-LLM operations
    - Feedback collection for learning
    - Run tagging and metadata
    """

    def __init__(self):
        self.settings = get_settings()
        self._client: Optional[Client] = None
        self._enabled = False

        self._initialize()

    def _initialize(self) -> None:
        """Initialize LangSmith client."""
        # Check if LangSmith is configured
        api_key = self.settings.langchain_api_key or os.getenv("LANGCHAIN_API_KEY")

        if not api_key:
            logger.warning("langsmith_not_configured", message="LANGCHAIN_API_KEY not set")
            return

        # Set environment variables for automatic tracing
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_API_KEY"] = api_key
        os.environ["LANGCHAIN_PROJECT"] = self.settings.langchain_project or "support-agent"
        os.environ["LANGCHAIN_ENDPOINT"] = self.settings.langchain_endpoint

        try:
            self._client = Client()
            self._enabled = True
            logger.info(
                "langsmith_initialized",
                project=self.settings.langchain_project
            )
        except Exception as e:
            logger.error("langsmith_init_failed", error=str(e))

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def client(self) -> Optional[Client]:
        return self._client

    def create_run(
        self,
        name: str,
        run_type: str = "chain",
        inputs: Optional[Dict] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ) -> Optional[RunTree]:
        """
        Create a new run for tracing.

        Args:
            name: Name of the run
            run_type: Type of run (chain, llm, tool, etc.)
            inputs: Input data
            tags: Tags for filtering
            metadata: Additional metadata
        """
        if not self._enabled:
            return None

        return RunTree(
            name=name,
            run_type=run_type,
            inputs=inputs or {},
            tags=tags or [],
            extra={"metadata": metadata or {}}
        )

    @contextmanager
    def trace_incident(
        self,
        incident_id: str,
        job_name: str,
        job_type: str,
        **metadata
    ):
        """
        Context manager to trace an entire incident processing.

        Usage:
            with langsmith.trace_incident("INC-123", "etl-job", "databricks") as run:
                # Process incident
                run.add_metadata({"severity": "P2"})
        """
        if not self._enabled:
            yield DummyRun()
            return

        tags = [
            f"incident:{incident_id}",
            f"job_type:{job_type}",
            f"env:{metadata.get('environment', 'unknown')}"
        ]

        with trace(
            name=f"incident:{incident_id}",
            run_type="chain",
            inputs={
                "incident_id": incident_id,
                "job_name": job_name,
                "job_type": job_type,
                **metadata
            },
            tags=tags,
            metadata={
                "incident_id": incident_id,
                "job_name": job_name,
                "job_type": job_type,
                **metadata
            }
        ) as run:
            yield IncidentRun(run, self._client)

    @contextmanager
    def trace_stage(
        self,
        stage_name: str,
        inputs: Optional[Dict] = None,
        **metadata
    ):
        """
        Trace a workflow stage (triage, diagnose, etc.).
        """
        if not self._enabled:
            yield DummyRun()
            return

        with trace(
            name=stage_name,
            run_type="chain",
            inputs=inputs or {},
            metadata=metadata
        ) as run:
            yield StageRun(run)

    @contextmanager
    def trace_tool(
        self,
        tool_name: str,
        inputs: Optional[Dict] = None,
        **metadata
    ):
        """
        Trace a tool execution.
        """
        if not self._enabled:
            yield DummyRun()
            return

        with trace(
            name=tool_name,
            run_type="tool",
            inputs=inputs or {},
            metadata=metadata
        ) as run:
            yield ToolRun(run)

    def record_feedback(
        self,
        run_id: str,
        key: str,
        score: float,
        comment: Optional[str] = None
    ) -> None:
        """
        Record feedback for a run (for learning/evaluation).

        Args:
            run_id: The run ID to provide feedback for
            key: Feedback key (e.g., "correctness", "helpfulness")
            score: Score (typically 0-1)
            comment: Optional comment
        """
        if not self._enabled or not self._client:
            return

        try:
            self._client.create_feedback(
                run_id=run_id,
                key=key,
                score=score,
                comment=comment
            )
            logger.info(
                "feedback_recorded",
                run_id=run_id,
                key=key,
                score=score
            )
        except Exception as e:
            logger.error("feedback_record_failed", error=str(e))

    def record_resolution_outcome(
        self,
        run_id: str,
        success: bool,
        resolution_type: str,
        human_override: bool = False
    ) -> None:
        """
        Record the outcome of an incident resolution.

        This data can be used for:
        - Evaluating agent performance
        - Training/fine-tuning
        - Identifying patterns
        """
        score = 1.0 if success else 0.0

        self.record_feedback(
            run_id=run_id,
            key="resolution_success",
            score=score,
            comment=f"Type: {resolution_type}, Human override: {human_override}"
        )

        if human_override:
            self.record_feedback(
                run_id=run_id,
                key="required_human",
                score=0.0,
                comment="Human intervention was required"
            )


class DummyRun:
    """Dummy run when LangSmith is not enabled."""

    def add_metadata(self, metadata: Dict) -> None:
        pass

    def add_outputs(self, outputs: Dict) -> None:
        pass

    def add_tags(self, tags: List[str]) -> None:
        pass

    def set_error(self, error: str) -> None:
        pass

    @property
    def run_id(self) -> str:
        return "dummy"


class IncidentRun:
    """Wrapper for incident-level run."""

    def __init__(self, run_tree, client: Optional[Client]):
        self._run = run_tree
        self._client = client
        self._start_time = datetime.utcnow()

    def add_metadata(self, metadata: Dict) -> None:
        """Add metadata to the run."""
        if self._run and hasattr(self._run, 'extra'):
            if 'metadata' not in self._run.extra:
                self._run.extra['metadata'] = {}
            self._run.extra['metadata'].update(metadata)

    def add_outputs(self, outputs: Dict) -> None:
        """Add outputs to the run."""
        if self._run:
            self._run.outputs = outputs

    def add_tags(self, tags: List[str]) -> None:
        """Add tags to the run."""
        if self._run and hasattr(self._run, 'tags'):
            self._run.tags.extend(tags)

    def set_error(self, error: str) -> None:
        """Mark the run as errored."""
        if self._run:
            self._run.error = error

    @property
    def run_id(self) -> str:
        if self._run:
            return str(self._run.id)
        return "unknown"

    def record_classification(
        self,
        category: str,
        confidence: float,
        is_known_issue: bool
    ) -> None:
        """Record classification results."""
        self.add_metadata({
            "classification": {
                "category": category,
                "confidence": confidence,
                "is_known_issue": is_known_issue
            }
        })
        self.add_tags([f"category:{category}"])

    def record_severity(self, severity: str) -> None:
        """Record assessed severity."""
        self.add_metadata({"severity": severity})
        self.add_tags([f"severity:{severity}"])

    def record_remediation(
        self,
        actions: List[str],
        success: bool,
        automated: bool
    ) -> None:
        """Record remediation outcome."""
        self.add_metadata({
            "remediation": {
                "actions": actions,
                "success": success,
                "automated": automated
            }
        })
        if automated:
            self.add_tags(["auto-remediated"])
        if success:
            self.add_tags(["resolved"])
        else:
            self.add_tags(["escalated"])


class StageRun:
    """Wrapper for workflow stage run."""

    def __init__(self, run_tree):
        self._run = run_tree

    def add_metadata(self, metadata: Dict) -> None:
        if self._run and hasattr(self._run, 'extra'):
            if 'metadata' not in self._run.extra:
                self._run.extra['metadata'] = {}
            self._run.extra['metadata'].update(metadata)

    def add_outputs(self, outputs: Dict) -> None:
        if self._run:
            self._run.outputs = outputs

    def set_error(self, error: str) -> None:
        if self._run:
            self._run.error = error

    @property
    def run_id(self) -> str:
        if self._run:
            return str(self._run.id)
        return "unknown"


class ToolRun:
    """Wrapper for tool execution run."""

    def __init__(self, run_tree):
        self._run = run_tree

    def add_outputs(self, outputs: Dict) -> None:
        if self._run:
            self._run.outputs = outputs

    def set_error(self, error: str) -> None:
        if self._run:
            self._run.error = error

    @property
    def run_id(self) -> str:
        if self._run:
            return str(self._run.id)
        return "unknown"


# ============================================================================
# DECORATORS FOR EASY TRACING
# ============================================================================

def traced_operation(
    name: Optional[str] = None,
    run_type: str = "chain",
    tags: Optional[List[str]] = None
):
    """
    Decorator to trace any function with LangSmith.

    Usage:
        @traced_operation("classify_error", tags=["classification"])
        async def classify_error(error_message: str) -> Classification:
            ...
    """
    def decorator(func: F) -> F:
        operation_name = name or func.__name__

        # Use LangSmith's traceable decorator
        traced_func = traceable(
            name=operation_name,
            run_type=run_type,
            tags=tags or []
        )(func)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await traced_func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return traced_func(*args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def traced_agent(agent_name: str):
    """
    Decorator for agent execute methods.

    Usage:
        class TriageAgent:
            @traced_agent("triage")
            async def execute(self, state):
                ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(self, state, *args, **kwargs):
            incident_id = state.get("incident", {})
            if hasattr(incident_id, "incident_id"):
                incident_id = incident_id.incident_id
            elif isinstance(incident_id, dict):
                incident_id = incident_id.get("incident_id", "unknown")

            with trace(
                name=f"agent:{agent_name}",
                run_type="chain",
                inputs={"incident_id": incident_id},
                tags=[f"agent:{agent_name}"],
                metadata={"agent": agent_name}
            ) as run:
                try:
                    result = await func(self, state, *args, **kwargs)
                    run.outputs = result
                    return result
                except Exception as e:
                    run.error = str(e)
                    raise

        return wrapper
    return decorator


def traced_tool(tool_name: str):
    """
    Decorator for tool execute methods.

    Usage:
        class RestartJobTool:
            @traced_tool("restart_databricks_job")
            async def execute(self, job_id: int):
                ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            with trace(
                name=f"tool:{tool_name}",
                run_type="tool",
                inputs=kwargs,
                tags=[f"tool:{tool_name}"]
            ) as run:
                try:
                    result = await func(*args, **kwargs)
                    if hasattr(result, 'model_dump'):
                        run.outputs = result.model_dump()
                    elif hasattr(result, '__dict__'):
                        run.outputs = result.__dict__
                    else:
                        run.outputs = {"result": str(result)}
                    return result
                except Exception as e:
                    run.error = str(e)
                    raise

        return wrapper
    return decorator


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

# Global LangSmith observability instance
langsmith = LangSmithObservability()


def get_langsmith() -> LangSmithObservability:
    """Get the global LangSmith instance."""
    return langsmith


# Need asyncio for decorator checks
import asyncio
