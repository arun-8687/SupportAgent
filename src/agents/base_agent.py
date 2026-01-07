"""
Base Agent class for all LangGraph agents.

Provides common functionality for:
- Tool access and execution
- LLM interaction
- State management
- Logging and tracing (with LangSmith integration)
"""
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

import structlog
from langchain_openai import AzureChatOpenAI
from pydantic import BaseModel

from src.graph.state import AppSupportState, ToolCallRecord
from src.integrations.config import get_settings
from src.tools.base import BaseTool, RollbackManager, ToolRegistry, ToolResult
from src.observability import (
    traced_agent,
    traced_operation,
    traced_tool,
    get_langsmith,
    metrics,
    audit,
    AuditEventType,
)


logger = structlog.get_logger()


class AgentConfig(BaseModel):
    """Configuration for an agent."""
    name: str
    description: str
    max_tool_calls: int = 10
    temperature: float = 0.3
    require_tool_confirmation: bool = False


class BaseAgent(ABC):
    """
    Base class for all LangGraph agent nodes.

    Each agent:
    - Receives state from the graph
    - Processes the state (with LLM and tools)
    - Returns updated state

    Subclasses implement the execute() method for
    their specific logic.
    """

    def __init__(
        self,
        config: AgentConfig,
        tool_registry: ToolRegistry,
        llm: Optional[AzureChatOpenAI] = None
    ):
        """
        Initialize agent.

        Args:
            config: Agent configuration
            tool_registry: Registry of available tools
            llm: Optional LLM client (created if not provided)
        """
        self.config = config
        self.tool_registry = tool_registry
        self.rollback_manager = RollbackManager(tool_registry)
        self.llm = llm or self._create_llm()
        self.logger = logger.bind(agent=config.name)

    def _create_llm(self) -> AzureChatOpenAI:
        """Create default LLM client."""
        settings = get_settings()
        return AzureChatOpenAI(
            azure_endpoint=settings.azure_openai_endpoint,
            api_key=settings.azure_openai_api_key,
            api_version=settings.azure_openai_api_version,
            azure_deployment=settings.azure_openai_deployment_name,
            temperature=self.config.temperature
        )

    @property
    def name(self) -> str:
        """Agent name."""
        return self.config.name

    @abstractmethod
    async def execute(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Execute agent logic.

        This is the main method that subclasses implement.

        Args:
            state: Current workflow state

        Returns:
            Dict with state updates
        """
        pass

    async def __call__(self, state: AppSupportState) -> Dict[str, Any]:
        """
        Callable interface for LangGraph.

        Wraps execute() with logging, error handling, and LangSmith tracing.

        Args:
            state: Current workflow state

        Returns:
            Updated state dict
        """
        incident = state.get("incident")
        incident_id = incident.incident_id if incident else None

        self.logger.info(
            "agent_starting",
            incident_id=incident_id
        )

        start_time = datetime.now(timezone.utc)

        # Get LangSmith for tracing
        langsmith = get_langsmith()

        try:
            # Execute agent logic with LangSmith tracing
            with langsmith.trace_stage(
                stage_name=f"agent:{self.name}",
                inputs={"incident_id": incident_id},
                agent=self.name
            ) as run:
                updates = await self.execute(state)

                # Record outputs in trace
                run.add_outputs(updates)

                # Add common updates
                updates["current_agent"] = self.name
                updates["updated_at"] = datetime.now(timezone.utc)

                # Calculate processing time
                end_time = datetime.now(timezone.utc)
                processing_ms = int((end_time - start_time).total_seconds() * 1000)
                updates["processing_time_ms"] = (
                    state.get("processing_time_ms", 0) + processing_ms
                )

                # Record metrics
                metrics.workflow_stage_duration.labels(stage=self.name).observe(
                    processing_ms / 1000
                )

                self.logger.info(
                    "agent_completed",
                    processing_ms=processing_ms,
                    updates_keys=list(updates.keys())
                )

                return updates

        except Exception as e:
            self.logger.error(
                "agent_failed",
                error=str(e),
                exc_info=True
            )

            # Record failure metrics
            metrics.tool_executions.labels(tool_name=self.name, status="error").inc()

            # Audit the failure
            audit.log(
                event_type=AuditEventType.GUARDRAIL_TRIGGERED,
                action=f"Agent {self.name} failed",
                incident_id=incident_id,
                outcome="failure",
                details={"error": str(e)}
            )

            # Return error state
            return {
                "current_agent": self.name,
                "requires_human_review": True,
                "updated_at": datetime.now(timezone.utc),
                "messages": state.get("messages", []) + [{
                    "role": "system",
                    "content": f"Agent {self.name} failed: {str(e)}"
                }]
            }

    # =========================================================================
    # Tool Execution Helpers
    # =========================================================================

    async def execute_tool(
        self,
        tool_name: str,
        **params
    ) -> ToolResult:
        """
        Execute a tool and record for rollback with LangSmith tracing.

        Args:
            tool_name: Name of tool to execute
            **params: Tool parameters

        Returns:
            ToolResult
        """
        tool = self.tool_registry.get(tool_name)
        if not tool:
            return ToolResult(
                success=False,
                error=f"Tool not found: {tool_name}"
            )

        self.logger.debug("executing_tool", tool=tool_name, params=params)

        # Get LangSmith for tracing
        langsmith = get_langsmith()
        start_time = datetime.now(timezone.utc)

        with langsmith.trace_tool(
            tool_name=tool_name,
            inputs=params
        ) as run:
            try:
                result = await tool(**params)

                # Record in LangSmith
                if result.success:
                    run.add_outputs({"data": result.data, "success": True})
                else:
                    run.set_error(result.error or "Unknown error")

                # Record metrics
                end_time = datetime.now(timezone.utc)
                duration_seconds = (end_time - start_time).total_seconds()
                metrics.tool_latency.labels(tool_name=tool_name).observe(duration_seconds)
                metrics.tool_executions.labels(
                    tool_name=tool_name,
                    status="success" if result.success else "error"
                ).inc()

                # Record for rollback if applicable
                if result.success and result.rollback_action:
                    self.rollback_manager.record_action(tool_name, result)

                return result

            except Exception as e:
                run.set_error(str(e))
                metrics.tool_executions.labels(tool_name=tool_name, status="error").inc()
                raise

    async def execute_tools_parallel(
        self,
        tool_calls: List[Dict[str, Any]]
    ) -> List[ToolResult]:
        """
        Execute multiple tools in parallel.

        Args:
            tool_calls: List of {"name": str, "params": dict}

        Returns:
            List of ToolResults
        """
        import asyncio

        tasks = [
            self.execute_tool(call["name"], **call.get("params", {}))
            for call in tool_calls
        ]

        return await asyncio.gather(*tasks)

    def record_tool_call(
        self,
        state: AppSupportState,
        tool_name: str,
        params: Dict[str, Any],
        result: ToolResult
    ) -> List[ToolCallRecord]:
        """
        Record a tool call in state.

        Args:
            state: Current state
            tool_name: Name of tool
            params: Tool parameters
            result: Tool result

        Returns:
            Updated tool_calls list
        """
        tool_calls = list(state.get("tool_calls", []))
        tool_calls.append(ToolCallRecord(
            tool_name=tool_name,
            input_params=params,
            output=result.data,
            success=result.success,
            error=result.error,
            execution_time_ms=result.execution_time_ms,
            timestamp=datetime.now(timezone.utc)
        ))
        return tool_calls

    # =========================================================================
    # LLM Interaction Helpers
    # =========================================================================

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[BaseTool]] = None,
        response_format: Optional[Dict[str, str]] = None,
        temperature: Optional[float] = None
    ) -> str:
        """
        Get LLM chat completion.

        Args:
            messages: Chat messages
            tools: Optional tools for function calling
            response_format: Optional response format (e.g., {"type": "json_object"})
            temperature: Optional temperature override

        Returns:
            LLM response content
        """
        kwargs = {}

        if response_format:
            kwargs["response_format"] = response_format

        if temperature is not None:
            kwargs["temperature"] = temperature

        if tools:
            # Convert tools to OpenAI function format
            tool_schemas = [tool.get_schema() for tool in tools]
            kwargs["tools"] = [
                {"type": "function", "function": schema}
                for schema in tool_schemas
            ]

        response = await self.llm.ainvoke(messages, **kwargs)
        return response.content

    async def chat_with_tools(
        self,
        messages: List[Dict[str, str]],
        available_tools: Optional[List[BaseTool]] = None,
        max_iterations: int = 5
    ) -> tuple[str, List[ToolResult]]:
        """
        Chat with LLM and execute any tool calls.

        Implements the ReAct pattern: Reason → Act → Observe.

        Args:
            messages: Initial messages
            available_tools: Tools the LLM can call
            max_iterations: Maximum tool call iterations

        Returns:
            Tuple of (final response, list of tool results)
        """
        if available_tools is None:
            available_tools = list(self.tool_registry._tools.values())

        tool_schemas = [
            {"type": "function", "function": tool.get_schema()}
            for tool in available_tools
        ]

        all_messages = list(messages)
        all_tool_results = []

        for _ in range(max_iterations):
            response = await self.llm.ainvoke(
                all_messages,
                tools=tool_schemas
            )

            # Check for tool calls
            if not response.tool_calls:
                return response.content, all_tool_results

            # Execute tool calls
            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]

                result = await self.execute_tool(tool_name, **tool_args)
                all_tool_results.append(result)

                # Add tool result to messages
                all_messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": json.dumps(result.data if result.success else {"error": result.error})
                })

        # Max iterations reached
        return "Max tool iterations reached", all_tool_results

    # =========================================================================
    # State Management Helpers
    # =========================================================================

    def add_message(
        self,
        state: AppSupportState,
        role: str,
        content: str
    ) -> List[Dict[str, Any]]:
        """
        Add a message to state.

        Args:
            state: Current state
            role: Message role (system, user, assistant)
            content: Message content

        Returns:
            Updated messages list
        """
        messages = list(state.get("messages", []))
        messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        return messages

    def should_escalate(
        self,
        state: AppSupportState,
        confidence_threshold: float = 0.5
    ) -> bool:
        """
        Check if current state should be escalated to human.

        Args:
            state: Current state
            confidence_threshold: Minimum confidence to avoid escalation

        Returns:
            True if should escalate
        """
        # Already flagged for review
        if state.get("requires_human_review"):
            return True

        # Check diagnostic confidence
        diagnostic = state.get("diagnostic_result")
        if diagnostic:
            if diagnostic.root_cause.confidence < confidence_threshold:
                return True

        # Check proposal confidence
        proposal = state.get("proposal")
        if proposal:
            if proposal.estimated_success_probability < confidence_threshold:
                return True

        # Check retry count
        if state.get("retry_count", 0) >= state.get("max_retries", 3):
            return True

        return False


class DiagnosticAgent(BaseAgent):
    """Base class for agents that perform diagnosis."""

    async def gather_evidence(
        self,
        state: AppSupportState,
        investigation_tools: List[str]
    ) -> List[ToolResult]:
        """
        Gather evidence using specified tools.

        Args:
            state: Current state with incident info
            investigation_tools: List of tool names to use

        Returns:
            List of tool results
        """
        incident = state["incident"]
        results = []

        for tool_name in investigation_tools:
            tool = self.tool_registry.get(tool_name)
            if not tool:
                continue

            # Build tool-specific params from incident
            params = self._build_tool_params(tool_name, incident)
            result = await self.execute_tool(tool_name, **params)
            results.append(result)

        return results

    def _build_tool_params(
        self,
        tool_name: str,
        incident: Any
    ) -> Dict[str, Any]:
        """Build tool parameters from incident context."""
        # Default implementation - subclasses can override
        params = {}

        if hasattr(incident, "job_name"):
            params["job_name"] = incident.job_name

        if hasattr(incident, "job_run_id") and incident.job_run_id:
            params["run_id"] = incident.job_run_id

        if hasattr(incident, "cluster_id") and incident.cluster_id:
            params["cluster_id"] = incident.cluster_id

        return params


class RemediationAgent(BaseAgent):
    """Base class for agents that perform remediation."""

    async def execute_with_rollback(
        self,
        steps: List[Dict[str, Any]]
    ) -> tuple[bool, List[ToolResult]]:
        """
        Execute remediation steps with rollback on failure.

        Args:
            steps: List of {"tool": str, "params": dict}

        Returns:
            Tuple of (success, results)
        """
        results = []
        self.rollback_manager.clear()

        for step in steps:
            result = await self.execute_tool(
                step["tool"],
                **step.get("params", {})
            )
            results.append(result)

            if not result.success:
                # Rollback previous steps
                self.logger.warning(
                    "step_failed_rolling_back",
                    failed_step=step["tool"]
                )
                await self.rollback_manager.rollback_all()
                return False, results

        return True, results
