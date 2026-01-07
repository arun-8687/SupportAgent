"""
Base Tool interface with rollback support.

All tools in the system inherit from BaseTool and implement
a consistent interface for execution and rollback.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Result of a tool execution."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: int = 0

    # Rollback information
    rollback_action: Optional[str] = None
    rollback_params: Optional[Dict[str, Any]] = None

    # Metadata
    tool_name: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ToolInput(BaseModel):
    """Base class for tool inputs."""
    pass


class BaseTool(ABC):
    """
    Base class for all tools with rollback support.

    Tools are the atomic units of action in the system.
    Each tool should:
    - Have a clear, single responsibility
    - Support rollback where possible
    - Return structured results
    - Handle errors gracefully
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this tool."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this tool does."""
        pass

    @property
    def supports_rollback(self) -> bool:
        """
        Override to True if this tool can be rolled back.

        Rollback support is critical for safe automation.
        Tools that modify state should implement rollback.
        """
        return False

    @property
    def is_read_only(self) -> bool:
        """
        True if this tool only reads data (no side effects).

        Read-only tools don't need rollback.
        """
        return True

    @property
    def risk_level(self) -> str:
        """
        Risk level of this tool: "low", "medium", "high".

        Used for approval routing decisions.
        """
        return "low"

    @property
    def requires_approval(self) -> bool:
        """
        True if this tool requires human approval before execution.

        Override for high-risk operations.
        """
        return self.risk_level == "high"

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """
        Execute the tool action.

        Args:
            **kwargs: Tool-specific parameters

        Returns:
            ToolResult with success status and data
        """
        pass

    async def rollback(self, **kwargs) -> ToolResult:
        """
        Rollback the action.

        Override this method if supports_rollback is True.

        Args:
            **kwargs: Rollback parameters (usually from rollback_params)

        Returns:
            ToolResult indicating rollback success
        """
        if self.supports_rollback:
            raise NotImplementedError(
                f"Tool {self.name} declares supports_rollback=True "
                "but doesn't implement rollback()"
            )
        return ToolResult(
            success=False,
            error="Rollback not supported for this tool"
        )

    async def validate(self, **kwargs) -> Optional[str]:
        """
        Validate input parameters before execution.

        Returns error message if validation fails, None if valid.

        Args:
            **kwargs: Tool parameters to validate

        Returns:
            Error message or None
        """
        return None

    def get_schema(self) -> Dict[str, Any]:
        """
        Return JSON schema for this tool's parameters.

        Used for LLM tool calling.
        """
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

    async def __call__(self, **kwargs) -> ToolResult:
        """
        Convenience method to execute tool.

        Includes validation and timing.
        """
        start_time = datetime.now(timezone.utc)

        # Validate inputs
        validation_error = await self.validate(**kwargs)
        if validation_error:
            return ToolResult(
                success=False,
                error=f"Validation failed: {validation_error}",
                tool_name=self.name
            )

        try:
            result = await self.execute(**kwargs)
            result.tool_name = self.name

            # Calculate execution time
            end_time = datetime.now(timezone.utc)
            result.execution_time_ms = int(
                (end_time - start_time).total_seconds() * 1000
            )

            return result

        except Exception as e:
            end_time = datetime.now(timezone.utc)
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=self.name,
                execution_time_ms=int(
                    (end_time - start_time).total_seconds() * 1000
                )
            )


class ReadOnlyTool(BaseTool):
    """Base class for read-only tools (no side effects)."""

    @property
    def is_read_only(self) -> bool:
        return True

    @property
    def supports_rollback(self) -> bool:
        return False  # No need for rollback

    @property
    def risk_level(self) -> str:
        return "low"


class MutatingTool(BaseTool):
    """Base class for tools that modify state."""

    @property
    def is_read_only(self) -> bool:
        return False

    @property
    def supports_rollback(self) -> bool:
        return True  # Should implement rollback

    @property
    def risk_level(self) -> str:
        return "medium"


class ToolRegistry:
    """
    Registry for all available tools.

    Provides tool discovery and access for agents.
    """

    def __init__(self):
        """Initialize empty registry."""
        self._tools: Dict[str, BaseTool] = {}
        self._by_category: Dict[str, List[str]] = {}

    def register(
        self,
        tool: BaseTool,
        category: Optional[str] = None
    ) -> None:
        """
        Register a tool.

        Args:
            tool: Tool instance to register
            category: Optional category for grouping
        """
        self._tools[tool.name] = tool

        if category:
            if category not in self._by_category:
                self._by_category[category] = []
            self._by_category[category].append(tool.name)

    def register_class(
        self,
        tool_class: Type[BaseTool],
        category: Optional[str] = None,
        **init_kwargs
    ) -> None:
        """
        Register a tool class (instantiate automatically).

        Args:
            tool_class: Tool class to instantiate and register
            category: Optional category
            **init_kwargs: Arguments for tool constructor
        """
        tool = tool_class(**init_kwargs)
        self.register(tool, category)

    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_by_category(self, category: str) -> List[BaseTool]:
        """Get all tools in a category."""
        names = self._by_category.get(category, [])
        return [self._tools[name] for name in names if name in self._tools]

    def list_tools(self) -> List[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def get_schemas(self) -> List[Dict[str, Any]]:
        """Get JSON schemas for all tools (for LLM)."""
        return [tool.get_schema() for tool in self._tools.values()]

    def get_read_only_tools(self) -> List[BaseTool]:
        """Get all read-only tools."""
        return [t for t in self._tools.values() if t.is_read_only]

    def get_mutating_tools(self) -> List[BaseTool]:
        """Get all tools that modify state."""
        return [t for t in self._tools.values() if not t.is_read_only]

    def get_rollback_capable_tools(self) -> List[BaseTool]:
        """Get all tools that support rollback."""
        return [t for t in self._tools.values() if t.supports_rollback]


class RollbackManager:
    """
    Manages rollback operations for executed tools.

    Maintains a stack of executed actions and can roll back
    in reverse order on failure.
    """

    def __init__(self, tool_registry: ToolRegistry):
        """
        Initialize rollback manager.

        Args:
            tool_registry: Registry to look up tools
        """
        self.tool_registry = tool_registry
        self._rollback_stack: List[Dict[str, Any]] = []

    def record_action(
        self,
        tool_name: str,
        result: ToolResult
    ) -> None:
        """
        Record an action for potential rollback.

        Args:
            tool_name: Name of executed tool
            result: Result containing rollback info
        """
        if result.rollback_action and result.rollback_params:
            self._rollback_stack.append({
                "tool_name": tool_name,
                "action": result.rollback_action,
                "params": result.rollback_params,
                "timestamp": datetime.now(timezone.utc)
            })

    async def rollback_all(self) -> List[ToolResult]:
        """
        Roll back all recorded actions in reverse order.

        Returns:
            List of rollback results
        """
        results = []

        while self._rollback_stack:
            action = self._rollback_stack.pop()

            # Find the tool
            tool = self.tool_registry.get(action["action"])
            if not tool:
                results.append(ToolResult(
                    success=False,
                    error=f"Rollback tool not found: {action['action']}"
                ))
                continue

            # Execute rollback
            try:
                result = await tool.rollback(**action["params"])
                results.append(result)
            except Exception as e:
                results.append(ToolResult(
                    success=False,
                    error=f"Rollback failed: {str(e)}"
                ))

        return results

    async def rollback_to(self, timestamp: datetime) -> List[ToolResult]:
        """
        Roll back actions after a specific timestamp.

        Args:
            timestamp: Roll back actions after this time

        Returns:
            List of rollback results
        """
        results = []

        while self._rollback_stack:
            action = self._rollback_stack[-1]

            if action["timestamp"] <= timestamp:
                break

            self._rollback_stack.pop()

            tool = self.tool_registry.get(action["action"])
            if tool:
                try:
                    result = await tool.rollback(**action["params"])
                    results.append(result)
                except Exception as e:
                    results.append(ToolResult(
                        success=False,
                        error=f"Rollback failed: {str(e)}"
                    ))

        return results

    def clear(self) -> None:
        """Clear the rollback stack."""
        self._rollback_stack.clear()

    @property
    def pending_rollbacks(self) -> int:
        """Number of actions that can be rolled back."""
        return len(self._rollback_stack)
