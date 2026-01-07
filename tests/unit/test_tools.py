"""
Unit tests for the base tool classes.
"""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock

from src.tools.base import (
    BaseTool,
    MutatingTool,
    ReadOnlyTool,
    RollbackManager,
    ToolRegistry,
    ToolResult,
)


class TestToolResult:
    """Tests for ToolResult model."""

    def test_success_result(self):
        """Test creating a successful result."""
        result = ToolResult(
            success=True,
            data={"key": "value"}
        )

        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None

    def test_error_result(self):
        """Test creating an error result."""
        result = ToolResult(
            success=False,
            error="Something went wrong"
        )

        assert result.success is False
        assert result.error == "Something went wrong"
        assert result.data is None

    def test_result_with_rollback(self):
        """Test result with rollback information."""
        result = ToolResult(
            success=True,
            data={"run_id": "123"},
            rollback_action="cancel_run",
            rollback_params={"run_id": "123"}
        )

        assert result.rollback_action == "cancel_run"
        assert result.rollback_params == {"run_id": "123"}


class TestBaseTool:
    """Tests for BaseTool abstract class."""

    def test_read_only_tool_properties(self):
        """Test ReadOnlyTool default properties."""

        class MyReadTool(ReadOnlyTool):
            @property
            def name(self):
                return "my_read_tool"

            @property
            def description(self):
                return "A read-only tool"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        tool = MyReadTool()

        assert tool.is_read_only is True
        assert tool.supports_rollback is False
        assert tool.risk_level == "low"
        assert tool.requires_approval is False

    def test_mutating_tool_properties(self):
        """Test MutatingTool default properties."""

        class MyMutateTool(MutatingTool):
            @property
            def name(self):
                return "my_mutate_tool"

            @property
            def description(self):
                return "A mutating tool"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

            async def rollback(self, **kwargs):
                return ToolResult(success=True, data={})

        tool = MyMutateTool()

        assert tool.is_read_only is False
        assert tool.supports_rollback is True
        assert tool.risk_level == "medium"

    @pytest.mark.asyncio
    async def test_tool_call_with_validation(self):
        """Test tool execution with validation."""

        class ValidatedTool(ReadOnlyTool):
            @property
            def name(self):
                return "validated_tool"

            @property
            def description(self):
                return "Tool with validation"

            async def validate(self, **kwargs):
                if "required_param" not in kwargs:
                    return "required_param is required"
                return None

            async def execute(self, **kwargs):
                return ToolResult(success=True, data=kwargs)

        tool = ValidatedTool()

        # Should fail validation
        result = await tool(other_param="value")
        assert result.success is False
        assert "Validation failed" in result.error

        # Should pass validation
        result = await tool(required_param="value")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_tool_execution_timing(self):
        """Test that execution time is recorded."""
        import asyncio

        class SlowTool(ReadOnlyTool):
            @property
            def name(self):
                return "slow_tool"

            @property
            def description(self):
                return "A slow tool"

            async def execute(self, **kwargs):
                await asyncio.sleep(0.1)
                return ToolResult(success=True, data={})

        tool = SlowTool()
        result = await tool()

        assert result.execution_time_ms >= 100

    def test_tool_schema_generation(self):
        """Test JSON schema generation."""

        class SchemaTestTool(ReadOnlyTool):
            @property
            def name(self):
                return "schema_test"

            @property
            def description(self):
                return "Tool for schema testing"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        tool = SchemaTestTool()
        schema = tool.get_schema()

        assert schema["name"] == "schema_test"
        assert schema["description"] == "Tool for schema testing"
        assert "parameters" in schema


class TestToolRegistry:
    """Tests for ToolRegistry."""

    def test_register_tool(self):
        """Test registering a tool."""
        registry = ToolRegistry()

        class TestTool(ReadOnlyTool):
            @property
            def name(self):
                return "test_tool"

            @property
            def description(self):
                return "Test tool"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        tool = TestTool()
        registry.register(tool, category="testing")

        assert "test_tool" in registry.list_tools()
        assert registry.get("test_tool") == tool

    def test_get_by_category(self):
        """Test getting tools by category."""
        registry = ToolRegistry()

        class Tool1(ReadOnlyTool):
            @property
            def name(self):
                return "tool1"

            @property
            def description(self):
                return "Tool 1"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        class Tool2(ReadOnlyTool):
            @property
            def name(self):
                return "tool2"

            @property
            def description(self):
                return "Tool 2"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        registry.register(Tool1(), category="cat_a")
        registry.register(Tool2(), category="cat_b")

        cat_a_tools = registry.get_by_category("cat_a")
        assert len(cat_a_tools) == 1
        assert cat_a_tools[0].name == "tool1"

    def test_get_read_only_tools(self):
        """Test filtering read-only tools."""
        registry = ToolRegistry()

        class ReadTool(ReadOnlyTool):
            @property
            def name(self):
                return "read_tool"

            @property
            def description(self):
                return "Read tool"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        class WriteTool(MutatingTool):
            @property
            def name(self):
                return "write_tool"

            @property
            def description(self):
                return "Write tool"

            async def execute(self, **kwargs):
                return ToolResult(success=True, data={})

        registry.register(ReadTool())
        registry.register(WriteTool())

        read_only = registry.get_read_only_tools()
        mutating = registry.get_mutating_tools()

        assert len(read_only) == 1
        assert len(mutating) == 1
        assert read_only[0].name == "read_tool"
        assert mutating[0].name == "write_tool"


class TestRollbackManager:
    """Tests for RollbackManager."""

    @pytest.fixture
    def registry_with_rollback_tool(self):
        """Create registry with a rollback-capable tool."""
        registry = ToolRegistry()

        class RollbackTool(MutatingTool):
            @property
            def name(self):
                return "rollback_tool"

            @property
            def description(self):
                return "Tool with rollback"

            async def execute(self, **kwargs):
                return ToolResult(
                    success=True,
                    data={"created": True},
                    rollback_action="rollback_tool",
                    rollback_params={"undo": True}
                )

            async def rollback(self, **kwargs):
                return ToolResult(success=True, data={"rolled_back": True})

        registry.register(RollbackTool())
        return registry

    def test_record_action(self, registry_with_rollback_tool):
        """Test recording actions for rollback."""
        manager = RollbackManager(registry_with_rollback_tool)

        result = ToolResult(
            success=True,
            rollback_action="rollback_tool",
            rollback_params={"id": "123"}
        )

        manager.record_action("rollback_tool", result)

        assert manager.pending_rollbacks == 1

    @pytest.mark.asyncio
    async def test_rollback_all(self, registry_with_rollback_tool):
        """Test rolling back all recorded actions."""
        manager = RollbackManager(registry_with_rollback_tool)

        # Record multiple actions
        for i in range(3):
            result = ToolResult(
                success=True,
                rollback_action="rollback_tool",
                rollback_params={"id": str(i)}
            )
            manager.record_action("rollback_tool", result)

        assert manager.pending_rollbacks == 3

        # Rollback all
        results = await manager.rollback_all()

        assert len(results) == 3
        assert all(r.success for r in results)
        assert manager.pending_rollbacks == 0

    def test_clear_rollback_stack(self, registry_with_rollback_tool):
        """Test clearing the rollback stack."""
        manager = RollbackManager(registry_with_rollback_tool)

        result = ToolResult(
            success=True,
            rollback_action="rollback_tool",
            rollback_params={"id": "123"}
        )
        manager.record_action("rollback_tool", result)

        assert manager.pending_rollbacks == 1

        manager.clear()

        assert manager.pending_rollbacks == 0
