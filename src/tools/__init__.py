# LangGraph Tools with rollback support
from .base import (
    BaseTool,
    ReadOnlyTool,
    MutatingTool,
    ToolResult,
    ToolInput,
    ToolRegistry,
    RollbackManager,
)
from .databricks_tools import (
    GetJobRunDetailsTool,
    GetJobRunLogsTool,
    GetClusterStatusTool,
    RestartDatabricksJobTool,
    CancelDatabricksRunTool,
    GetJobDetailsTool,
    register_databricks_tools,
)
from .remediation_tools import (
    RestartJobTool,
    ClearCacheTool,
    ScaleClusterTool,
    RunHealthCheckTool,
    CheckUpstreamTool,
    NotifyTeamTool,
    GetJobStatusTool,
    GetRecentJobRunsTool,
    register_common_tools,
)


def create_tool_registry() -> ToolRegistry:
    """Create and populate the default tool registry."""
    registry = ToolRegistry()
    register_databricks_tools(registry)
    register_common_tools(registry)
    return registry


__all__ = [
    # Base classes
    "BaseTool",
    "ReadOnlyTool",
    "MutatingTool",
    "ToolResult",
    "ToolInput",
    "ToolRegistry",
    "RollbackManager",
    # Databricks tools
    "GetJobRunDetailsTool",
    "GetJobRunLogsTool",
    "GetClusterStatusTool",
    "RestartDatabricksJobTool",
    "CancelDatabricksRunTool",
    "GetJobDetailsTool",
    "register_databricks_tools",
    # Common tools
    "RestartJobTool",
    "ClearCacheTool",
    "ScaleClusterTool",
    "RunHealthCheckTool",
    "CheckUpstreamTool",
    "NotifyTeamTool",
    "GetJobStatusTool",
    "GetRecentJobRunsTool",
    "register_common_tools",
    # Factory
    "create_tool_registry",
]
