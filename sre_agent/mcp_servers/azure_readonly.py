"""
azure-readonly MCP server.

Exposes read-only Azure CLI diagnostics: resource metadata, metrics,
App Service state, and resource health. Only `show`/`list` verbs are
reachable — the allowlist has no `create`/`update`/`delete`/`restart`,
so this server cannot mutate anything even if a tool call were malformed.
Mitigation (restarts, scaling) stays behind skills + the permission gate.

Run standalone: python -m sre_agent.mcp_servers.azure_readonly
Requires: Azure CLI on PATH, authenticated (az login or a managed identity
/ service principal already logged in via `az login --identity`).
"""
from mcp.server.fastmcp import FastMCP

from sre_agent.mcp_servers._shell import run_readonly, validate_identifier

mcp = FastMCP("azure-readonly")

_ALLOWED = {"resource", "monitor", "webapp", "aks"}


@mcp.tool()
async def resource_show(resource_id: str) -> str:
    """Show full metadata for an Azure resource by its resource ID."""
    validate_identifier(resource_id, "resource_id")
    return await run_readonly(
        "az", _ALLOWED, ["resource", "show", "--ids", resource_id, "-o", "json"]
    )


@mcp.tool()
async def resource_health(resource_id: str) -> str:
    """Current Azure Resource Health status for a resource."""
    validate_identifier(resource_id, "resource_id")
    return await run_readonly(
        "az",
        _ALLOWED,
        [
            "resource", "show", "--ids",
            f"{resource_id}/providers/Microsoft.ResourceHealth/availabilityStatuses/current",
            "-o", "json",
        ],
    )


@mcp.tool()
async def metrics_list(resource_id: str, metric_names: str, interval: str = "PT5M") -> str:
    """
    Metric values for a resource over the last hour. metric_names is a
    comma-separated list (e.g. "MemoryWorkingSet,CpuPercentage"); interval
    is an ISO 8601 duration (PT1M, PT5M, PT1H).
    """
    validate_identifier(resource_id, "resource_id")
    for name in metric_names.split(","):
        validate_identifier(name.strip(), "metric_names")
    validate_identifier(interval, "interval")
    return await run_readonly(
        "az",
        _ALLOWED,
        [
            "monitor", "metrics", "list", "--resource", resource_id,
            "--metric", metric_names, "--interval", interval, "-o", "json",
        ],
    )


@mcp.tool()
async def webapp_show(resource_group: str, name: str) -> str:
    """App Service state (Running/Stopped), plan, and configuration summary."""
    validate_identifier(resource_group, "resource_group")
    validate_identifier(name, "name")
    return await run_readonly(
        "az", _ALLOWED, ["webapp", "show", "-g", resource_group, "-n", name, "-o", "json"]
    )


@mcp.tool()
async def aks_show(resource_group: str, name: str) -> str:
    """AKS cluster metadata: node pools, Kubernetes version, provisioning state."""
    validate_identifier(resource_group, "resource_group")
    validate_identifier(name, "name")
    return await run_readonly(
        "az", _ALLOWED, ["aks", "show", "-g", resource_group, "-n", name, "-o", "json"]
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
