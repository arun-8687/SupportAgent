"""
kubectl-readonly MCP server.

Exposes read-only Kubernetes diagnostics as MCP tools: pod status, pod
description, container logs (including --previous for crashed
containers), resource usage, and HPA status. There is deliberately no
write tool here (no rollout restart, no scale, no patch) — mitigation
actions stay behind the permission gate and human approval; this server
only gathers evidence.

Run standalone: python -m sre_agent.mcp_servers.kubectl_readonly
Requires: kubectl on PATH with a current context pointed at the cluster
to inspect (KUBECONFIG env var or the default kubeconfig location).
"""
from mcp.server.fastmcp import FastMCP

from sre_agent.mcp_servers._shell import run_readonly, validate_identifier

mcp = FastMCP("kubectl-readonly")

_ALLOWED = {"get", "describe", "logs", "top"}


@mcp.tool()
async def get_pods(namespace: str) -> str:
    """List pods in a namespace with status, restarts, and age."""
    validate_identifier(namespace, "namespace")
    return await run_readonly(
        "kubectl", _ALLOWED, ["get", "pods", "-n", namespace, "-o", "wide"]
    )


@mcp.tool()
async def describe_pod(namespace: str, pod: str) -> str:
    """Full description of a pod: events, conditions, container states."""
    validate_identifier(namespace, "namespace")
    validate_identifier(pod, "pod")
    return await run_readonly(
        "kubectl", _ALLOWED, ["describe", "pod", pod, "-n", namespace]
    )


@mcp.tool()
async def pod_logs(
    namespace: str, pod: str, previous: bool = False, tail: int = 200
) -> str:
    """
    Container logs for a pod. Set previous=true to read the CRASHED
    container's logs after an OOMKilled/CrashLoopBackOff restart — this is
    usually more useful than the current container's logs, which start
    fresh after the crash.
    """
    validate_identifier(namespace, "namespace")
    validate_identifier(pod, "pod")
    tail = max(1, min(int(tail), 2000))  # bound output regardless of input
    args = ["logs", pod, "-n", namespace, f"--tail={tail}"]
    if previous:
        args.append("--previous")
    return await run_readonly("kubectl", _ALLOWED, args)


@mcp.tool()
async def top_pods(namespace: str) -> str:
    """Live CPU/memory usage per pod, sorted by memory (requires metrics-server)."""
    validate_identifier(namespace, "namespace")
    return await run_readonly(
        "kubectl", _ALLOWED, ["top", "pods", "-n", namespace, "--sort-by=memory"]
    )


@mcp.tool()
async def get_hpa(namespace: str, name: str) -> str:
    """HPA status: current/desired replicas and utilization vs. target."""
    validate_identifier(namespace, "namespace")
    validate_identifier(name, "name")
    return await run_readonly(
        "kubectl", _ALLOWED, ["get", "hpa", name, "-n", namespace, "-o", "wide"]
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
