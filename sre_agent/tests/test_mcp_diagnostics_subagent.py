"""Tests for the MCP diagnostics subagent's bounded tool-calling loop."""
import pytest

from sre_agent.integrations.normalizers import normalize, to_incident
from sre_agent.subagents.mcp_diagnostics import MCPDiagnosticsSubagent


class FakeTool:
    """Minimal stand-in for a langchain-mcp-adapters StructuredTool."""

    def __init__(self, name: str, result: str = "ok", raises: bool = False):
        self.name = name
        self.description = f"fake {name}"
        self._result = result
        self._raises = raises
        self.calls = []

    async def ainvoke(self, args):
        self.calls.append(args)
        if self._raises:
            raise RuntimeError("boom")
        return self._result


class FakeToolCallResponse:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls
        self.content = ""


class FakeBoundModel:
    """Replays a scripted sequence of tool-call responses, then stops."""

    def __init__(self, script):
        self._script = list(script)
        self.invocations = 0

    async def ainvoke(self, messages):
        self.invocations += 1
        if self._script:
            return self._script.pop(0)
        return FakeToolCallResponse(tool_calls=[])


class FakeModel:
    def __init__(self, script):
        self._bound = FakeBoundModel(script)

    def bind_tools(self, tools):
        return self._bound


@pytest.mark.unit
async def test_no_mcp_tools_returns_no_evidence(azure_monitor_alert):
    subagent = MCPDiagnosticsSubagent(tools=[])
    incident = to_incident(normalize(azure_monitor_alert))
    evidence = await subagent.collect(incident)
    assert evidence == []


@pytest.mark.unit
async def test_offline_fallback_calls_search_knowledge_once(azure_monitor_alert, monkeypatch):
    from sre_agent import llm as llm_module

    monkeypatch.setattr(llm_module, "get_chat_model", lambda: None)
    search_tool = FakeTool("search_knowledge", result="found: prior OOM incident")
    other_tool = FakeTool("get_pods")

    subagent = MCPDiagnosticsSubagent(tools=[search_tool, other_tool])
    incident = to_incident(normalize(azure_monitor_alert))
    evidence = await subagent.collect(incident)

    assert len(evidence) == 1
    assert evidence[0].source == "mcp:search_knowledge"
    assert "prior OOM incident" in evidence[0].observation
    assert len(search_tool.calls) == 1
    assert not other_tool.calls  # only the deterministic fallback tool is called


@pytest.mark.unit
async def test_offline_fallback_with_no_search_tool_returns_nothing(azure_monitor_alert, monkeypatch):
    from sre_agent import llm as llm_module

    monkeypatch.setattr(llm_module, "get_chat_model", lambda: None)
    subagent = MCPDiagnosticsSubagent(tools=[FakeTool("get_pods")])
    incident = to_incident(normalize(azure_monitor_alert))
    assert await subagent.collect(incident) == []


@pytest.mark.unit
async def test_tool_calling_loop_executes_and_stops(azure_monitor_alert, monkeypatch):
    from sre_agent import llm as llm_module

    pods_tool = FakeTool("get_pods", result="pod-1 Running")
    script = [
        FakeToolCallResponse(
            tool_calls=[{"id": "1", "name": "get_pods", "args": {"namespace": "prod"}}]
        ),
        FakeToolCallResponse(tool_calls=[]),  # model stops after one call
    ]
    fake_model = FakeModel(script)
    monkeypatch.setattr(llm_module, "get_chat_model", lambda: fake_model)

    subagent = MCPDiagnosticsSubagent(tools=[pods_tool])
    incident = to_incident(normalize(azure_monitor_alert))
    evidence = await subagent.collect(incident)

    assert len(evidence) == 1
    assert evidence[0].source == "mcp:get_pods"
    assert "pod-1 Running" in evidence[0].observation
    assert pods_tool.calls == [{"namespace": "prod"}]
    assert fake_model._bound.invocations == 2  # one tool-call turn + one stop turn


@pytest.mark.unit
async def test_tool_calling_loop_bounded_by_max_iterations(azure_monitor_alert, monkeypatch):
    from sre_agent import llm as llm_module
    from sre_agent.subagents import mcp_diagnostics as mod

    pods_tool = FakeTool("get_pods", result="ok")
    # Model always wants to call another tool — the loop must not run forever.
    infinite_call = FakeToolCallResponse(
        tool_calls=[{"id": "x", "name": "get_pods", "args": {"namespace": "prod"}}]
    )
    fake_model = FakeModel([infinite_call] * 10)
    monkeypatch.setattr(llm_module, "get_chat_model", lambda: fake_model)

    subagent = MCPDiagnosticsSubagent(tools=[pods_tool])
    incident = to_incident(normalize(azure_monitor_alert))
    evidence = await subagent.collect(incident)

    assert len(evidence) == mod.MAX_TOOL_ITERATIONS
    assert fake_model._bound.invocations == mod.MAX_TOOL_ITERATIONS


@pytest.mark.unit
async def test_unknown_tool_call_recorded_as_error_not_crash(azure_monitor_alert, monkeypatch):
    from sre_agent import llm as llm_module

    script = [
        FakeToolCallResponse(
            tool_calls=[{"id": "1", "name": "nonexistent_tool", "args": {}}]
        ),
        FakeToolCallResponse(tool_calls=[]),
    ]
    fake_model = FakeModel(script)
    monkeypatch.setattr(llm_module, "get_chat_model", lambda: fake_model)

    subagent = MCPDiagnosticsSubagent(tools=[FakeTool("get_pods")])
    incident = to_incident(normalize(azure_monitor_alert))
    evidence = await subagent.collect(incident)

    assert len(evidence) == 1
    assert "Unknown tool" in evidence[0].observation


@pytest.mark.unit
async def test_tool_exception_recorded_not_raised(azure_monitor_alert, monkeypatch):
    from sre_agent import llm as llm_module

    failing_tool = FakeTool("get_pods", raises=True)
    script = [
        FakeToolCallResponse(tool_calls=[{"id": "1", "name": "get_pods", "args": {}}]),
        FakeToolCallResponse(tool_calls=[]),
    ]
    fake_model = FakeModel(script)
    monkeypatch.setattr(llm_module, "get_chat_model", lambda: fake_model)

    subagent = MCPDiagnosticsSubagent(tools=[failing_tool])
    incident = to_incident(normalize(azure_monitor_alert))
    evidence = await subagent.collect(incident)  # must not raise

    assert "Tool call failed" in evidence[0].observation


@pytest.mark.unit
def test_heuristic_finding_reflects_evidence_presence(azure_monitor_alert):
    subagent = MCPDiagnosticsSubagent()
    incident = to_incident(normalize(azure_monitor_alert))
    empty = subagent.heuristic_finding(incident, [])
    assert empty.confidence == 0.0

    from sre_agent.models import Evidence

    nonempty = subagent.heuristic_finding(
        incident, [Evidence(source="mcp:get_pods", observation="x", data={})]
    )
    assert nonempty.confidence > 0.0


@pytest.mark.unit
def test_registered_in_subagent_registry():
    from sre_agent.subagents.registry import SubagentRegistry

    registry = SubagentRegistry()
    assert "mcp_diagnostics" in registry.names()
