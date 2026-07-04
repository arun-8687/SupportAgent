"""
MCP diagnostics subagent.

The only subagent that reasons dynamically instead of running a fixed
collect() query: it binds every enabled MCP server's tools (see
mcp/servers.yaml — kubectl-readonly, azure-readonly, knowledge-search by
default, plus any third-party server an operator enables) to the LLM and
runs a bounded tool-calling loop, letting the model decide which
diagnostics to pull based on the incident at hand instead of a
hard-coded query per subagent.

This is deliberately read-only. Every shipped MCP tool is a diagnostic
verb (get/describe/logs/top, show/list, search) with no mutating
counterpart — there is no permission gate here because there is nothing
for it to gate. If a future MCP server exposes a mutating tool, it must
be proposed as a MitigationAction through propose_mitigation like any
other action, not called from this loop.

Every tool result is fenced as untrusted external data before re-entering
the conversation (an on-prem log line is exactly the kind of content
prompt-injection guidance targets), and every call is logged as a step
for the same App Insights correlation every other action gets.

Offline/no-LLM fallback: without a configured model this subagent can't
reason about which tool to call, so it falls back to one direct
search_knowledge call (if the knowledge-search server is enabled) —
useful, deterministic, and free of any tool-selection guesswork.
"""
import logging
from typing import Any, Dict, List, Optional

from sre_agent import llm as llm_module
from sre_agent.mcp.loader import load_mcp_tools
from sre_agent.models import Evidence, Incident, SubagentFinding
from sre_agent.observability import log_step
from sre_agent.security import external_data_block
from sre_agent.subagents.base import Subagent

logger = logging.getLogger(__name__)

MAX_TOOL_ITERATIONS = 4
MAX_RESULT_CHARS = 1500


class MCPDiagnosticsSubagent(Subagent):
    name = "mcp_diagnostics"
    description = (
        "You dynamically query connected MCP tools (Kubernetes, Azure "
        "resource diagnostics, institutional knowledge search, and any "
        "operator-enabled MCP server) to gather whatever evidence the "
        "incident actually calls for, instead of a fixed set of queries."
    )

    def __init__(self, tools: Optional[List[Any]] = None) -> None:
        # Pre-supplied tools (tests, or a caller that already loaded them)
        # skip the MCP client round-trip.
        self._tools_override = tools

    async def _load_tools(self) -> List[Any]:
        if self._tools_override is not None:
            return self._tools_override
        try:
            return await load_mcp_tools()
        except Exception:
            logger.exception("Failed to load MCP tools; continuing without them")
            return []

    async def collect(self, incident: Incident) -> List[Evidence]:
        tools = await self._load_tools()
        if not tools:
            return []

        model = llm_module.get_chat_model()
        if model is None:
            return await self._fallback_knowledge_search(incident, tools)

        return await self._tool_calling_loop(incident, tools, model)

    async def _fallback_knowledge_search(
        self, incident: Incident, tools: List[Any]
    ) -> List[Evidence]:
        """No LLM to drive tool selection: one deterministic knowledge lookup."""
        search_tool = next((t for t in tools if t.name == "search_knowledge"), None)
        if search_tool is None:
            return []
        query = f"{incident.alert.title} {incident.service_name}"
        try:
            result = await search_tool.ainvoke({"query": query, "service_name": incident.service_name})
        except Exception as exc:
            logger.warning("Fallback knowledge search failed: %s", exc)
            return []
        return [
            Evidence(
                source="mcp:search_knowledge",
                observation=str(result)[:MAX_RESULT_CHARS],
                data={"query": query},
            )
        ]

    async def _tool_calling_loop(
        self, incident: Incident, tools: List[Any], model: Any
    ) -> List[Evidence]:
        from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

        bound = model.bind_tools(tools)
        tool_by_name: Dict[str, Any] = {t.name: t for t in tools}

        messages: List[Any] = [
            SystemMessage(
                content=(
                    "You are investigating an SRE incident. Use the available tools "
                    "to gather diagnostic evidence relevant to the incident below. "
                    "Call at most a few tools, then stop once you have enough signal — "
                    "do not call tools that are unrelated to the incident's resource type."
                )
            ),
            HumanMessage(
                content=(
                    f"Incident: {incident.alert.title}\n"
                    f"Service: {incident.service_name} ({incident.environment})\n"
                    f"Resource: {incident.alert.resource.resource_id or 'unknown'}\n"
                    f"Description (untrusted):\n"
                    + external_data_block(incident.alert.description)
                )
            ),
        ]

        evidence: List[Evidence] = []
        for iteration in range(MAX_TOOL_ITERATIONS):
            try:
                response = await bound.ainvoke(messages)
            except Exception:
                logger.exception("MCP tool-calling loop failed on iteration %d", iteration)
                break
            messages.append(response)

            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                break

            for call in tool_calls:
                result_text, error = await self._invoke_tool(tool_by_name, call)
                log_step(
                    "mcp_tool_call",
                    "failed" if error else "succeeded",
                    incident_id=incident.incident_id,
                    tool=call.get("name"),
                    iteration=iteration,
                )
                evidence.append(
                    Evidence(
                        source=f"mcp:{call.get('name', 'unknown')}",
                        observation=(result_text or error or "")[:MAX_RESULT_CHARS],
                        data={"args": call.get("args", {})},
                    )
                )
                messages.append(
                    ToolMessage(
                        content=external_data_block((result_text or error or "")[:MAX_RESULT_CHARS]),
                        tool_call_id=call.get("id", call.get("name", "")),
                    )
                )
        return evidence

    @staticmethod
    async def _invoke_tool(tool_by_name: Dict[str, Any], call: dict) -> tuple:
        """Returns (result_text, error_text) — exactly one is set."""
        tool = tool_by_name.get(call.get("name", ""))
        if tool is None:
            return None, f"Unknown tool: {call.get('name')}"
        try:
            result = await tool.ainvoke(call.get("args", {}))
            return str(result), None
        except Exception as exc:
            return None, f"Tool call failed: {exc}"

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        if not evidence:
            return SubagentFinding(
                subagent=self.name,
                summary="No MCP servers enabled or reachable; no dynamic diagnostics gathered.",
                confidence=0.0,
            )
        return SubagentFinding(
            subagent=self.name,
            summary=f"Gathered {len(evidence)} evidence item(s) via dynamic MCP tool calls.",
            confidence=0.3,
        )
