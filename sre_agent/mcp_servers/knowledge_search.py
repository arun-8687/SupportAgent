"""
knowledge-search MCP server.

Exposes the SRE agent's own institutional knowledge — past incidents,
user-saved facts, uploaded runbooks, and synthesized notes — as MCP
tools. Unlike kubectl_readonly/azure_readonly (which shell out to
external CLIs), this server is in-process: it reads the same data
directory (SRE_AGENT_DATA_DIR) the running agent writes to, so results
are always current.

Two consumers:
  1. External MCP clients (Claude Desktop, VS Code, another agent) can
     ask "how did we fix this before?" without going through the
     incident workflow.
  2. The agent's own mcp_diagnostics subagent (subagents/mcp_diagnostics.py)
     loads this server like any other, so a bounded tool-calling loop can
     query knowledge as one more source of evidence mid-investigation.

Run standalone: python -m sre_agent.mcp_servers.knowledge_search
"""
from mcp.server.fastmcp import FastMCP

from sre_agent.memory.unified import AgentMemory

mcp = FastMCP("knowledge-search")

# One AgentMemory instance for the process lifetime — memory stores cache
# by file mtime, so this stays cheap and always current.
_memory = AgentMemory()


@mcp.tool()
async def search_knowledge(query: str, service_name: str = "") -> str:
    """
    Search all institutional knowledge (past incidents, saved facts,
    uploaded runbooks, synthesized notes) for one query. Returns ranked
    excerpts with citations. Pass service_name to boost same-service
    past incidents.
    """
    results = _memory.search(query, service_name=service_name or None, top_k=5)
    if not results:
        return "No matching knowledge found."
    return "\n\n".join(
        f"[{r.source}:{r.citation}] (similarity {r.similarity:.2f}) {r.title}\n{r.content}"
        for r in results
    )


@mcp.tool()
async def remember_fact(fact: str) -> str:
    """Save a discrete operational fact for future incidents (#remember)."""
    memory = _memory.user_memories.remember(fact)
    return f"Saved as {memory.memory_id}: {memory.fact}"


@mcp.tool()
async def list_knowledge_documents() -> str:
    """List uploaded runbooks/docs available in the knowledge base."""
    docs = _memory.knowledge_base.list_documents()
    return "\n".join(docs) if docs else "No knowledge base documents uploaded."


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
