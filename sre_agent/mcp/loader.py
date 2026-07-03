"""
MCP connector loader.

Connects the agent to external platforms (Grafana, Prometheus, GitHub,
Datadog, ...) through the Model Context Protocol. Server definitions live
in servers.yaml; enabled servers' tools are returned as LangChain tools
that subagents can call during evidence collection.

Requires the optional `langchain-mcp-adapters` package; without it (or
with every server disabled) this returns an empty tool list and the
built-in Python tools carry the investigation.
"""
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from sre_agent.config import get_settings

logger = logging.getLogger(__name__)

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_server_configs(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Read enabled MCP server definitions, expanding ${ENV_VAR} references."""
    path = path or get_settings().mcp_servers_file
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    configs: Dict[str, Dict[str, Any]] = {}
    for server in data.get("servers", []):
        if not server.get("enabled", False):
            continue
        name = server["name"]
        conf = _expand_env({k: v for k, v in server.items() if k not in ("name", "enabled")})
        configs[name] = conf
    return configs


async def load_mcp_tools(path: Optional[Path] = None) -> List[Any]:
    """Return LangChain tools from all enabled MCP servers."""
    configs = load_server_configs(path)
    if not configs:
        return []
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
    except ImportError:
        logger.warning(
            "langchain-mcp-adapters not installed; MCP servers %s ignored",
            list(configs),
        )
        return []
    client = MultiServerMCPClient(configs)
    tools = await client.get_tools()
    logger.info("Loaded %d MCP tools from %s", len(tools), list(configs))
    return tools
