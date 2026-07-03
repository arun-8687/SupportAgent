"""
Markdown frontmatter parsing.

Skills and custom agents are authored as single markdown files: a YAML
frontmatter block carries the structured metadata, and the markdown body
carries the prose (procedural guidance for skills, the system prompt for
custom agents).

    ---
    name: database_expert
    handoff_description: Handles SQL and database troubleshooting
    tools: [query_metrics]
    ---
    You are a database specialist...
"""
import re
from typing import Any, Dict, Tuple

import yaml

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)


def parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    """Split a markdown document into (metadata, body).

    Returns ({}, text) when there is no frontmatter block or the block
    isn't a YAML mapping — the caller decides whether metadata is required.
    """
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    try:
        meta = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return {}, text
    if not isinstance(meta, dict):
        return {}, text
    return meta, match.group(2)
