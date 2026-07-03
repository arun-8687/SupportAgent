"""Shared fixtures for SRE Agent tests (fully offline: no LLM, no Azure)."""
import json
from pathlib import Path

import pytest

from sre_agent.gate.permission_gate import PermissionGate
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.hooks.engine import HookEngine
from sre_agent.memory.knowledge_store import KnowledgeStore
from sre_agent.service import SREAgentService
from sre_agent.skills.executor import SkillExecutor
from sre_agent.skills.registry import SkillRegistry

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def azure_monitor_alert() -> dict:
    return json.loads((SAMPLES / "azure_monitor_alert.json").read_text())


@pytest.fixture
def pagerduty_alert() -> dict:
    return json.loads((SAMPLES / "pagerduty_alert.json").read_text())


@pytest.fixture
def knowledge_store(tmp_path) -> KnowledgeStore:
    return KnowledgeStore(path=tmp_path / "knowledge.jsonl")


@pytest.fixture
def skills() -> SkillRegistry:
    return SkillRegistry()


@pytest.fixture
def service(knowledge_store, skills) -> SREAgentService:
    """Full workflow wired with dry-run executor and temp knowledge store."""
    nodes = SREAgentNodes(
        skills=skills,
        gate=PermissionGate(autonomous_mode=False),
        hooks=HookEngine(),
        knowledge=knowledge_store,
        executor=SkillExecutor(registry=skills, dry_run=True),
    )
    return SREAgentService(nodes=nodes)
