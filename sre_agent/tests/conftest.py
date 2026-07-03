"""Shared fixtures for SRE Agent tests (fully offline: no LLM, no Azure)."""
import json
from pathlib import Path

import pytest

from sre_agent.gate.permission_gate import PermissionGate
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.hooks.engine import HookEngine
from sre_agent.memory.knowledge_base import KnowledgeBase
from sre_agent.memory.knowledge_store import KnowledgeStore
from sre_agent.memory.synthesized import SynthesizedKnowledge
from sre_agent.memory.unified import AgentMemory
from sre_agent.memory.user_memories import UserMemoryStore
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
def agent_memory(tmp_path, knowledge_store) -> AgentMemory:
    """Unified memory rooted in a temp directory (no repo pollution)."""
    return AgentMemory(
        incidents=knowledge_store,
        user_memories=UserMemoryStore(path=tmp_path / "memories" / "user_memories.jsonl"),
        knowledge_base=KnowledgeBase(directory=tmp_path / "knowledge_base"),
        synthesized=SynthesizedKnowledge(directory=tmp_path / "memories" / "synthesizedKnowledge"),
        insights_path=tmp_path / "memories" / "session_insights.jsonl",
    )


@pytest.fixture
def skills() -> SkillRegistry:
    return SkillRegistry()


@pytest.fixture
def hooks() -> HookEngine:
    return HookEngine()


@pytest.fixture
def service(knowledge_store, agent_memory, skills, hooks) -> SREAgentService:
    """Full workflow wired with dry-run executor and temp memory stores."""
    nodes = SREAgentNodes(
        skills=skills,
        gate=PermissionGate(autonomous_mode=False),
        hooks=hooks,
        knowledge=knowledge_store,
        memory=agent_memory,
        executor=SkillExecutor(registry=skills, dry_run=True, hooks=hooks),
    )
    return SREAgentService(nodes=nodes)
