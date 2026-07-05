"""Shared fixtures for SRE Agent tests (fully offline: no LLM, no Azure)."""
import json
from pathlib import Path

import pytest

from sre_agent.gate.permission_gate import PermissionGate
from sre_agent.graph.nodes import SREAgentNodes
from sre_agent.hooks.engine import HookEngine
from sre_agent.known_errors import KnownErrorStore
from sre_agent.memory.knowledge_base import KnowledgeBase
from sre_agent.memory.knowledge_store import KnowledgeStore
from sre_agent.memory.synthesized import SynthesizedKnowledge
from sre_agent.memory.unified import AgentMemory
from sre_agent.memory.user_memories import UserMemoryStore
from sre_agent.service import SREAgentService
from sre_agent.skills.executor import SkillExecutor
from sre_agent.skills.registry import SkillRegistry
from sre_agent.stores import FileAlertLedger, FilePendingApprovalStore

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
def alert_ledger(tmp_path) -> FileAlertLedger:
    return FileAlertLedger(path=tmp_path / "alert_ledger.jsonl")


@pytest.fixture
def pending_approvals(tmp_path) -> FilePendingApprovalStore:
    return FilePendingApprovalStore(path=tmp_path / "pending_approvals.jsonl")


@pytest.fixture
def known_errors(tmp_path) -> KnownErrorStore:
    """Known-error store rooted in a temp dir (no repo pollution)."""
    return KnownErrorStore(
        global_dir=tmp_path / "known_errors",
        apps_dir=tmp_path / "apps",
    )


@pytest.fixture
def service(
    knowledge_store, agent_memory, skills, hooks, alert_ledger, pending_approvals, known_errors
) -> SREAgentService:
    """Full workflow wired with dry-run executor and temp stores."""
    nodes = SREAgentNodes(
        skills=skills,
        gate=PermissionGate(autonomous_mode=False),
        hooks=hooks,
        knowledge=knowledge_store,
        memory=agent_memory,
        executor=SkillExecutor(registry=skills, dry_run=True, hooks=hooks),
        known_errors=known_errors,
    )
    return SREAgentService(
        nodes=nodes,
        alert_ledger=alert_ledger,
        pending_approvals=pending_approvals,
    )


@pytest.fixture
def production_settings(monkeypatch):
    """Switch settings to production strict mode for one test."""
    from sre_agent.config import get_settings

    monkeypatch.setenv("SRE_AGENT_ENVIRONMENT", "production")
    get_settings.cache_clear()
    yield get_settings()
    monkeypatch.delenv("SRE_AGENT_ENVIRONMENT", raising=False)
    get_settings.cache_clear()
