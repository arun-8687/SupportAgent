"""Memory system tests: synthesized md files, user memories, KB, insights."""
import pytest

from sre_agent.memory.knowledge_base import KnowledgeBase
from sre_agent.memory.synthesized import OVERVIEW_FILE, SynthesizedKnowledge
from sre_agent.memory.user_memories import UserMemoryStore
from sre_agent.models import SessionInsight


# --------------------------------------------------------------------------- #
# Synthesized knowledge (markdown files)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_save_topic_creates_md_file_and_overview_link(tmp_path):
    knowledge = SynthesizedKnowledge(directory=tmp_path)
    filename = knowledge.save_topic(
        "aks networking gotchas",
        "The ingress controller must start before app pods.",
    )
    assert filename == "aks-networking-gotchas.md"
    assert (tmp_path / filename).exists()
    assert "ingress controller" in knowledge.read_topic("aks networking gotchas")

    overview = (tmp_path / OVERVIEW_FILE).read_text()
    assert "aks-networking-gotchas.md" in overview  # linked from overview


@pytest.mark.unit
def test_topic_merge_appends_not_overwrites(tmp_path):
    knowledge = SynthesizedKnowledge(directory=tmp_path)
    knowledge.save_topic("deployment", "Pipeline uses blue/green slots.")
    knowledge.save_topic("deployment", "Rollback takes ~4 minutes.")
    content = knowledge.read_topic("deployment")
    assert "blue/green" in content and "Rollback" in content


@pytest.mark.unit
def test_overview_respects_character_budget(tmp_path):
    knowledge = SynthesizedKnowledge(directory=tmp_path)
    (tmp_path / OVERVIEW_FILE).write_text("x" * 10000)
    assert len(knowledge.load_overview()) <= 2000


@pytest.mark.unit
def test_synthesized_search_finds_topic(tmp_path):
    knowledge = SynthesizedKnowledge(directory=tmp_path)
    knowledge.save_topic("auth", "Production uses managed identity for SQL auth.")
    hits = knowledge.search("how does production SQL auth work")
    assert "auth.md" in hits


# --------------------------------------------------------------------------- #
# User memories (#remember / #retrieve / #forget)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_remember_retrieve_forget(tmp_path):
    store = UserMemoryStore(path=tmp_path / "user_memories.jsonl")
    store.remember("Production uses 3 AKS clusters in West US 2")
    store.remember("Database failover takes approximately 15 minutes")

    hits = store.retrieve("how long does database failover take?")
    assert hits
    assert "15 minutes" in hits[0].fact

    removed = store.forget("database failover")
    assert removed == 1
    assert not store.retrieve("database failover")
    # Unrelated memory survives.
    assert store.retrieve("AKS clusters")


# --------------------------------------------------------------------------- #
# Knowledge base (uploaded docs)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_knowledge_base_upload_and_search_with_citation(tmp_path):
    kb = KnowledgeBase(directory=tmp_path)
    kb.add_document(
        "production-database-failover.md",
        "# DB failover runbook\n1. Verify secondary replica health\n2. Initiate failover",
    )
    results = kb.search("how should I handle a database failover?")
    assert results
    assert results[0].citation == "production-database-failover.md"
    assert "secondary replica" in results[0].content


@pytest.mark.unit
def test_knowledge_base_rejects_unsupported_format(tmp_path):
    kb = KnowledgeBase(directory=tmp_path)
    with pytest.raises(ValueError):
        kb.add_document("binary.exe", "nope")


# --------------------------------------------------------------------------- #
# Unified search + session insights
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_unified_search_spans_all_sources(agent_memory):
    agent_memory.user_memories.remember("Redis cache uses Premium tier with 6GB")
    agent_memory.knowledge_base.add_document(
        "redis-runbook.md", "# Redis runbook\nFailover takes about 90 seconds."
    )
    agent_memory.synthesized.save_topic("architecture", "checkout uses redis cache heavily")

    results = agent_memory.search("redis cache failover")
    sources = {r.source for r in results}
    assert "user_memory" in sources
    assert "knowledge_base" in sources
    assert "synthesized" in sources
    assert all(r.citation for r in results)


@pytest.mark.unit
def test_session_insight_persists_and_updates_md_files(agent_memory):
    insight = SessionInsight(
        insight_id=agent_memory.new_insight_id(),
        incident_id="sre-abc",
        service_name="payment-service",
        symptoms_observed=["HTTP 503 errors", "memory at 95%"],
        resolution_steps=["Scaled up App Service SKU"],
        root_cause="Memory leak in deployment v2.3",
        pitfalls_to_avoid=["Restarting didn't help"],
        outcome="resolved",
    )
    agent_memory.capture_session_insight(insight)

    assert len(agent_memory.load_insights()) == 1
    # Insight merged into synthesized markdown knowledge.
    topic = agent_memory.synthesized.read_topic("debugging payment-service")
    assert "Memory leak in deployment v2.3" in topic
    assert "Restarting didn't help" in topic
