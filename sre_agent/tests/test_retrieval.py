"""
Semantic retrieval tests.

Uses a deterministic fake embedder (keyword-bag -> sparse vector) so the
vector store's ranking, save/search/load_all surface, same-service boost,
factory selection, and graceful degradation are all covered without a live
Postgres or a real embedding API. A pgvector integration test is included
but auto-skips unless SRE_AGENT_TEST_DATABASE_URL points at a real DB.
"""
import os

import pytest

from sre_agent.models import KnowledgeRecord
from sre_agent.retrieval import embeddings
from sre_agent.retrieval.vector_index import (
    InMemoryVectorIndex,
    VectorHit,
    cosine_similarity,
)
from sre_agent.retrieval.vector_knowledge_store import (
    VectorKnowledgeStore,
    create_incident_knowledge_store,
)


# --------------------------------------------------------------------------- #
# Deterministic fake embedder
# --------------------------------------------------------------------------- #

_VOCAB = [
    "memory", "oom", "leak", "cpu", "latency", "disk", "network",
    "payment", "orders", "checkout", "restart", "scale", "deploy",
]


class FakeEmbedder:
    """Bag-of-known-words -> unit-ish vector. Shared vocabulary means texts
    about the same topic land near each other in cosine space."""

    def embed_query(self, text: str):
        low = text.lower()
        return [1.0 if word in low else 0.0 for word in _VOCAB]

    def embed_documents(self, texts):
        return [self.embed_query(t) for t in texts]


@pytest.fixture
def fake_embedder(monkeypatch):
    embeddings.reset_for_tests()
    monkeypatch.setattr(embeddings, "get_embedder", lambda: FakeEmbedder())
    yield
    embeddings.reset_for_tests()


def _record(rid, title, service="payment-service", root_cause="", tags=None):
    return KnowledgeRecord(
        record_id=rid, incident_id=f"i-{rid}", service_name=service,
        title=title, root_cause=root_cause, category="memory",
        mitigations=["restart_aks_deployment"], tags=tags or [],
    )


# --------------------------------------------------------------------------- #
# Cosine + in-memory index
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_cosine_bounds():
    assert cosine_similarity([1, 0], [1, 0]) == 1.0
    assert cosine_similarity([1, 0], [0, 1]) == 0.0
    assert cosine_similarity([], [1]) == 0.0
    assert cosine_similarity([0, 0], [0, 0]) == 0.0


@pytest.mark.unit
def test_in_memory_index_ranks_by_similarity():
    idx = InMemoryVectorIndex()
    idx.add("a", [1, 0, 0], {"service_name": "x"})
    idx.add("b", [0, 1, 0], {"service_name": "x"})
    hits = idx.query([0.9, 0.1, 0], top_k=2)
    assert [h.id for h in hits] == ["a", "b"]
    assert hits[0].score > hits[1].score


@pytest.mark.unit
def test_in_memory_same_service_boost():
    idx = InMemoryVectorIndex()
    idx.add("same", [1, 0], {"service_name": "payment"})
    idx.add("other", [1, 0], {"service_name": "orders"})
    hits = idx.query([1, 0], top_k=2, service_name="payment")
    assert hits[0].id == "same"  # identical vector, boost breaks the tie


# --------------------------------------------------------------------------- #
# VectorKnowledgeStore behaves like KnowledgeStore
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_semantic_search_returns_relevant_record(fake_embedder):
    store = VectorKnowledgeStore(InMemoryVectorIndex())
    store.save(_record("1", "payment memory leak OOM"))
    store.save(_record("2", "checkout latency network slowness", service="checkout"))

    matches = store.search("memory oom", service_name="payment-service")
    assert matches
    assert matches[0].record_id == "1"
    assert matches[0].similarity > 0


@pytest.mark.unit
def test_search_returns_knowledge_match_shape(fake_embedder):
    store = VectorKnowledgeStore(InMemoryVectorIndex())
    store.save(_record("1", "payment memory leak", root_cause="leak in v2"))
    match = store.search("memory")[0]
    assert match.record_id == "1"
    assert match.root_cause == "leak in v2"
    assert match.resolution == "restart_aks_deployment"
    assert 0.0 <= match.similarity <= 1.0


@pytest.mark.unit
def test_load_all_roundtrips(fake_embedder):
    store = VectorKnowledgeStore(InMemoryVectorIndex())
    store.save(_record("1", "payment memory leak"))
    store.save(_record("2", "orders cpu"))
    ids = {r.record_id for r in store.load_all()}
    assert ids == {"1", "2"}


@pytest.mark.unit
def test_new_record_id_prefix():
    assert VectorKnowledgeStore.new_record_id().startswith("kb-")


# --------------------------------------------------------------------------- #
# Degradation
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_search_without_embedder_returns_empty(monkeypatch):
    embeddings.reset_for_tests()
    monkeypatch.setattr(embeddings, "get_embedder", lambda: None)
    store = VectorKnowledgeStore(InMemoryVectorIndex())
    # save still mirrors nothing (no mirror path) and doesn't raise.
    store.save(_record("1", "payment memory leak"))
    assert store.search("memory") == []
    embeddings.reset_for_tests()


@pytest.mark.unit
def test_mirror_persists_and_rehydrates(fake_embedder, tmp_path):
    mirror = tmp_path / "mirror.jsonl"
    store = VectorKnowledgeStore(InMemoryVectorIndex(), mirror_path=mirror)
    store.save(_record("1", "payment memory leak OOM"))
    assert mirror.exists()

    # A fresh store over a new index rehydrates from the mirror at startup.
    store2 = VectorKnowledgeStore(InMemoryVectorIndex(), mirror_path=mirror)
    matches = store2.search("memory oom", service_name="payment-service")
    assert matches and matches[0].record_id == "1"


# --------------------------------------------------------------------------- #
# Factory selection
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_factory_defaults_to_file_without_embeddings(monkeypatch):
    from sre_agent.config import get_settings
    from sre_agent.memory.knowledge_store import KnowledgeStore

    embeddings.reset_for_tests()
    get_settings.cache_clear()
    store = create_incident_knowledge_store()
    assert isinstance(store, KnowledgeStore)  # keyword backend


@pytest.mark.unit
def test_factory_memory_backend_with_embeddings(monkeypatch, tmp_path):
    from sre_agent.config import get_settings

    monkeypatch.setenv("SRE_AGENT_OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SRE_AGENT_KNOWLEDGE_VECTOR_BACKEND", "memory")
    monkeypatch.setenv("SRE_AGENT_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        store = create_incident_knowledge_store()
        assert isinstance(store, VectorKnowledgeStore)
    finally:
        for var in ("SRE_AGENT_OPENAI_API_KEY", "SRE_AGENT_KNOWLEDGE_VECTOR_BACKEND", "SRE_AGENT_DATA_DIR"):
            monkeypatch.delenv(var, raising=False)
        get_settings.cache_clear()


@pytest.mark.unit
def test_factory_pgvector_forced_without_db_raises(monkeypatch):
    from sre_agent.config import get_settings

    monkeypatch.setenv("SRE_AGENT_KNOWLEDGE_VECTOR_BACKEND", "pgvector")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="pgvector"):
            create_incident_knowledge_store()
    finally:
        monkeypatch.delenv("SRE_AGENT_KNOWLEDGE_VECTOR_BACKEND", raising=False)
        get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# pgvector integration (skipped unless a real DB is provided)
# --------------------------------------------------------------------------- #

@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SRE_AGENT_TEST_DATABASE_URL"),
    reason="set SRE_AGENT_TEST_DATABASE_URL to a pgvector-enabled Postgres",
)
def test_pgvector_index_roundtrip(fake_embedder):
    from sre_agent.retrieval.vector_index import PgVectorIndex

    url = os.environ["SRE_AGENT_TEST_DATABASE_URL"]
    index = PgVectorIndex(url, dim=len(_VOCAB), table="sre_knowledge_vectors_test")
    store = VectorKnowledgeStore(index)
    store.save(_record("pg1", "payment memory leak OOM"))
    matches = store.search("memory oom", service_name="payment-service")
    assert matches and matches[0].record_id == "pg1"
