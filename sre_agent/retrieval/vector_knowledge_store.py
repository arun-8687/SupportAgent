"""
Vector-backed incident knowledge store.

Drop-in replacement for memory.knowledge_store.KnowledgeStore: identical
save / search / load_all / new_record_id surface returning KnowledgeMatch,
so AgentMemory and the graph nodes use it unchanged. Retrieval is semantic
(embedding cosine) instead of keyword overlap, so recall no longer degrades
as the corpus grows past thousands of records — the reason the file store
was flagged at 40k/day scale.

Backends (via the factory): pgvector for production (durable, indexed),
in-memory for dev/single-instance. The in-memory index is not durable on
its own, so records are mirrored to JSONL and re-indexed at startup; the
pgvector backend needs no mirror (Postgres is durable).

Degradation: a query that can't be embedded returns [] (logged) rather
than throwing; a record that can't be embedded on save is still mirrored
so it is not lost. The factory only selects this store when embeddings are
configured, so the offline default stays the keyword file store.
"""
import logging
import uuid
from pathlib import Path
from typing import List, Optional

from sre_agent.config import get_settings
from sre_agent.locking import file_lock
from sre_agent.models import KnowledgeMatch, KnowledgeRecord
from sre_agent.retrieval import embeddings
from sre_agent.retrieval.vector_index import (
    InMemoryVectorIndex,
    PgVectorIndex,
    VectorIndex,
)

logger = logging.getLogger(__name__)


def _record_text(record: KnowledgeRecord) -> str:
    """Text embedded per record — the same fields the keyword store
    tokenized, so ranking intent is preserved, just semantically."""
    return " ".join(
        [record.title, record.root_cause, record.category, *record.tags]
    ).strip()


class VectorKnowledgeStore:
    """Semantic incident knowledge store over a VectorIndex + embedder.

    Retrieval is hybrid by default: the semantic (vector) arm and the
    exact-keyword arm are fused with Reciprocal Rank Fusion so error codes
    and job names match exactly while symptoms match semantically — and so
    retrieval still works when embeddings are momentarily unavailable.
    """

    # RRF constant; 60 is the widely-used default. Rank-based fusion needs
    # no score normalization between cosine and keyword scales.
    RRF_K = 60

    def __init__(
        self,
        index: VectorIndex,
        mirror_path: Optional[Path] = None,
        hybrid: Optional[bool] = None,
    ) -> None:
        self.index = index
        self.mirror_path = mirror_path
        self.hybrid = get_settings().knowledge_hybrid_search if hybrid is None else hybrid
        if self.mirror_path is not None:
            self._rehydrate()

    def save(self, record: KnowledgeRecord) -> KnowledgeRecord:
        text = _record_text(record)
        vector = embeddings.embed_query_sync(text)
        if vector is not None:
            self.index.add(record.record_id, vector, record.model_dump(mode="json"), text=text)
        elif self.hybrid:
            # No embedding, but the keyword arm still needs the record —
            # index with a NULL vector so it stays keyword-searchable.
            self.index.add(record.record_id, None, record.model_dump(mode="json"), text=text)
        else:
            logger.warning(
                "Could not embed knowledge record %s; mirrored only", record.record_id
            )
        if self.mirror_path is not None:
            self._append_mirror(record)
        logger.info("Knowledge captured (vector): %s (%s)", record.record_id, record.title)
        return record

    def search(
        self, query: str, service_name: Optional[str] = None, top_k: int = 3
    ) -> List[KnowledgeMatch]:
        vector = embeddings.embed_query_sync(query)
        vector_hits = (
            self.index.query(vector, top_k=top_k, service_name=service_name)
            if vector
            else []
        )
        if not self.hybrid:
            if vector is None:
                logger.warning("Query embedding unavailable; no vector matches")
            return [self._to_match(h.payload, h.score) for h in vector_hits]

        keyword_hits = self.index.keyword_query(
            query, top_k=top_k, service_name=service_name
        )
        fused = self._rrf_fuse(vector_hits, keyword_hits, top_k)
        return [self._to_match(payload, score) for payload, score in fused]

    def _rrf_fuse(self, vector_hits, keyword_hits, top_k):
        """Reciprocal Rank Fusion of the two arms.

        Ordering is by fused rank (robust across score scales); the score
        reported on each match is the best interpretable relevance (cosine
        or keyword) from whichever arm ranked it, not the raw RRF value.
        """
        fused: dict = {}  # id -> [rrf, best_score, payload]
        for hits in (vector_hits, keyword_hits):
            for rank, hit in enumerate(hits, start=1):
                entry = fused.setdefault(hit.id, [0.0, 0.0, hit.payload])
                entry[0] += 1.0 / (self.RRF_K + rank)
                entry[1] = max(entry[1], hit.score)
        ordered = sorted(fused.values(), key=lambda e: e[0], reverse=True)
        return [(payload, best) for _rrf, best, payload in ordered[:top_k]]

    def load_all(self) -> List[KnowledgeRecord]:
        records = []
        for payload in self.index.all_payloads():
            try:
                records.append(KnowledgeRecord.model_validate(payload))
            except Exception:
                logger.warning("Skipping malformed indexed record")
        return records

    @staticmethod
    def new_record_id() -> str:
        return f"kb-{uuid.uuid4().hex[:10]}"

    # ------------------------------------------------------------------ #

    @staticmethod
    def _to_match(payload: dict, score: float) -> KnowledgeMatch:
        return KnowledgeMatch(
            record_id=payload.get("record_id", ""),
            title=payload.get("title", ""),
            root_cause=payload.get("root_cause") or None,
            resolution="; ".join(payload.get("mitigations", [])) or None,
            similarity=round(max(0.0, min(1.0, score)), 3),
        )

    def _append_mirror(self, record: KnowledgeRecord) -> None:
        self.mirror_path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(self.mirror_path), self.mirror_path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")

    def _rehydrate(self) -> None:
        """Re-index mirrored records at startup (memory-backend durability)."""
        if not self.mirror_path or not self.mirror_path.exists():
            return
        records = []
        for line in self.mirror_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(KnowledgeRecord.model_validate_json(line))
            except Exception:
                continue
        if not records:
            return
        texts = [_record_text(r) for r in records]
        vectors = embeddings.embed_texts_sync(texts)
        if vectors is None:
            if not self.hybrid:
                logger.warning("Rehydrate skipped: embeddings unavailable at startup")
                return
            # Hybrid: still re-index for the keyword arm (NULL vectors).
            vectors = [None] * len(records)
        for record, vector, text in zip(records, vectors, texts):
            self.index.add(record.record_id, vector, record.model_dump(mode="json"), text=text)
        logger.info("Rehydrated %d knowledge records into vector index", len(records))


def create_incident_knowledge_store():
    """Select the incident knowledge backend from settings.

    auto: pgvector when DATABASE_URL + embeddings; else in-memory vector
    when embeddings alone; else the keyword file store. Explicit values
    ("pgvector" | "memory" | "file") force a backend and fail loudly when
    the requested backend can't be built.
    """
    from sre_agent.memory.knowledge_store import KnowledgeStore

    settings = get_settings()
    backend = settings.knowledge_vector_backend.strip().lower()

    if backend == "file":
        return KnowledgeStore()

    if backend in ("auto", "pgvector") and settings.database_url and settings.embeddings_configured:
        try:
            index = PgVectorIndex(settings.database_url, dim=settings.embedding_dim)
            logger.info("Incident knowledge store: pgvector")
            return VectorKnowledgeStore(index)
        except Exception:
            logger.exception("pgvector backend unavailable")
            if backend == "pgvector":
                raise
            # auto: fall through.

    if backend in ("auto", "memory") and settings.embeddings_configured:
        mirror = settings.data_dir / "knowledge_vectors_mirror.jsonl"
        logger.info("Incident knowledge store: in-memory vector (mirror=%s)", mirror)
        return VectorKnowledgeStore(InMemoryVectorIndex(), mirror_path=mirror)

    if backend == "pgvector":
        raise RuntimeError(
            "knowledge_vector_backend=pgvector requires SRE_AGENT_DATABASE_URL "
            "and embedding configuration."
        )
    if backend == "memory":
        raise RuntimeError(
            "knowledge_vector_backend=memory requires embedding configuration."
        )

    logger.info("Incident knowledge store: keyword file backend")
    return KnowledgeStore()
