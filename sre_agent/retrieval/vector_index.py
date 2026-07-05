"""
Vector index backends behind the incident knowledge store.

`VectorIndex` is the small interface the store depends on. Each backend
supports two retrieval arms so the store can do hybrid search:

  query()          -> semantic (embedding cosine)
  keyword_query()  -> exact/lexical (token overlap in memory; Postgres
                      full-text `simple` config in pgvector, which keeps
                      identifiers like error codes and job names intact —
                      no stemming, so "S0C7" stays "S0C7")

Two implementations:

  InMemoryVectorIndex  -> pure-Python; no external deps. Dev / single
                          instance / tests.
  PgVectorIndex        -> Postgres + pgvector. HNSW cosine index for the
                          semantic arm (builds incrementally — no IVFFlat
                          train-on-empty problem) + a GIN full-text index
                          for the keyword arm. One long-lived connection
                          with reconnect-once.

Both store an opaque `payload` dict and the searchable `text` alongside
each vector so the caller reconstructs its domain object from a hit
without a second lookup.
"""
import json
import logging
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from sre_agent.textsearch import jaccard, tokens

logger = logging.getLogger(__name__)


@dataclass
class VectorHit:
    id: str
    score: float  # relevance in [0, 1] for the arm that produced it
    payload: Dict[str, Any]


def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return max(-1.0, min(1.0, dot / (na * nb)))


class VectorIndex(ABC):
    @abstractmethod
    def add(
        self, id: str, vector: Optional[List[float]], payload: Dict[str, Any], text: str = ""
    ) -> None:
        """Index a record. `vector` may be None for keyword-only records
        (embedding unavailable at save time)."""
        ...

    @abstractmethod
    def query(
        self, vector: List[float], top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        ...

    @abstractmethod
    def keyword_query(
        self, query_text: str, top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        ...

    @abstractmethod
    def all_payloads(self) -> List[Dict[str, Any]]:
        ...


class InMemoryVectorIndex(VectorIndex):
    """Pure-Python cosine + token-overlap index. Deterministic, dep-free."""

    def __init__(self) -> None:
        # id -> (vector, payload, text_tokens)
        self._items: List[Tuple[str, List[float], Dict[str, Any], Set[str]]] = []

    def add(
        self, id: str, vector: Optional[List[float]], payload: Dict[str, Any], text: str = ""
    ) -> None:
        self._items.append((id, list(vector) if vector else [], dict(payload), tokens(text)))

    def query(
        self, vector: List[float], top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        scored = []
        for id, vec, payload, _ in self._items:
            score = cosine_similarity(vector, vec)
            if service_name and payload.get("service_name") == service_name:
                score = min(1.0, score + 0.1)
            scored.append(VectorHit(id=id, score=score, payload=payload))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:top_k]

    def keyword_query(
        self, query_text: str, top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        query_tokens = tokens(query_text)
        if not query_tokens:
            return []
        scored = []
        for id, _, payload, doc_tokens in self._items:
            score = jaccard(query_tokens, doc_tokens)
            if service_name and payload.get("service_name") == service_name:
                score = min(1.0, score + 0.1)
            if score > 0:
                scored.append(VectorHit(id=id, score=score, payload=payload))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:top_k]

    def all_payloads(self) -> List[Dict[str, Any]]:
        return [payload for _, _, payload, _ in self._items]


class PgVectorIndex(VectorIndex):
    """Postgres + pgvector: HNSW semantic arm + full-text keyword arm."""

    def __init__(self, database_url: str, dim: int, table: str = "sre_knowledge_vectors") -> None:
        import psycopg  # lazy: only needed for the production backend
        from pgvector.psycopg import register_vector

        self._psycopg = psycopg
        self._register_vector = register_vector
        self.database_url = database_url
        self.dim = dim
        self.table = table
        self._conn = None
        conn = self._get_conn()
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table} (
                id           TEXT PRIMARY KEY,
                service_name TEXT,
                embedding    vector({self.dim}),
                search_text  TEXT,
                payload      JSONB NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        # Semantic arm: HNSW cosine (pgvector >= 0.5). Builds incrementally,
        # so — unlike IVFFlat — it needs no data present at creation time.
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS {self.table}_embedding_hnsw "
            f"ON {self.table} USING hnsw (embedding vector_cosine_ops)"
        )
        # Keyword arm: GIN full-text over 'simple' (no stemming -> exact
        # identifiers survive).
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS {self.table}_search_fts "
            f"ON {self.table} USING gin (to_tsvector('simple', coalesce(search_text, '')))"
        )
        conn.commit()

    def _get_conn(self):
        if self._conn is None or self._conn.closed:
            self._conn = self._psycopg.connect(self.database_url)
            self._register_vector(self._conn)
        return self._conn

    def _run(self, fn):
        try:
            return fn(self._get_conn())
        except self._psycopg.OperationalError:
            logger.warning("pgvector connection lost; reconnecting once")
            try:
                if self._conn is not None:
                    self._conn.close()
            except Exception:
                pass
            self._conn = None
            return fn(self._get_conn())

    def add(
        self, id: str, vector: Optional[List[float]], payload: Dict[str, Any], text: str = ""
    ) -> None:
        def op(conn):
            conn.execute(
                f"INSERT INTO {self.table} (id, service_name, embedding, search_text, payload) "
                f"VALUES (%s, %s, %s, %s, %s) "
                f"ON CONFLICT (id) DO UPDATE SET embedding = EXCLUDED.embedding, "
                f"search_text = EXCLUDED.search_text, payload = EXCLUDED.payload",
                # None -> NULL embedding: the record stays keyword-searchable.
                (id, payload.get("service_name"), vector if vector else None, text, json.dumps(payload)),
            )
            conn.commit()

        self._run(op)

    def query(
        self, vector: List[float], top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        def op(conn):
            rows = conn.execute(
                f"""
                SELECT id, payload,
                       1 - (embedding <=> %s::vector) AS similarity,
                       (service_name = %s) AS same_service
                FROM {self.table}
                WHERE embedding IS NOT NULL
                ORDER BY (1 - (embedding <=> %s::vector))
                         + (CASE WHEN service_name = %s THEN 0.1 ELSE 0 END) DESC
                LIMIT %s
                """,
                (vector, service_name, vector, service_name, top_k),
            ).fetchall()
            conn.commit()
            return [self._hit(r[0], r[1], float(r[2] or 0.0), r[3]) for r in rows]

        return self._run(op)

    def keyword_query(
        self, query_text: str, top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        def op(conn):
            rows = conn.execute(
                f"""
                SELECT id, payload,
                       ts_rank(to_tsvector('simple', coalesce(search_text, '')),
                               plainto_tsquery('simple', %s)) AS rank,
                       (service_name = %s) AS same_service
                FROM {self.table}
                WHERE to_tsvector('simple', coalesce(search_text, ''))
                      @@ plainto_tsquery('simple', %s)
                ORDER BY rank
                         + (CASE WHEN service_name = %s THEN 0.1 ELSE 0 END) DESC
                LIMIT %s
                """,
                (query_text, service_name, query_text, service_name, top_k),
            ).fetchall()
            conn.commit()
            # ts_rank is unbounded-ish; clamp for the [0,1] score contract.
            return [self._hit(r[0], r[1], min(1.0, float(r[2] or 0.0)), r[3]) for r in rows]

        return self._run(op)

    @staticmethod
    def _hit(id, payload, similarity, same_service) -> VectorHit:
        score = similarity
        if same_service:
            score = min(1.0, score + 0.1)
        data = payload if isinstance(payload, dict) else json.loads(payload)
        return VectorHit(id=id, score=score, payload=data)

    def all_payloads(self) -> List[Dict[str, Any]]:
        def op(conn):
            rows = conn.execute(f"SELECT payload FROM {self.table}").fetchall()
            conn.commit()
            return [r[0] if isinstance(r[0], dict) else json.loads(r[0]) for r in rows]

        return self._run(op)
