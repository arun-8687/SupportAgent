"""
Vector index backends behind the incident knowledge store.

`VectorIndex` is the small interface the store depends on. Two
implementations:

  InMemoryVectorIndex  -> pure-Python cosine; no external deps. For dev /
                          single-instance / tests. Not durable on its own
                          (the store persists records separately when it
                          needs durability).
  PgVectorIndex        -> Postgres + pgvector, cosine distance (<=>), one
                          long-lived connection with reconnect-once. The
                          production backend: durable, scales past the
                          O(n) keyword scan that the file store degrades to.

Both store an opaque `payload` dict alongside each vector so the caller
reconstructs its domain object (a KnowledgeRecord) from a query hit
without a second lookup.
"""
import json
import logging
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VectorHit:
    id: str
    score: float  # cosine similarity in [0, 1]
    payload: Dict[str, Any]


def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    # Clamp to guard against float drift outside [-1, 1].
    return max(-1.0, min(1.0, dot / (na * nb)))


class VectorIndex(ABC):
    @abstractmethod
    def add(self, id: str, vector: List[float], payload: Dict[str, Any]) -> None:
        ...

    @abstractmethod
    def query(
        self, vector: List[float], top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        ...

    @abstractmethod
    def all_payloads(self) -> List[Dict[str, Any]]:
        ...


class InMemoryVectorIndex(VectorIndex):
    """Pure-Python cosine index. Deterministic and dependency-free."""

    def __init__(self) -> None:
        self._items: List[Tuple[str, List[float], Dict[str, Any]]] = []

    def add(self, id: str, vector: List[float], payload: Dict[str, Any]) -> None:
        self._items.append((id, list(vector), dict(payload)))

    def query(
        self, vector: List[float], top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        scored = []
        for id, vec, payload in self._items:
            score = cosine_similarity(vector, vec)
            # Same-service boost, matching the keyword store's behavior.
            if service_name and payload.get("service_name") == service_name:
                score = min(1.0, score + 0.1)
            scored.append(VectorHit(id=id, score=score, payload=payload))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:top_k]

    def all_payloads(self) -> List[Dict[str, Any]]:
        return [payload for _, _, payload in self._items]


class PgVectorIndex(VectorIndex):
    """Postgres + pgvector cosine index (production backend)."""

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
                payload      JSONB NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        # IVFFlat cosine index for approximate NN at scale; harmless small-N.
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS {self.table}_embedding_idx "
            f"ON {self.table} USING ivfflat (embedding vector_cosine_ops) "
            f"WITH (lists = 100)"
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

    def add(self, id: str, vector: List[float], payload: Dict[str, Any]) -> None:
        def op(conn):
            conn.execute(
                f"INSERT INTO {self.table} (id, service_name, embedding, payload) "
                f"VALUES (%s, %s, %s, %s) "
                f"ON CONFLICT (id) DO UPDATE SET embedding = EXCLUDED.embedding, "
                f"payload = EXCLUDED.payload",
                (id, payload.get("service_name"), vector, json.dumps(payload)),
            )
            conn.commit()

        self._run(op)

    def query(
        self, vector: List[float], top_k: int, service_name: Optional[str] = None
    ) -> List[VectorHit]:
        def op(conn):
            # 1 - cosine_distance = cosine_similarity. Same-service boost is
            # applied in the ORDER BY so it ranks like the keyword store.
            rows = conn.execute(
                f"""
                SELECT id, payload,
                       1 - (embedding <=> %s::vector) AS similarity,
                       (service_name = %s) AS same_service
                FROM {self.table}
                ORDER BY (1 - (embedding <=> %s::vector))
                         + (CASE WHEN service_name = %s THEN 0.1 ELSE 0 END) DESC
                LIMIT %s
                """,
                (vector, service_name, vector, service_name, top_k),
            ).fetchall()
            conn.commit()
            hits = []
            for id, payload, similarity, same_service in rows:
                score = float(similarity or 0.0)
                if same_service:
                    score = min(1.0, score + 0.1)
                data = payload if isinstance(payload, dict) else json.loads(payload)
                hits.append(VectorHit(id=id, score=score, payload=data))
            return hits

        return self._run(op)

    def all_payloads(self) -> List[Dict[str, Any]]:
        def op(conn):
            rows = conn.execute(f"SELECT payload FROM {self.table}").fetchall()
            conn.commit()
            return [r[0] if isinstance(r[0], dict) else json.loads(r[0]) for r in rows]

        return self._run(op)
