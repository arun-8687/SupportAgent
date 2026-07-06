"""
Incident index — a queryable list of all incidents for the monitoring UI.

The LangGraph checkpointer is keyed only by `thread_id = incident_id`, so
there is no way to *list* incidents (only look one up by id). This store
maintains one row per incident, upserted by the service at its existing
chokepoints (mirroring how it already writes the pending-approval store),
and exposes filtered/sorted/paginated reads for the API.

Two backends, selected by `create_incident_index()`:
  - FileIncidentIndexStore  — JSONL keyed by incident_id (dev / tests /
    single-host over a shared mount). Writes are sync; the async read
    methods wrap the sync reads so API code can `await` uniformly offline.
  - PostgresIncidentIndexStore — durable, indexed, cross-process. Sync
    `upsert` (worker) via a long-lived connection with reconnect-once;
    async `alist`/`aget` (API) over an AsyncConnectionPool.

Writes are sync because the worker (async graph) already calls the stores
synchronously, exactly like `pending_approvals`. Reads are async because
the API serves them concurrently over a pool.
"""
import json
import logging
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sre_agent.config import get_settings
from sre_agent.locking import file_lock

logger = logging.getLogger(__name__)

# Columns a UI lists/filters on. Kept flat and small so the list query is
# cheap and indexable — the full investigation is fetched per-incident from
# the checkpointer, not from here.
INDEX_FIELDS = (
    "incident_id", "app_code", "service_name", "severity", "environment",
    "title", "status", "awaiting_approval", "ticket_id", "resolution_summary",
    "created_at", "updated_at",
)

_SORTABLE = {"created_at", "updated_at", "severity", "status", "app_code", "service_name"}


@dataclass
class IncidentIndexRow:
    incident_id: str
    app_code: str = "UNMAPPED"
    service_name: str = "unknown"
    severity: str = "sev3"
    environment: str = "prod"
    title: str = ""
    status: str = "received"
    awaiting_approval: bool = False
    ticket_id: Optional[str] = None
    resolution_summary: Optional[str] = None
    created_at: float = 0.0  # unix seconds
    updated_at: float = 0.0

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "IncidentIndexRow":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def _apply_filters_sort_page(
    rows: List[IncidentIndexRow],
    status: Optional[str],
    app_code: Optional[str],
    severity: Optional[str],
    service_name: Optional[str],
    awaiting_approval: Optional[bool],
    sort: str,
    descending: bool,
    limit: int,
    offset: int,
) -> Tuple[List[IncidentIndexRow], int]:
    """Shared in-memory filter/sort/paginate (file backend + tests)."""
    def keep(r: IncidentIndexRow) -> bool:
        if status and r.status != status:
            return False
        if app_code and r.app_code != app_code:
            return False
        if severity and r.severity != severity:
            return False
        if service_name and r.service_name != service_name:
            return False
        if awaiting_approval is not None and r.awaiting_approval != awaiting_approval:
            return False
        return True

    filtered = [r for r in rows if keep(r)]
    total = len(filtered)
    key = sort if sort in _SORTABLE else "updated_at"
    filtered.sort(key=lambda r: getattr(r, key), reverse=descending)
    return filtered[offset:offset + limit], total


class FileIncidentIndexStore:
    """JSONL-backed incident index (dev / tests / shared-mount)."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or get_settings().data_dir / "incident_index.jsonl"

    def upsert(self, incident_id: str, **fields_: Any) -> None:
        now = time.time()
        with file_lock(self.path):
            rows = {r.incident_id: r for r in self._read()}
            row = rows.get(incident_id) or IncidentIndexRow(
                incident_id=incident_id, created_at=now
            )
            for key, value in fields_.items():
                if key in INDEX_FIELDS and key != "incident_id" and value is not None:
                    setattr(row, key, value)
            if not row.created_at:
                row.created_at = now
            row.updated_at = now
            rows[incident_id] = row
            self._write(list(rows.values()))

    def get(self, incident_id: str) -> Optional[IncidentIndexRow]:
        return next((r for r in self._read() if r.incident_id == incident_id), None)

    def list(
        self,
        status: Optional[str] = None,
        app_code: Optional[str] = None,
        severity: Optional[str] = None,
        service_name: Optional[str] = None,
        awaiting_approval: Optional[bool] = None,
        sort: str = "updated_at",
        descending: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[IncidentIndexRow], int]:
        return _apply_filters_sort_page(
            self._read(), status, app_code, severity, service_name,
            awaiting_approval, sort, descending, limit, offset,
        )

    # Async read surface (API awaits uniformly; file reads are fast).
    async def alist(self, **kwargs) -> Tuple[List[IncidentIndexRow], int]:
        return self.list(**kwargs)

    async def aget(self, incident_id: str) -> Optional[IncidentIndexRow]:
        return self.get(incident_id)

    def _read(self) -> List[IncidentIndexRow]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(IncidentIndexRow.from_json(json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue
        return rows

    def _write(self, rows: List[IncidentIndexRow]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            "".join(json.dumps(r.to_json()) + "\n" for r in rows), encoding="utf-8"
        )


class PostgresIncidentIndexStore:
    """Durable, indexed incident index.

    Sync writes via a long-lived connection (worker); async reads via an
    AsyncConnectionPool (API). The API passes its shared pool; when none is
    given the store lazily opens its own on first async read.
    """

    def __init__(self, database_url: str, pool: Optional[Any] = None) -> None:
        import psycopg

        self._psycopg = psycopg
        self.database_url = database_url
        self._conn = None
        self._pool = pool
        conn = self._get_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sre_incident_index (
                incident_id        TEXT PRIMARY KEY,
                app_code           TEXT,
                service_name       TEXT,
                severity           TEXT,
                environment        TEXT,
                title              TEXT,
                status             TEXT,
                awaiting_approval  BOOLEAN NOT NULL DEFAULT FALSE,
                ticket_id          TEXT,
                resolution_summary TEXT,
                created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        for col in ("status", "app_code", "updated_at", "severity"):
            conn.execute(
                f"CREATE INDEX IF NOT EXISTS sre_incident_index_{col} "
                f"ON sre_incident_index ({col})"
            )
        conn.commit()

    # -- sync write path (worker) --------------------------------------- #

    def _get_conn(self):
        if self._conn is None or self._conn.closed:
            self._conn = self._psycopg.connect(self.database_url)
        return self._conn

    def _run(self, fn):
        try:
            return fn(self._get_conn())
        except self._psycopg.OperationalError:
            logger.warning("Postgres connection lost; reconnecting once")
            try:
                if self._conn is not None:
                    self._conn.close()
            except Exception:
                pass
            self._conn = None
            return fn(self._get_conn())

    def upsert(self, incident_id: str, **fields_: Any) -> None:
        cols = {k: v for k, v in fields_.items()
                if k in INDEX_FIELDS and k != "incident_id" and v is not None}

        def op(conn) -> None:
            set_cols = list(cols.keys()) + ["updated_at"]
            insert_cols = ["incident_id"] + set_cols
            placeholders = ", ".join(["%s"] * len(insert_cols))
            updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in set_cols)
            values = [incident_id] + [cols[c] for c in cols] + ["now()"]
            # 'now()' can't be a bound param; build it inline for updated_at.
            insert_cols_sql = ", ".join(insert_cols)
            vals_sql = ", ".join(
                "now()" if c == "updated_at" else "%s" for c in insert_cols
            )
            bound = [incident_id] + [cols[c] for c in cols]
            conn.execute(
                f"INSERT INTO sre_incident_index ({insert_cols_sql}) "
                f"VALUES ({vals_sql}) "
                f"ON CONFLICT (incident_id) DO UPDATE SET {updates}",
                bound,
            )
            conn.commit()

        self._run(op)

    # -- async read path (API) ------------------------------------------ #

    async def _get_pool(self):
        if self._pool is None:
            from psycopg_pool import AsyncConnectionPool

            self._pool = AsyncConnectionPool(self.database_url, open=False)
            await self._pool.open()
        return self._pool

    async def alist(
        self,
        status: Optional[str] = None,
        app_code: Optional[str] = None,
        severity: Optional[str] = None,
        service_name: Optional[str] = None,
        awaiting_approval: Optional[bool] = None,
        sort: str = "updated_at",
        descending: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[IncidentIndexRow], int]:
        where, params = [], []
        for col, val in (
            ("status", status), ("app_code", app_code), ("severity", severity),
            ("service_name", service_name), ("awaiting_approval", awaiting_approval),
        ):
            if val is not None:
                where.append(f"{col} = %s")
                params.append(val)
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        order_col = sort if sort in _SORTABLE else "updated_at"
        direction = "DESC" if descending else "ASC"

        pool = await self._get_pool()
        async with pool.connection() as conn:
            total = (await (await conn.execute(
                f"SELECT count(*) FROM sre_incident_index {where_sql}", params
            )).fetchone())[0]
            rows = await (await conn.execute(
                f"SELECT {', '.join(INDEX_FIELDS)} FROM sre_incident_index "
                f"{where_sql} ORDER BY {order_col} {direction} LIMIT %s OFFSET %s",
                params + [limit, offset],
            )).fetchall()
        return [self._row(r) for r in rows], total

    async def aget(self, incident_id: str) -> Optional[IncidentIndexRow]:
        pool = await self._get_pool()
        async with pool.connection() as conn:
            row = await (await conn.execute(
                f"SELECT {', '.join(INDEX_FIELDS)} FROM sre_incident_index "
                f"WHERE incident_id = %s",
                (incident_id,),
            )).fetchone()
        return self._row(row) if row else None

    @staticmethod
    def _row(record) -> IncidentIndexRow:
        data = dict(zip(INDEX_FIELDS, record))
        for key in ("created_at", "updated_at"):
            val = data.get(key)
            if hasattr(val, "timestamp"):
                data[key] = val.timestamp()
        return IncidentIndexRow.from_json(data)


def create_incident_index(pool: Optional[Any] = None):
    """Postgres when database_url is set, else the file backend.

    `pool` (an AsyncConnectionPool) is passed by the API for shared async
    reads; the worker passes nothing (sync writes only).
    """
    settings = get_settings()
    if settings.database_url:
        try:
            return PostgresIncidentIndexStore(settings.database_url, pool=pool)
        except Exception:
            if settings.is_production:
                raise
            logger.exception("Postgres incident index unavailable; using file backend")
    return FileIncidentIndexStore()
