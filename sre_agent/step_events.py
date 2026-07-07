"""
Step-event store — durable per-incident run timeline for the monitoring UI.

`observability.log_step` is fire-and-forget (App Insights or stdlib logs);
there is no local, queryable timeline a UI can render or stream. This store
persists step events so the API can show an incident's timeline and stream
it live over SSE.

Two backends (factory `create_step_event_store`):
  - FileStepEventStore  — append-only JSONL with a monotonic `seq` (dev /
    tests). Sync append; async reads wrap sync.
  - PostgresStepEventStore — a TIME-PARTITIONED table (`sre_step_events`,
    monthly range partitions on `ts`) so retention is a partition drop, not
    a mass delete — essential at 40k jobs/day where events dominate volume.

Writes never happen on the workflow hot path: `log_step`'s sink only
enqueues, and `step_writer.StepEventWriter` drains the queue in batches and
calls `append_many` here. See step_writer.py.
"""
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sre_agent.config import get_settings
from sre_agent.locking import file_lock

logger = logging.getLogger(__name__)

EVENT_FIELDS = ("seq", "incident_id", "step", "status", "duration_ms", "fields", "ts")


@dataclass
class StepEvent:
    incident_id: str
    step: str
    status: str
    ts: float  # unix seconds
    seq: int = 0  # assigned by the store on append
    duration_ms: Optional[int] = None
    fields: Dict[str, Any] = None  # arbitrary extra dimensions

    def __post_init__(self):
        if self.fields is None:
            self.fields = {}

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "StepEvent":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def event_from_record(record: Dict[str, Any]) -> StepEvent:
    """Build a StepEvent from the dict observability emits to sinks."""
    return StepEvent(
        incident_id=record.get("incident_id") or "",
        step=record.get("step", ""),
        status=record.get("status", ""),
        ts=record.get("ts") or time.time(),
        duration_ms=record.get("duration_ms"),
        fields=record.get("fields") or {},
    )


class FileStepEventStore:
    """Append-only JSONL step-event store (dev / tests)."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or get_settings().data_dir / "step_events.jsonl"
        self._seq_lock = threading.Lock()

    def append_many(self, events: List[StepEvent]) -> int:
        if not events:
            return 0
        with file_lock(self.path):
            next_seq = self._max_seq() + 1
            for i, ev in enumerate(events):
                ev.seq = next_seq + i
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                for ev in events:
                    fh.write(json.dumps(ev.to_json()) + "\n")
            return events[-1].seq

    def append(self, event: StepEvent) -> int:
        return self.append_many([event])

    def by_incident(self, incident_id: str) -> List[StepEvent]:
        return [e for e in self._read() if e.incident_id == incident_id]

    def tail(
        self, after_seq: int = 0, incident_id: Optional[str] = None, limit: int = 200
    ) -> List[StepEvent]:
        out = [
            e for e in self._read()
            if e.seq > after_seq and (incident_id is None or e.incident_id == incident_id)
        ]
        out.sort(key=lambda e: e.seq)
        return out[:limit]

    # Async wrappers for uniform API awaits (file reads are fast).
    async def aby_incident(self, incident_id: str) -> List[StepEvent]:
        return self.by_incident(incident_id)

    async def atail(self, **kwargs) -> List[StepEvent]:
        return self.tail(**kwargs)

    def _max_seq(self) -> int:
        return max((e.seq for e in self._read()), default=0)

    def _read(self) -> List[StepEvent]:
        if not self.path.exists():
            return []
        events = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(StepEvent.from_json(json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue
        return events


class PostgresStepEventStore:
    """Time-partitioned durable step-event store."""

    def __init__(self, database_url: str, pool: Optional[Any] = None) -> None:
        import psycopg

        self._psycopg = psycopg
        self.database_url = database_url
        self._conn = None
        self._pool = pool
        conn = self._get_conn()
        # `seq` is a monotonic id for the SSE tail; on a partitioned parent
        # it must be part of the primary key alongside the partition key.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sre_step_events (
                seq         BIGINT GENERATED ALWAYS AS IDENTITY,
                incident_id TEXT NOT NULL,
                step        TEXT NOT NULL,
                status      TEXT NOT NULL,
                duration_ms INTEGER,
                fields      JSONB NOT NULL DEFAULT '{}'::jsonb,
                ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (seq, ts)
            ) PARTITION BY RANGE (ts)
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS sre_step_events_incident "
            "ON sre_step_events (incident_id, seq)"
        )
        conn.commit()
        self._ensure_partition(conn, datetime.now(timezone.utc))

    def _ensure_partition(self, conn, when: datetime) -> None:
        """Create the monthly partition covering `when` if missing."""
        start = when.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month = start.month % 12 + 1
        year = start.year + (1 if start.month == 12 else 0)
        end = start.replace(year=year, month=month)
        name = f"sre_step_events_{start:%Y%m}"
        # Partition bounds in a CREATE TABLE ... FOR VALUES clause are DDL and
        # CANNOT be bound parameters — inline them as timestamptz literals.
        # start/end are internally derived (first-of-month), so no injection.
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF sre_step_events "
            f"FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}')"
        )
        conn.commit()

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

    def append_many(self, events: List[StepEvent]) -> int:
        if not events:
            return 0

        def op(conn) -> int:
            self._ensure_partition(conn, datetime.now(timezone.utc))
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO sre_step_events (incident_id, step, status, duration_ms, fields, ts) "
                    "VALUES (%s, %s, %s, %s, %s, to_timestamp(%s))",
                    [
                        (e.incident_id, e.step, e.status, e.duration_ms,
                         json.dumps(e.fields), e.ts)
                        for e in events
                    ],
                )
                seq = conn.execute("SELECT max(seq) FROM sre_step_events").fetchone()[0]
            conn.commit()
            return seq or 0

        return self._run(op)

    def append(self, event: StepEvent) -> int:
        return self.append_many([event])

    async def _get_pool(self):
        if self._pool is None:
            from psycopg_pool import AsyncConnectionPool

            self._pool = AsyncConnectionPool(self.database_url, open=False)
            await self._pool.open()
        return self._pool

    async def aby_incident(self, incident_id: str) -> List[StepEvent]:
        pool = await self._get_pool()
        async with pool.connection() as conn:
            rows = await (await conn.execute(
                "SELECT seq, incident_id, step, status, duration_ms, fields, "
                "extract(epoch from ts) FROM sre_step_events "
                "WHERE incident_id = %s ORDER BY seq",
                (incident_id,),
            )).fetchall()
        return [self._row(r) for r in rows]

    async def atail(
        self, after_seq: int = 0, incident_id: Optional[str] = None, limit: int = 200
    ) -> List[StepEvent]:
        where = ["seq > %s"]
        params: List[Any] = [after_seq]
        if incident_id is not None:
            where.append("incident_id = %s")
            params.append(incident_id)
        pool = await self._get_pool()
        async with pool.connection() as conn:
            rows = await (await conn.execute(
                "SELECT seq, incident_id, step, status, duration_ms, fields, "
                "extract(epoch from ts) FROM sre_step_events "
                f"WHERE {' AND '.join(where)} ORDER BY seq LIMIT %s",
                params + [limit],
            )).fetchall()
        return [self._row(r) for r in rows]

    def drop_partitions_older_than(self, days: int) -> int:
        """Retention: drop monthly partitions entirely older than `days`."""
        cutoff = datetime.now(timezone.utc).replace(day=1) - _months(days)

        def op(conn) -> int:
            rows = conn.execute(
                "SELECT inhrelid::regclass::text FROM pg_inherits "
                "WHERE inhparent = 'sre_step_events'::regclass"
            ).fetchall()
            dropped = 0
            for (name,) in rows:
                # partition name suffix is YYYYMM
                suffix = name.split("_")[-1]
                try:
                    part_month = datetime(int(suffix[:4]), int(suffix[4:6]), 1, tzinfo=timezone.utc)
                except ValueError:
                    continue
                if part_month < cutoff:
                    conn.execute(f"DROP TABLE IF EXISTS {name}")
                    dropped += 1
            conn.commit()
            return dropped

        return self._run(op)

    @staticmethod
    def _row(record) -> StepEvent:
        seq, incident_id, step, status, duration_ms, flds, ts = record
        return StepEvent(
            seq=seq, incident_id=incident_id, step=step, status=status,
            duration_ms=duration_ms,
            fields=flds if isinstance(flds, dict) else json.loads(flds or "{}"),
            ts=float(ts),
        )


def _months(days: int):
    from datetime import timedelta
    return timedelta(days=days)


def create_step_event_store(pool: Optional[Any] = None):
    settings = get_settings()
    if settings.database_url:
        try:
            return PostgresStepEventStore(settings.database_url, pool=pool)
        except Exception:
            if settings.is_production:
                raise
            logger.exception("Postgres step-event store unavailable; using file backend")
    return FileStepEventStore()
