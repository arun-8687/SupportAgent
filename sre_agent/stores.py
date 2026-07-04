"""
Operational state stores: alert deduplication and pending approvals.

Service Bus delivers at-least-once, so the same alert can arrive more
than once (lock expiry, host crash, retry). The AlertLedger makes intake
idempotent AND crash-safe via a claim lifecycle:

    claim()           -> atomically registers the alert (storing its raw
                         payload) before any processing
    mark_processed()  -> called once the investigation reached a durable
                         state (finished, or paused at approval with a
                         checkpoint); the stored payload is dropped
    reclaim()         -> a redelivered alert whose original claim never
                         reached mark_processed was a crashed attempt:
                         re-point the claim at a fresh incident and
                         investigate again (never silently drop it)
    stalled()         -> claims that stayed unprocessed past a deadline
                         with no redelivery (message already completed);
                         a sweeper re-runs them from the stored payload

It also detects alert storms — a flapping monitor firing the same
service+category repeatedly gets suppressed after a threshold instead of
spawning dozens of LLM-powered investigations.

The PendingApprovalStore tracks investigations paused at the permission
gate so a sweeper can time them out (escalate) instead of letting them
hang forever.

Backends: Postgres (via psycopg, when SRE_AGENT_DATABASE_URL is set) for
multi-instance production — connections are created once and reused, not
per-operation; a file+lock fallback for local/dev.
"""
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sre_agent.config import get_settings
from sre_agent.locking import file_lock

logger = logging.getLogger(__name__)


@dataclass
class ClaimResult:
    """Outcome of trying to claim an alert for processing."""
    status: str  # "new" | "duplicate" | "storm"
    incident_id: Optional[str] = None  # existing incident for duplicates
    # For duplicates: did the original claim finish processing? False
    # means the earlier attempt crashed and the alert must be reclaimed.
    processed: bool = True


@dataclass
class PendingApproval:
    incident_id: str
    created_at: float  # unix timestamp


@dataclass
class StalledIntake:
    """An unprocessed claim past the staleness deadline."""
    alert_id: str
    incident_id: str
    payload: Optional[dict]


# --------------------------------------------------------------------------- #
# Alert ledger
# --------------------------------------------------------------------------- #

class FileAlertLedger:
    """File-backed ledger; safe for single-host / shared-NFS setups."""

    def __init__(self, path: Optional[Path] = None) -> None:
        settings = get_settings()
        self.path = path or settings.data_dir / "alert_ledger.jsonl"
        self.storm_threshold = settings.storm_threshold
        self.storm_window = settings.storm_window_seconds

    def claim(
        self,
        alert_id: str,
        incident_id: str,
        storm_key: str,
        payload: Optional[dict] = None,
    ) -> ClaimResult:
        with file_lock(self.path):
            entries = self._read()
            for entry in entries:
                if entry["alert_id"] == alert_id:
                    return ClaimResult(
                        "duplicate",
                        incident_id=entry["incident_id"],
                        processed=entry.get("processed", True),
                    )

            now = time.time()
            recent = [
                e for e in entries
                if e.get("storm_key") == storm_key and now - e["ts"] < self.storm_window
            ]
            status = "storm" if len(recent) >= self.storm_threshold else "new"

            entries.append(
                {
                    "alert_id": alert_id,
                    "incident_id": incident_id,
                    "storm_key": storm_key,
                    "ts": now,
                    "status": status,
                    # Storm-suppressed entries need no recovery.
                    "processed": status == "storm",
                    "payload": payload if status == "new" else None,
                }
            )
            # Bound the file: keep the newest ~5000 entries.
            self._write(entries[-5000:])
            if status == "storm":
                parent = next(
                    (e["incident_id"] for e in recent if e.get("status") == "new"), None
                )
                return ClaimResult("storm", incident_id=parent)
            return ClaimResult("new", incident_id=incident_id, processed=False)

    def mark_processed(self, alert_id: str) -> None:
        """The investigation reached a durable state; drop the payload."""
        with file_lock(self.path):
            entries = self._read()
            for entry in entries:
                if entry["alert_id"] == alert_id:
                    entry["processed"] = True
                    entry["payload"] = None
            self._write(entries)

    def reclaim(self, alert_id: str, new_incident_id: str) -> bool:
        """Re-point a crashed (unprocessed) claim at a fresh incident."""
        with file_lock(self.path):
            entries = self._read()
            for entry in entries:
                if entry["alert_id"] == alert_id and not entry.get("processed", True):
                    entry["incident_id"] = new_incident_id
                    self._write(entries)
                    return True
            return False

    def stalled(self, max_age_seconds: int) -> List[StalledIntake]:
        """Unprocessed claims older than the deadline, with stored payloads."""
        cutoff = time.time() - max_age_seconds
        return [
            StalledIntake(e["alert_id"], e["incident_id"], e.get("payload"))
            for e in self._read()
            if not e.get("processed", True) and e["ts"] < cutoff
        ]

    def _read(self) -> List[Dict]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def _write(self, entries: List[Dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8"
        )


class PostgresAlertLedger:
    """Postgres-backed ledger: atomic claims across many instances."""

    def __init__(self, database_url: str) -> None:
        import psycopg  # provided by langgraph-checkpoint-postgres extras

        self._psycopg = psycopg
        self.database_url = database_url
        self._conn = None
        settings = get_settings()
        self.storm_threshold = settings.storm_threshold
        self.storm_window = settings.storm_window_seconds
        conn = self._get_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sre_alert_ledger (
                alert_id    TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                storm_key   TEXT NOT NULL,
                status      TEXT NOT NULL,
                processed   BOOLEAN NOT NULL DEFAULT FALSE,
                payload     TEXT,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        # Upgrades for tables created by earlier versions.
        conn.execute(
            "ALTER TABLE sre_alert_ledger ADD COLUMN IF NOT EXISTS "
            "processed BOOLEAN NOT NULL DEFAULT TRUE"
        )
        conn.execute(
            "ALTER TABLE sre_alert_ledger ADD COLUMN IF NOT EXISTS payload TEXT"
        )
        conn.commit()

    def _get_conn(self):
        """One long-lived connection, reopened when broken — never a
        connect() handshake per operation."""
        if self._conn is None or self._conn.closed:
            self._conn = self._psycopg.connect(self.database_url)
        return self._conn

    def _run(self, fn):
        """Execute fn(conn) with a single reconnect retry on broken pipes."""
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

    def claim(
        self,
        alert_id: str,
        incident_id: str,
        storm_key: str,
        payload: Optional[dict] = None,
    ) -> ClaimResult:
        def op(conn) -> ClaimResult:
            row = conn.execute(
                "SELECT incident_id, processed FROM sre_alert_ledger WHERE alert_id = %s",
                (alert_id,),
            ).fetchone()
            if row:
                conn.commit()
                return ClaimResult("duplicate", incident_id=row[0], processed=row[1])

            count = conn.execute(
                """
                SELECT count(*) FROM sre_alert_ledger
                WHERE storm_key = %s AND created_at > now() - make_interval(secs => %s)
                """,
                (storm_key, self.storm_window),
            ).fetchone()[0]
            status = "storm" if count >= self.storm_threshold else "new"

            inserted = conn.execute(
                """
                INSERT INTO sre_alert_ledger
                    (alert_id, incident_id, storm_key, status, processed, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (alert_id) DO NOTHING
                RETURNING alert_id
                """,
                (
                    alert_id, incident_id, storm_key, status,
                    status == "storm",
                    json.dumps(payload) if payload and status == "new" else None,
                ),
            ).fetchone()
            if inserted is None:
                row = conn.execute(
                    "SELECT incident_id, processed FROM sre_alert_ledger WHERE alert_id = %s",
                    (alert_id,),
                ).fetchone()
                conn.commit()
                return ClaimResult(
                    "duplicate",
                    incident_id=row[0] if row else None,
                    processed=row[1] if row else True,
                )

            if status == "storm":
                # Parent must come from THIS storm's window — a stale key
                # from weeks ago must not be pointed at.
                parent = conn.execute(
                    """
                    SELECT incident_id FROM sre_alert_ledger
                    WHERE storm_key = %s AND status = 'new'
                      AND created_at > now() - make_interval(secs => %s)
                    ORDER BY created_at ASC LIMIT 1
                    """,
                    (storm_key, self.storm_window),
                ).fetchone()
                conn.commit()
                return ClaimResult("storm", incident_id=parent[0] if parent else None)
            conn.commit()
            return ClaimResult("new", incident_id=incident_id, processed=False)

        return self._run(op)

    def mark_processed(self, alert_id: str) -> None:
        def op(conn) -> None:
            conn.execute(
                "UPDATE sre_alert_ledger SET processed = TRUE, payload = NULL "
                "WHERE alert_id = %s",
                (alert_id,),
            )
            conn.commit()

        self._run(op)

    def reclaim(self, alert_id: str, new_incident_id: str) -> bool:
        def op(conn) -> bool:
            row = conn.execute(
                "UPDATE sre_alert_ledger SET incident_id = %s "
                "WHERE alert_id = %s AND processed = FALSE RETURNING alert_id",
                (new_incident_id, alert_id),
            ).fetchone()
            conn.commit()
            return row is not None

        return self._run(op)

    def stalled(self, max_age_seconds: int) -> List[StalledIntake]:
        def op(conn) -> List[StalledIntake]:
            rows = conn.execute(
                """
                SELECT alert_id, incident_id, payload FROM sre_alert_ledger
                WHERE processed = FALSE
                  AND created_at < now() - make_interval(secs => %s)
                """,
                (max_age_seconds,),
            ).fetchall()
            conn.commit()
            return [
                StalledIntake(r[0], r[1], json.loads(r[2]) if r[2] else None)
                for r in rows
            ]

        return self._run(op)


# --------------------------------------------------------------------------- #
# Pending approvals
# --------------------------------------------------------------------------- #

class FilePendingApprovalStore:
    """File-backed registry of investigations awaiting human approval."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or get_settings().data_dir / "pending_approvals.jsonl"

    def add(self, incident_id: str) -> None:
        with file_lock(self.path):
            pending = self._read()
            if all(p.incident_id != incident_id for p in pending):
                pending.append(PendingApproval(incident_id, time.time()))
            self._write(pending)

    def remove(self, incident_id: str) -> None:
        with file_lock(self.path):
            pending = [p for p in self._read() if p.incident_id != incident_id]
            self._write(pending)

    def expired(self, timeout_seconds: int) -> List[str]:
        cutoff = time.time() - timeout_seconds
        return [p.incident_id for p in self._read() if p.created_at < cutoff]

    def all(self) -> List[PendingApproval]:
        return self._read()

    def _read(self) -> List[PendingApproval]:
        if not self.path.exists():
            return []
        pending = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    pending.append(PendingApproval(data["incident_id"], data["created_at"]))
                except (json.JSONDecodeError, KeyError):
                    continue
        return pending

    def _write(self, pending: List[PendingApproval]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            "".join(
                json.dumps({"incident_id": p.incident_id, "created_at": p.created_at}) + "\n"
                for p in pending
            ),
            encoding="utf-8",
        )


class PostgresPendingApprovalStore:
    """Postgres-backed pending-approval registry (persistent connection)."""

    def __init__(self, database_url: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self.database_url = database_url
        self._conn = None
        conn = self._get_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sre_pending_approvals (
                incident_id TEXT PRIMARY KEY,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
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

    def add(self, incident_id: str) -> None:
        def op(conn) -> None:
            conn.execute(
                "INSERT INTO sre_pending_approvals (incident_id) VALUES (%s) "
                "ON CONFLICT (incident_id) DO NOTHING",
                (incident_id,),
            )
            conn.commit()

        self._run(op)

    def remove(self, incident_id: str) -> None:
        def op(conn) -> None:
            conn.execute(
                "DELETE FROM sre_pending_approvals WHERE incident_id = %s",
                (incident_id,),
            )
            conn.commit()

        self._run(op)

    def expired(self, timeout_seconds: int) -> List[str]:
        def op(conn) -> List[str]:
            rows = conn.execute(
                "SELECT incident_id FROM sre_pending_approvals "
                "WHERE created_at < now() - make_interval(secs => %s)",
                (timeout_seconds,),
            ).fetchall()
            conn.commit()
            return [r[0] for r in rows]

        return self._run(op)

    def all(self) -> List[PendingApproval]:
        def op(conn) -> List[PendingApproval]:
            rows = conn.execute(
                "SELECT incident_id, extract(epoch from created_at) "
                "FROM sre_pending_approvals"
            ).fetchall()
            conn.commit()
            return [PendingApproval(r[0], float(r[1])) for r in rows]

        return self._run(op)


# --------------------------------------------------------------------------- #
# Factories
# --------------------------------------------------------------------------- #

def create_alert_ledger():
    settings = get_settings()
    if settings.database_url:
        try:
            return PostgresAlertLedger(settings.database_url)
        except Exception:
            if settings.is_production:
                raise
            logger.exception("Postgres alert ledger unavailable; using file backend")
    return FileAlertLedger()


def create_pending_approval_store():
    settings = get_settings()
    if settings.database_url:
        try:
            return PostgresPendingApprovalStore(settings.database_url)
        except Exception:
            if settings.is_production:
                raise
            logger.exception("Postgres approval store unavailable; using file backend")
    return FilePendingApprovalStore()
