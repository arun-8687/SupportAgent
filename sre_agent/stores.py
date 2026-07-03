"""
Operational state stores: alert deduplication and pending approvals.

Service Bus delivers at-least-once, so the same alert can arrive more
than once (lock expiry, host crash, retry). The AlertLedger makes intake
idempotent: the first delivery of an alert_id claims it and maps it to an
incident; every later delivery is recognized as a duplicate. It also
detects alert storms — a flapping monitor firing the same service+category
repeatedly gets suppressed after a threshold instead of spawning dozens
of LLM-powered investigations.

The PendingApprovalStore tracks investigations paused at the permission
gate so a sweeper can time them out (escalate) instead of letting them
hang forever.

Backends: Postgres (via psycopg, when SRE_AGENT_DATABASE_URL is set) for
multi-instance production; a file+lock fallback for local/dev.
"""
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from sre_agent.config import get_settings
from sre_agent.locking import file_lock

logger = logging.getLogger(__name__)


@dataclass
class ClaimResult:
    """Outcome of trying to claim an alert for processing."""
    status: str  # "new" | "duplicate" | "storm"
    incident_id: Optional[str] = None  # existing incident for duplicates


@dataclass
class PendingApproval:
    incident_id: str
    created_at: float  # unix timestamp


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

    def claim(self, alert_id: str, incident_id: str, storm_key: str) -> ClaimResult:
        with file_lock(self.path):
            entries = self._read()
            for entry in entries:
                if entry["alert_id"] == alert_id:
                    return ClaimResult("duplicate", incident_id=entry["incident_id"])

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
                }
            )
            # Bound the file: keep the newest ~5000 entries.
            self._write(entries[-5000:])
            if status == "storm":
                parent = next(
                    (e["incident_id"] for e in recent if e.get("status") == "new"), None
                )
                return ClaimResult("storm", incident_id=parent)
            return ClaimResult("new", incident_id=incident_id)

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
        settings = get_settings()
        self.storm_threshold = settings.storm_threshold
        self.storm_window = settings.storm_window_seconds
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sre_alert_ledger (
                    alert_id    TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    storm_key   TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.commit()

    def _connect(self):
        return self._psycopg.connect(self.database_url)

    def claim(self, alert_id: str, incident_id: str, storm_key: str) -> ClaimResult:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT incident_id FROM sre_alert_ledger WHERE alert_id = %s",
                (alert_id,),
            ).fetchone()
            if row:
                return ClaimResult("duplicate", incident_id=row[0])

            count = conn.execute(
                """
                SELECT count(*) FROM sre_alert_ledger
                WHERE storm_key = %s AND created_at > now() - make_interval(secs => %s)
                """,
                (storm_key, self.storm_window),
            ).fetchone()[0]
            status = "storm" if count >= self.storm_threshold else "new"

            # ON CONFLICT: another instance claimed it between our SELECT and
            # this INSERT — treat as duplicate.
            inserted = conn.execute(
                """
                INSERT INTO sre_alert_ledger (alert_id, incident_id, storm_key, status)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (alert_id) DO NOTHING
                RETURNING alert_id
                """,
                (alert_id, incident_id, storm_key, status),
            ).fetchone()
            conn.commit()
            if inserted is None:
                row = conn.execute(
                    "SELECT incident_id FROM sre_alert_ledger WHERE alert_id = %s",
                    (alert_id,),
                ).fetchone()
                return ClaimResult("duplicate", incident_id=row[0] if row else None)

            if status == "storm":
                parent = conn.execute(
                    """
                    SELECT incident_id FROM sre_alert_ledger
                    WHERE storm_key = %s AND status = 'new'
                    ORDER BY created_at ASC LIMIT 1
                    """,
                    (storm_key,),
                ).fetchone()
                return ClaimResult("storm", incident_id=parent[0] if parent else None)
            return ClaimResult("new", incident_id=incident_id)


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
    """Postgres-backed pending-approval registry."""

    def __init__(self, database_url: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self.database_url = database_url
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sre_pending_approvals (
                    incident_id TEXT PRIMARY KEY,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.commit()

    def _connect(self):
        return self._psycopg.connect(self.database_url)

    def add(self, incident_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sre_pending_approvals (incident_id) VALUES (%s) "
                "ON CONFLICT (incident_id) DO NOTHING",
                (incident_id,),
            )
            conn.commit()

    def remove(self, incident_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM sre_pending_approvals WHERE incident_id = %s",
                (incident_id,),
            )
            conn.commit()

    def expired(self, timeout_seconds: int) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT incident_id FROM sre_pending_approvals "
                "WHERE created_at < now() - make_interval(secs => %s)",
                (timeout_seconds,),
            ).fetchall()
            return [r[0] for r in rows]

    def all(self) -> List[PendingApproval]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT incident_id, extract(epoch from created_at) "
                "FROM sre_pending_approvals"
            ).fetchall()
            return [PendingApproval(r[0], float(r[1])) for r in rows]


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
