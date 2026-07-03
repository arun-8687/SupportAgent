"""
Operational maintenance: checkpoint retention.

LangGraph writes a checkpoint per superstep, and each one carries the
full incident state (raw alert payload, all evidence). Without retention
the checkpoint tables grow unbounded. Finished threads older than
SRE_AGENT_CHECKPOINT_RETENTION_DAYS are pruned; a thread that is still
paused for approval is protected by the pending-approvals registry
(sweep it first — the sweeper escalates and unregisters it).
"""
import logging

from sre_agent.config import get_settings
from sre_agent.stores import create_pending_approval_store

logger = logging.getLogger(__name__)

# Standard tables created by langgraph-checkpoint-postgres.
CHECKPOINT_TABLES = ("checkpoint_writes", "checkpoint_blobs", "checkpoints")


def prune_checkpoints(retention_days: int | None = None) -> int:
    """Delete checkpoint rows for threads older than the retention window.

    No-op (returns 0) when no Postgres checkpointer is configured.
    """
    settings = get_settings()
    if not settings.database_url:
        return 0
    retention_days = retention_days or settings.checkpoint_retention_days

    try:
        import psycopg
    except ImportError:
        logger.warning("psycopg not installed; skipping checkpoint pruning")
        return 0

    pending = {p.incident_id for p in create_pending_approval_store().all()}
    deleted = 0
    try:
        with psycopg.connect(settings.database_url) as conn:
            # Find stale thread_ids from the newest checkpoint per thread.
            rows = conn.execute(
                """
                SELECT thread_id, max((checkpoint->>'ts')::timestamptz) AS latest
                FROM checkpoints
                GROUP BY thread_id
                HAVING max((checkpoint->>'ts')::timestamptz)
                       < now() - make_interval(days => %s)
                """,
                (retention_days,),
            ).fetchall()
            stale = [r[0] for r in rows if r[0] not in pending]
            if not stale:
                return 0
            for table in CHECKPOINT_TABLES:
                result = conn.execute(
                    f"DELETE FROM {table} WHERE thread_id = ANY(%s)",  # noqa: S608
                    (stale,),
                )
                deleted += result.rowcount or 0
            conn.commit()
            logger.info(
                "Pruned checkpoints for %d stale threads (%d rows)",
                len(stale), deleted,
            )
    except Exception:
        logger.exception("Checkpoint pruning failed")
    return deleted
