"""
FastAPI application: monitoring reads + the approve/reject action.

Assembled by `create_app()` so it runs two ways with the same routes:
  - production: a lifespan opens the async Postgres pool, builds the
    Postgres-backed stores and the `SREAgentService`, and closes them on
    shutdown; the SPA build is mounted at `/`.
  - tests: file-backed stores and a conftest `SREAgentService` are injected,
    so the whole surface runs offline with no database.

All reads require `SRE.Viewer`; the single write (`POST .../approval`)
requires `SRE.Approver` and is per-identity rate limited. The incident detail
redacts the raw alert payload (serializers.serialize_state).
"""
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.webapi import serializers
from sre_agent.webapi.auth import (
    APPROVER_ROLE,
    VIEWER_ROLE,
    Principal,
    require_approver,
    require_viewer,
)
from sre_agent.webapi.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from sre_agent.webapi.sse import step_event_stream

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #

class ApprovalDecision(BaseModel):
    approved: bool
    reason: str = Field(default="", max_length=2000)


# --------------------------------------------------------------------------- #
# Per-identity rate limiter (approvals)
# --------------------------------------------------------------------------- #

class _RateLimiter:
    """Fixed-window per-key limiter (in-process, per instance)."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


# --------------------------------------------------------------------------- #
# Dependency accessors (read off app.state)
# --------------------------------------------------------------------------- #

def get_service(request: Request):
    return request.app.state.service


def get_incident_index(request: Request):
    return request.app.state.incident_index


def get_step_events(request: Request):
    return request.app.state.step_events


# --------------------------------------------------------------------------- #
# Lifespan
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    injected: Dict[str, Any] = app.state.injected
    pool = None

    # Open a shared async pool for the read stores when a DB is configured and
    # nothing was injected. Tests inject file stores and skip this entirely.
    if settings.database_url and not injected.get("incident_index"):
        from psycopg_pool import AsyncConnectionPool

        pool = AsyncConnectionPool(
            settings.database_url, open=False,
            min_size=settings.db_pool_min, max_size=settings.db_pool_max,
        )
        await pool.open()
    app.state.pool = pool

    if injected.get("incident_index"):
        app.state.incident_index = injected["incident_index"]
    else:
        from sre_agent.incident_index import create_incident_index
        app.state.incident_index = create_incident_index(pool=pool)

    if injected.get("step_events"):
        app.state.step_events = injected["step_events"]
    else:
        from sre_agent.step_events import create_step_event_store
        app.state.step_events = create_step_event_store(pool=pool)

    if injected.get("service"):
        app.state.service = injected["service"]
    else:
        from sre_agent.service import SREAgentService
        app.state.service = SREAgentService(incident_index=app.state.incident_index)

    logger.info("Web API ready (database=%s)", bool(settings.database_url))
    try:
        yield
    finally:
        if pool is not None:
            await pool.close()


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #

def create_app(
    *,
    service=None,
    incident_index=None,
    step_events=None,
) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="SRE Agent Console", version="1.0.0", lifespan=lifespan)
    app.state.injected = {
        "service": service,
        "incident_index": incident_index,
        "step_events": step_events,
    }
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)

    approval_limiter = _RateLimiter(limit=30, window_seconds=60.0)

    # ----------------------------------------------------------------- #
    # Identity
    # ----------------------------------------------------------------- #

    @app.get("/api/me")
    async def me(principal: Principal = Depends(require_viewer)):
        return {
            "identity": principal.identity,
            "provider": principal.provider,
            "roles": sorted(principal.roles),
            "can_approve": principal.has_role(APPROVER_ROLE) or not settings.is_production,
            "verified": principal.verified,
        }

    # ----------------------------------------------------------------- #
    # Incidents
    # ----------------------------------------------------------------- #

    @app.get("/api/incidents")
    async def list_incidents(
        _: Principal = Depends(require_viewer),
        index=Depends(get_incident_index),
        status_filter: Optional[str] = Query(None, alias="status"),
        app_code: Optional[str] = None,
        severity: Optional[str] = None,
        service_name: Optional[str] = None,
        awaiting_approval: Optional[bool] = None,
        sort: str = "updated_at",
        descending: bool = True,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        rows, total = await index.alist(
            status=status_filter, app_code=app_code, severity=severity,
            service_name=service_name, awaiting_approval=awaiting_approval,
            sort=sort, descending=descending, limit=limit, offset=offset,
        )
        return {
            "items": [serializers.serialize_index_row(r) for r in rows],
            "total": total, "limit": limit, "offset": offset,
        }

    @app.get("/api/incidents/{incident_id}")
    async def incident_detail(
        incident_id: str,
        _: Principal = Depends(require_viewer),
        service=Depends(get_service),
        index=Depends(get_incident_index),
    ):
        config = {"configurable": {"thread_id": incident_id}}
        try:
            snapshot = await service.graph.aget_state(config)
        except Exception:
            snapshot = None
        row = await index.aget(incident_id)
        if (snapshot is None or not snapshot.values) and row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown incident")
        return {
            "index": serializers.serialize_index_row(row) if row else None,
            "state": serializers.serialize_state(snapshot.values) if snapshot and snapshot.values else None,
            "awaiting_approval": bool(snapshot and snapshot.next) if snapshot else False,
        }

    @app.get("/api/incidents/{incident_id}/timeline")
    async def incident_timeline(
        incident_id: str,
        _: Principal = Depends(require_viewer),
        events=Depends(get_step_events),
    ):
        timeline = await events.aby_incident(incident_id)
        return {"items": serializers.serialize_timeline(timeline)}

    @app.get("/api/incidents/{incident_id}/events")
    async def incident_events(
        request: Request,
        incident_id: str,
        _: Principal = Depends(require_viewer),
        events=Depends(get_step_events),
    ):
        after_seq = _last_event_id(request)
        return StreamingResponse(
            step_event_stream(events, after_seq=after_seq, incident_id=incident_id,
                              poll_interval=settings.step_event_flush_interval),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
        )

    @app.get("/api/events")
    async def global_events(
        request: Request,
        _: Principal = Depends(require_viewer),
        events=Depends(get_step_events),
    ):
        after_seq = _last_event_id(request)
        return StreamingResponse(
            step_event_stream(events, after_seq=after_seq, incident_id=None,
                              poll_interval=settings.step_event_flush_interval),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
        )

    # ----------------------------------------------------------------- #
    # Approvals
    # ----------------------------------------------------------------- #

    @app.get("/api/approvals/pending")
    async def pending_approvals(
        _: Principal = Depends(require_viewer),
        service=Depends(get_service),
        index=Depends(get_incident_index),
    ):
        items = []
        for pending in service.pending_approvals.all():
            row = await index.aget(pending.incident_id)
            items.append({
                "incident_id": pending.incident_id,
                "created_at": pending.created_at,
                "incident": serializers.serialize_index_row(row) if row else None,
            })
        return {"items": items}

    @app.post("/api/incidents/{incident_id}/approval")
    async def submit_approval(
        incident_id: str,
        decision: ApprovalDecision,
        principal: Principal = Depends(require_approver),
        service=Depends(get_service),
    ):
        if not approval_limiter.check(principal.identity):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "Approval rate limit exceeded; slow down")
        result = await service.submit_approval(
            incident_id=incident_id,
            approved=decision.approved,
            approver=principal.identity,
            reason=decision.reason,
            channel="web",
            approver_verified=principal.verified,
        )
        return result

    # ----------------------------------------------------------------- #
    # Metrics / health
    # ----------------------------------------------------------------- #

    @app.get("/api/metrics/summary")
    async def metrics_summary(
        _: Principal = Depends(require_viewer),
        index=Depends(get_incident_index),
    ):
        rows, total = await index.alist(limit=1000, offset=0)
        by_status: Dict[str, int] = defaultdict(int)
        awaiting = 0
        resolution_times = []
        for r in rows:
            by_status[r.status] += 1
            if r.awaiting_approval:
                awaiting += 1
            if r.status == "resolved" and r.updated_at and r.created_at:
                resolution_times.append(r.updated_at - r.created_at)
        mttr = sum(resolution_times) / len(resolution_times) if resolution_times else None
        return {
            "total": total,
            "by_status": dict(by_status),
            "awaiting_approval": awaiting,
            "mttr_seconds": mttr,
        }

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(request: Request):
        pool = getattr(request.app.state, "pool", None)
        if pool is None:
            return {"status": "ready", "database": False}
        try:
            async with pool.connection() as conn:
                await conn.execute("SELECT 1")
            return {"status": "ready", "database": True}
        except Exception:
            return JSONResponse(status_code=503, content={"status": "not_ready"})

    _mount_spa(app, settings.webapi_spa_dist_dir)
    return app


def _last_event_id(request: Request) -> int:
    """Resume point for SSE: Last-Event-ID header or ?after_seq query."""
    header = request.headers.get("last-event-id")
    if header and header.isdigit():
        return int(header)
    after = request.query_params.get("after_seq")
    if after and after.isdigit():
        return int(after)
    return 0


def _mount_spa(app: FastAPI, dist_dir: Optional[Path]) -> None:
    """Serve the built React SPA at / with history-fallback to index.html."""
    if not dist_dir:
        return
    dist = Path(dist_dir)
    if not dist.is_dir():
        logger.warning("SPA dist dir %s not found; UI not served", dist)
        return
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(dist), html=True), name="spa")
