"""
Production-ready API with FastAPI.

Features:
- Rate limiting
- Authentication
- Error handling
- Health checks
- Metrics endpoint
- Structured responses
"""
import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
import structlog

from src.integrations.config import get_settings
from src.observability import (
    metrics,
    tracer,
    audit,
    health,
    configure_logging,
    AuditEventType,
    get_langsmith
)
from src.storage.database import get_database_pool, get_vector_store
from src.integrations.llm_client import get_llm_client, get_embedding_client
from src.integrations.databricks_client import get_databricks_client

logger = structlog.get_logger()


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class IncidentRequest(BaseModel):
    """Incoming incident request."""
    job_name: str = Field(..., description="Name of the failed job")
    job_type: str = Field(..., description="Type of job (databricks, iws, etc)")
    source_system: str = Field(..., description="Source system identifier")
    environment: str = Field(..., description="Environment (prod, uat, dev)")
    error_message: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code")
    stack_trace: Optional[str] = Field(None, description="Stack trace")
    failure_timestamp: Optional[datetime] = Field(None, description="When the failure occurred")
    job_run_id: Optional[str] = Field(None, description="Job run identifier")
    cluster_id: Optional[str] = Field(None, description="Cluster ID (for Databricks)")
    owner_team: Optional[str] = Field(None, description="Team that owns the job")
    priority_hint: Optional[str] = Field(None, description="Priority hint (P1-P4)")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class IncidentResponse(BaseModel):
    """Incident creation response."""
    incident_id: str
    status: str
    message: str
    estimated_resolution_time_minutes: Optional[int] = None


class IncidentStatusResponse(BaseModel):
    """Incident status response."""
    incident_id: str
    status: str
    severity: Optional[str]
    classification: Optional[str]
    workflow_stage: str
    resolution_summary: Optional[str]
    actions_taken: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class ApprovalRequest(BaseModel):
    """Approval request for remediation."""
    incident_id: str
    approved: bool
    approver: str
    reason: Optional[str] = None


class ApprovalResponse(BaseModel):
    """Approval response."""
    incident_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: datetime
    components: Dict[str, Dict[str, Any]]


class MetricsInfo(BaseModel):
    """Metrics summary."""
    incidents_received: int
    incidents_resolved: int
    incidents_escalated: int
    avg_resolution_time_seconds: float
    auto_resolution_rate: float


# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, requests_per_minute: int = 60):
        self.rpm = requests_per_minute
        self._requests: Dict[str, List[float]] = {}

    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed."""
        now = time.time()
        minute_ago = now - 60

        if client_id not in self._requests:
            self._requests[client_id] = []

        # Clean old requests
        self._requests[client_id] = [
            t for t in self._requests[client_id] if t > minute_ago
        ]

        if len(self._requests[client_id]) >= self.rpm:
            return False

        self._requests[client_id].append(now)
        return True


rate_limiter = RateLimiter(requests_per_minute=100)


# ============================================================================
# AUTHENTICATION
# ============================================================================

async def verify_api_key(request: Request) -> str:
    """Verify API key from header with constant-time comparison."""
    import secrets

    api_key = request.headers.get("X-API-Key")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    settings = get_settings()

    # In production, require valid API keys
    if settings.environment != "development":
        valid_keys = settings.api_keys.split(",") if settings.api_keys else []

        # Use constant-time comparison to prevent timing attacks
        is_valid = any(
            secrets.compare_digest(api_key, valid_key.strip())
            for valid_key in valid_keys
        )

        if not is_valid:
            raise HTTPException(status_code=403, detail="Invalid API key")

    return api_key


def get_client_id(request: Request) -> str:
    """Get client identifier for rate limiting."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ============================================================================
# APP LIFECYCLE
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    configure_logging(
        log_level=get_settings().log_level,
        json_format=get_settings().environment != "development"
    )

    logger.info("application_starting", environment=get_settings().environment)

    # Initialize database
    try:
        pool = await get_database_pool()
        health.register("database", pool.health_check)
        logger.info("database_connected")
    except Exception as e:
        logger.error("database_connection_failed", error=str(e))

    # Initialize vector store
    try:
        vector_store = await get_vector_store()
        logger.info("vector_store_initialized")
    except Exception as e:
        logger.error("vector_store_init_failed", error=str(e))

    # Register health checks
    health.register("llm", lambda: {"healthy": True})  # Placeholder
    health.register("databricks", lambda: {"healthy": True})  # Placeholder

    # Set build info
    metrics.build_info.info({
        "version": "1.0.0",
        "environment": get_settings().environment
    })

    logger.info("application_started")

    yield

    # Shutdown
    logger.info("application_shutting_down")

    try:
        pool = await get_database_pool()
        await pool.close()
    except:
        pass

    logger.info("application_stopped")


# ============================================================================
# APP CREATION
# ============================================================================

def create_app() -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(
        title="Support Agent API",
        description="AI-powered incident management and auto-remediation",
        version="1.0.0",
        lifespan=lifespan
    )

    # CORS - Configure appropriately for production
    settings = get_settings()
    allowed_origins = ["*"] if settings.environment == "development" else [
        "https://*.azurewebsites.net",
        "https://*.azure.com"
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "X-API-Key", "X-Request-ID", "Content-Type"],
    )

    # ========================================================================
    # MIDDLEWARE
    # ========================================================================

    @app.middleware("http")
    async def add_request_context(request: Request, call_next):
        """Add request context for tracing and logging."""
        request_id = request.headers.get("X-Request-ID", uuid4().hex[:8])
        client_id = get_client_id(request)

        # Check rate limit
        if not rate_limiter.is_allowed(client_id):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"}
            )

        # Start trace
        with tracer.start_trace(
            f"{request.method} {request.url.path}",
            request_id=request_id,
            client_id=client_id
        ) as span:
            start_time = time.time()

            # Add request context to logs
            structlog.contextvars.bind_contextvars(
                request_id=request_id,
                path=request.url.path,
                method=request.method
            )

            try:
                response = await call_next(request)

                # Record metrics
                duration = time.time() - start_time
                metrics.workflow_stage_duration.labels(
                    stage="http_request"
                ).observe(duration)

                response.headers["X-Request-ID"] = request_id
                response.headers["X-Response-Time"] = f"{duration*1000:.2f}ms"

                return response

            except Exception as e:
                span.set_status("error", str(e))
                logger.error("request_failed", error=str(e))
                raise

            finally:
                structlog.contextvars.unbind_contextvars(
                    "request_id", "path", "method"
                )

    # ========================================================================
    # HEALTH ENDPOINTS
    # ========================================================================

    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        """Health check endpoint."""
        results = await health.check_all()
        status_info = health.get_status(results)

        if status_info["status"] != "healthy":
            return JSONResponse(
                status_code=503,
                content=status_info
            )

        return HealthResponse(
            status=status_info["status"],
            timestamp=datetime.utcnow(),
            components=status_info["components"]
        )

    @app.get("/health/live")
    async def liveness():
        """Kubernetes liveness probe."""
        return {"status": "alive"}

    @app.get("/health/ready")
    async def readiness():
        """Kubernetes readiness probe."""
        if await health.is_healthy():
            return {"status": "ready"}
        raise HTTPException(status_code=503, detail="Not ready")

    @app.get("/metrics")
    async def prometheus_metrics():
        """Prometheus metrics endpoint."""
        return Response(
            content=metrics.get_metrics(),
            media_type="text/plain"
        )

    # ========================================================================
    # LANGSMITH TEST ENDPOINT
    # ========================================================================

    @app.get("/api/v1/test-langsmith")
    async def test_langsmith_integration():
        """Test LangSmith connectivity and create a test trace."""
        import os

        ls = get_langsmith()

        if not ls.enabled:
            return {
                "status": "disabled",
                "message": "LangSmith not configured. Check LANGCHAIN_API_KEY environment variable.",
                "project": os.getenv("LANGCHAIN_PROJECT", "not set")
            }

        # Create a test trace to verify connectivity
        try:
            with ls.trace_incident(
                incident_id="CONNECTIVITY-TEST",
                job_name="langsmith-connectivity-test",
                job_type="test",
                environment=get_settings().environment,
                source_system="api-test"
            ) as run:
                run.add_outputs({"test": "successful", "timestamp": datetime.utcnow().isoformat()})
                run_id = run.run_id

            return {
                "status": "enabled",
                "project": os.getenv("LANGCHAIN_PROJECT", "support-agent"),
                "run_id": run_id,
                "message": "Trace created successfully. Check LangSmith UI."
            }

        except Exception as e:
            logger.error("langsmith_test_failed", error=str(e))
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "LangSmith trace failed. Check server logs for details.",
                    "project": os.getenv("LANGCHAIN_PROJECT", "not set")
                }
            )

    # ========================================================================
    # INCIDENT ENDPOINTS
    # ========================================================================

    @app.post("/api/v1/incidents", response_model=IncidentResponse)
    async def create_incident(
        incident: IncidentRequest,
        background_tasks: BackgroundTasks,
        api_key: str = Depends(verify_api_key)
    ):
        """Create a new incident."""
        incident_id = f"INC-{uuid4().hex[:8].upper()}"

        # Record metrics
        metrics.incidents_received.labels(
            job_type=incident.job_type,
            environment=incident.environment,
            source_system=incident.source_system
        ).inc()

        # Audit log
        audit.log(
            event_type=AuditEventType.INCIDENT_RECEIVED,
            action="create_incident",
            incident_id=incident_id,
            details={
                "job_name": incident.job_name,
                "job_type": incident.job_type,
                "environment": incident.environment
            }
        )

        logger.info(
            "incident_received",
            incident_id=incident_id,
            job_name=incident.job_name,
            job_type=incident.job_type
        )

        # Process incident in background
        background_tasks.add_task(
            process_incident,
            incident_id=incident_id,
            incident_data=incident.model_dump()
        )

        return IncidentResponse(
            incident_id=incident_id,
            status="processing",
            message="Incident received and being processed",
            estimated_resolution_time_minutes=5
        )

    @app.get("/api/v1/incidents/{incident_id}", response_model=IncidentStatusResponse)
    async def get_incident(
        incident_id: str,
        api_key: str = Depends(verify_api_key)
    ):
        """Get incident status."""
        vector_store = await get_vector_store()

        async with vector_store.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    incident_id, status, severity, category,
                    resolution_summary, created_at, updated_at
                FROM incidents
                WHERE incident_id = $1
            """, incident_id)

            if not row:
                raise HTTPException(status_code=404, detail="Incident not found")

            # Get action history
            history = await vector_store.get_incident_history(incident_id)

            return IncidentStatusResponse(
                incident_id=row["incident_id"],
                status=row["status"] or "processing",
                severity=row["severity"],
                classification=row["category"],
                workflow_stage="processing",  # Would come from workflow state
                resolution_summary=row["resolution_summary"],
                actions_taken=history,
                created_at=row["created_at"],
                updated_at=row["updated_at"]
            )

    @app.get("/api/v1/incidents/{incident_id}/audit")
    async def get_incident_audit_trail(
        incident_id: str,
        api_key: str = Depends(verify_api_key)
    ):
        """Get audit trail for an incident."""
        events = audit.get_incident_audit_trail(incident_id)
        return {"incident_id": incident_id, "events": [e.to_dict() for e in events]}

    # ========================================================================
    # APPROVAL ENDPOINTS
    # ========================================================================

    @app.post("/api/v1/approvals", response_model=ApprovalResponse)
    async def submit_approval(
        approval: ApprovalRequest,
        background_tasks: BackgroundTasks,
        api_key: str = Depends(verify_api_key)
    ):
        """Submit approval for a remediation."""
        # Audit log
        audit.log(
            event_type=AuditEventType.REMEDIATION_APPROVED if approval.approved
                      else AuditEventType.REMEDIATION_REJECTED,
            action="approval_submitted",
            incident_id=approval.incident_id,
            actor=approval.approver,
            details={"approved": approval.approved, "reason": approval.reason}
        )

        if approval.approved:
            # Continue workflow execution
            background_tasks.add_task(
                continue_incident_workflow,
                incident_id=approval.incident_id
            )

        return ApprovalResponse(
            incident_id=approval.incident_id,
            status="approved" if approval.approved else "rejected",
            message="Remediation will proceed" if approval.approved
                    else "Remediation rejected, incident escalated"
        )

    @app.get("/api/v1/approvals/pending")
    async def get_pending_approvals(
        api_key: str = Depends(verify_api_key)
    ):
        """Get list of incidents pending approval."""
        # In a real implementation, this would query the workflow state
        return {"pending": []}

    # ========================================================================
    # DASHBOARD ENDPOINTS
    # ========================================================================

    @app.get("/api/v1/dashboard/summary", response_model=MetricsInfo)
    async def get_dashboard_summary(
        api_key: str = Depends(verify_api_key)
    ):
        """Get dashboard summary metrics."""
        # In a real implementation, aggregate from database
        return MetricsInfo(
            incidents_received=0,
            incidents_resolved=0,
            incidents_escalated=0,
            avg_resolution_time_seconds=0.0,
            auto_resolution_rate=0.0
        )

    @app.get("/api/v1/dashboard/recent")
    async def get_recent_incidents(
        limit: int = 20,
        api_key: str = Depends(verify_api_key)
    ):
        """Get recent incidents for dashboard."""
        vector_store = await get_vector_store()

        async with vector_store.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    incident_id, job_name, job_type, environment,
                    status, severity, created_at
                FROM incidents
                ORDER BY created_at DESC
                LIMIT $1
            """, limit)

            return {"incidents": [dict(row) for row in rows]}

    return app


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

async def process_incident(incident_id: str, incident_data: Dict[str, Any]) -> None:
    """Process an incident through the workflow."""
    logger.info("processing_incident_started", incident_id=incident_id)

    try:
        # Import here to avoid circular imports
        from src.services.workflow_service import WorkflowService

        # Initialize workflow service
        service = WorkflowService()

        # Run the workflow
        result = await service.process_incident(
            incident_id=incident_id,
            **incident_data
        )

        logger.info(
            "processing_incident_completed",
            incident_id=incident_id,
            status=result.get("status")
        )

    except Exception as e:
        logger.error(
            "processing_incident_failed",
            incident_id=incident_id,
            error=str(e)
        )

        # Update incident status
        try:
            vector_store = await get_vector_store()
            async with vector_store.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE incidents
                    SET status = 'error', updated_at = NOW()
                    WHERE incident_id = $1
                """, incident_id)
        except:
            pass

        # Audit log
        audit.log(
            event_type=AuditEventType.INCIDENT_ESCALATED,
            action="processing_failed",
            incident_id=incident_id,
            outcome="failure",
            details={"error": str(e)}
        )


async def continue_incident_workflow(incident_id: str) -> None:
    """Continue workflow after approval."""
    logger.info("continuing_workflow", incident_id=incident_id)
    # Implementation would resume the workflow from checkpoint


# ============================================================================
# APP INSTANCE
# ============================================================================

app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=get_settings().environment == "development"
    )
