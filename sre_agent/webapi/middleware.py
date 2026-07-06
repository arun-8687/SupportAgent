"""
Production middleware: request id + latency telemetry, structured errors,
and a request-body size cap.

Every request gets an id (honoring an inbound `X-Request-ID`) echoed back and
logged via `observability.log_step`, so API activity lands in the same App
Insights timeline as the workflow. Unhandled exceptions become a structured
JSON error — never a stack trace to the client.
"""
import logging
import time
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from sre_agent.observability import log_step

logger = logging.getLogger(__name__)

# Approval/read bodies are tiny; anything large is abuse or a mistake.
MAX_BODY_BYTES = 256 * 1024


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, times the request, and logs the outcome."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.exception("Unhandled error [%s] %s %s", request_id,
                             request.method, request.url.path)
            log_step("webapi_request", "error", request_id,
                     duration_ms=duration_ms, method=request.method,
                     path=request.url.path)
            return JSONResponse(
                status_code=500,
                content={"error": "internal_error", "request_id": request_id},
                headers={"x-request-id": request_id},
            )
        duration_ms = int((time.monotonic() - start) * 1000)
        response.headers["x-request-id"] = request_id
        log_step("webapi_request",
                 "ok" if response.status_code < 400 else "client_error",
                 request_id, duration_ms=duration_ms, method=request.method,
                 path=request.url.path, http_status=response.status_code)
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies before they reach a handler."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"error": "payload_too_large"},
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"error": "bad_content_length"})
        return await call_next(request)
