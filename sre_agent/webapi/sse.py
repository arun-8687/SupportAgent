"""
Server-Sent Events for live updates.

Both live surfaces — a single incident's timeline and the global dashboard —
are driven by tailing the durable step-event store by monotonic `seq`:
`atail(after_seq=..., incident_id=...)` returns only events newer than the
last one the client saw, so a reconnect resumes exactly where it left off
(the client sends `Last-Event-ID`). Between batches we emit an SSE comment
heartbeat so proxies/load balancers keep the connection open and the client
detects a dead link quickly.

Tailing works identically on the file and Postgres backends, so it needs no
LISTEN/NOTIFY plumbing and streams correctly in tests. The poll interval is
small; at Postgres scale a NOTIFY-driven wakeup can replace the sleep without
changing this contract.
"""
import asyncio
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def sse_message(data: Dict[str, Any], event: Optional[str] = None,
                event_id: Optional[str] = None) -> str:
    """Format one SSE frame (event/id optional)."""
    lines = []
    if event:
        lines.append(f"event: {event}")
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"data: {json.dumps(data)}")
    return "\n".join(lines) + "\n\n"


async def step_event_stream(
    store,
    after_seq: int = 0,
    incident_id: Optional[str] = None,
    poll_interval: float = 1.0,
    heartbeat_interval: float = 15.0,
    stop: Optional[asyncio.Event] = None,
):
    """Yield SSE frames for new step events until the client disconnects.

    Resumable: `after_seq` (from the client's Last-Event-ID) advances as
    events flow, so a reconnect never replays or skips. Emits a heartbeat
    comment when idle so intermediaries don't reap the connection.
    """
    last_seq = after_seq
    idle = 0.0
    # Prime with a hello frame so the client knows the stream is live.
    yield ": connected\n\n"
    while stop is None or not stop.is_set():
        try:
            events = await store.atail(after_seq=last_seq, incident_id=incident_id, limit=200)
        except Exception:
            logger.exception("SSE tail failed; will retry")
            events = []
        if events:
            for ev in events:
                last_seq = max(last_seq, ev.seq)
                yield sse_message(ev.to_json(), event="step", event_id=str(ev.seq))
            idle = 0.0
        else:
            idle += poll_interval
            if idle >= heartbeat_interval:
                yield ": heartbeat\n\n"
                idle = 0.0
        await asyncio.sleep(poll_interval)
