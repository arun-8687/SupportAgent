"""
Non-blocking step-event writer.

The workflow must never do event I/O on its hot path. `observability.log_step`'s
durable sink only enqueues onto a **bounded** in-memory queue (drop-oldest +
a dropped counter when full, so an alert storm can never block or OOM the
graph). A background task drains the queue in batches and writes them to the
StepEventStore in a single multi-row insert per batch.

Lifecycle: `start()` at worker/API startup registers the sink and launches
the drain task; `stop()` (graceful shutdown) unregisters the sink, flushes
whatever is queued, and cancels the task.
"""
import asyncio
import logging
import time
from collections import deque
from typing import Any, Deque, Dict, Optional

from sre_agent import observability
from sre_agent.config import get_settings
from sre_agent.step_events import StepEvent, event_from_record

logger = logging.getLogger(__name__)


class StepEventWriter:
    """Bounded async queue + batching background writer for step events."""

    def __init__(
        self,
        store,
        batch_size: Optional[int] = None,
        flush_interval: Optional[float] = None,
        queue_max: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.store = store
        self.batch_size = batch_size or settings.step_event_batch_size
        self.flush_interval = flush_interval or settings.step_event_flush_interval
        self.queue_max = queue_max or settings.step_event_queue_max
        # A plain deque with drop-oldest is simpler + safe here: the sink
        # runs in the same event loop as the drain task (log_step is called
        # from async nodes), so no cross-thread locking is needed.
        self._buf: Deque[StepEvent] = deque(maxlen=self.queue_max)
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self.dropped = 0

    # -- sink (hot path) ------------------------------------------------- #

    def _sink(self, record: Dict[str, Any]) -> None:
        """Registered with observability; MUST be cheap and never raise."""
        try:
            if len(self._buf) >= self.queue_max:
                self.dropped += 1  # deque(maxlen) drops the oldest on append
            record = {**record, "ts": record.get("ts") or time.time()}
            self._buf.append(event_from_record(record))
        except Exception:  # pragma: no cover - defensive
            pass

    # -- lifecycle ------------------------------------------------------- #

    def start(self) -> None:
        observability.register_step_sink(self._sink)
        self._task = asyncio.create_task(self._run(), name="step-event-writer")
        logger.info(
            "Step-event writer started (batch=%d interval=%.2fs queue_max=%d)",
            self.batch_size, self.flush_interval, self.queue_max,
        )

    async def stop(self) -> None:
        observability.unregister_step_sink(self._sink)
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=self.flush_interval + 5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        await self._flush()  # final drain
        if self.dropped:
            logger.warning("Step-event writer dropped %d events under load", self.dropped)

    # -- drain loop ------------------------------------------------------ #

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self.flush_interval)
            except asyncio.TimeoutError:
                pass
            await self._flush()

    async def _flush(self) -> None:
        while self._buf:
            batch = [self._buf.popleft() for _ in range(min(self.batch_size, len(self._buf)))]
            try:
                # StepEventStore.append_many is sync; offload so a slow DB
                # write never blocks the event loop.
                await asyncio.to_thread(self.store.append_many, batch)
            except Exception:
                logger.exception("Failed to persist %d step events", len(batch))
                break  # avoid a tight failure loop; retry on next interval
