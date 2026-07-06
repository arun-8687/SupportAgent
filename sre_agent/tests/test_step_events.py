"""StepEventStore + non-blocking StepEventWriter tests (offline)."""
import asyncio

import pytest

from sre_agent import observability
from sre_agent.step_events import FileStepEventStore, StepEvent, event_from_record
from sre_agent.step_writer import StepEventWriter


@pytest.fixture
def store(tmp_path):
    return FileStepEventStore(path=tmp_path / "step_events.jsonl")


@pytest.fixture(autouse=True)
def _clean_sinks():
    observability.clear_step_sinks()
    yield
    observability.clear_step_sinks()


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_append_assigns_monotonic_seq(store):
    store.append(StepEvent("i1", "triage", "completed", ts=1.0))
    store.append_many([
        StepEvent("i1", "verify", "completed", ts=2.0),
        StepEvent("i2", "triage", "completed", ts=3.0),
    ])
    events = store._read()
    assert [e.seq for e in events] == [1, 2, 3]


@pytest.mark.unit
def test_by_incident_and_tail(store):
    for i in range(5):
        store.append(StepEvent("i1" if i % 2 == 0 else "i2", f"s{i}", "completed", ts=i))
    assert [e.step for e in store.by_incident("i1")] == ["s0", "s2", "s4"]

    # tail(after_seq) drives the SSE stream: only newer events.
    tail = store.tail(after_seq=3)
    assert [e.seq for e in tail] == [4, 5]
    assert store.tail(after_seq=3, incident_id="i2") == [e for e in tail if e.incident_id == "i2"]


@pytest.mark.unit
async def test_async_read_wrappers(store):
    store.append(StepEvent("i1", "triage", "completed", ts=1.0))
    assert len(await store.aby_incident("i1")) == 1
    assert len(await store.atail(after_seq=0)) == 1


@pytest.mark.unit
def test_event_from_record_maps_observability_shape():
    rec = {"step": "triage", "status": "completed", "incident_id": "i1",
           "duration_ms": 5, "ts": 9.0, "fields": {"service_name": "pay"}}
    ev = event_from_record(rec)
    assert ev.incident_id == "i1" and ev.duration_ms == 5
    assert ev.fields["service_name"] == "pay" and ev.ts == 9.0


# --------------------------------------------------------------------------- #
# Non-blocking writer
# --------------------------------------------------------------------------- #

@pytest.mark.unit
async def test_writer_persists_log_step_events(store):
    writer = StepEventWriter(store, batch_size=10, flush_interval=0.05)
    writer.start()
    try:
        # log_step goes through the registered sink -> queue -> batch write.
        observability.log_step("triage", "completed", "i1", service_name="pay")
        observability.log_step("verify", "completed", "i1")
        await asyncio.sleep(0.15)  # let the drain loop flush
    finally:
        await writer.stop()

    steps = {e.step for e in store.by_incident("i1")}
    assert {"triage", "verify"} <= steps


@pytest.mark.unit
async def test_writer_flushes_remaining_on_stop(store):
    writer = StepEventWriter(store, batch_size=100, flush_interval=100.0)  # never auto-flush
    writer.start()
    observability.log_step("triage", "completed", "i1")
    # stop() must drain what's queued even though the interval never elapsed.
    await writer.stop()
    assert len(store.by_incident("i1")) == 1


@pytest.mark.unit
async def test_writer_drop_oldest_and_counter_under_flood(store):
    # Tiny queue: floods overflow and drop-oldest, counting drops. The
    # workflow (sink) never blocks regardless.
    writer = StepEventWriter(store, batch_size=5, flush_interval=100.0, queue_max=5)
    writer.start()
    try:
        for i in range(50):
            observability.log_step("s", "completed", f"i{i}")
        assert writer.dropped >= 40  # only ~5 fit; the rest are dropped
        assert len(writer._buf) <= 5
    finally:
        await writer.stop()


@pytest.mark.unit
async def test_sink_unregistered_after_stop(store):
    writer = StepEventWriter(store, flush_interval=0.05)
    writer.start()
    await writer.stop()
    before = len(store._read())
    observability.log_step("s", "completed", "i1")  # no sink now
    assert len(store._read()) == before  # nothing persisted
