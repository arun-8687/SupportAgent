"""IncidentIndexStore tests (file backend, offline)."""
import pytest

from sre_agent.incident_index import FileIncidentIndexStore, IncidentIndexRow


@pytest.fixture
def index(tmp_path):
    return FileIncidentIndexStore(path=tmp_path / "incident_index.jsonl")


@pytest.mark.unit
def test_upsert_creates_then_updates(index):
    index.upsert("sre-1", app_code="PAY-1", service_name="payment", severity="sev2",
                 title="mem oom", status="received")
    row = index.get("sre-1")
    assert row.app_code == "PAY-1" and row.status == "received"
    assert row.created_at > 0 and row.updated_at >= row.created_at

    created = row.created_at
    index.upsert("sre-1", status="resolved", ticket_id="INC-9")
    row2 = index.get("sre-1")
    assert row2.status == "resolved" and row2.ticket_id == "INC-9"
    assert row2.app_code == "PAY-1"  # preserved
    assert row2.created_at == created  # created_at is stable
    assert row2.updated_at >= created


@pytest.mark.unit
def test_upsert_ignores_unknown_and_none_fields(index):
    index.upsert("sre-1", title="t", bogus="x", status=None)
    row = index.get("sre-1")
    assert row.title == "t"
    assert not hasattr(row, "bogus")
    assert row.status == "received"  # default kept (None ignored)


@pytest.mark.unit
def test_list_filter_sort_paginate(index):
    for i in range(5):
        index.upsert(f"sre-{i}", app_code="PAY" if i % 2 == 0 else "ORD",
                     severity="sev1" if i == 4 else "sev3",
                     status="resolved" if i < 3 else "awaiting_approval")

    rows, total = index.list(app_code="PAY")
    assert total == 3 and {r.incident_id for r in rows} == {"sre-0", "sre-2", "sre-4"}

    rows, total = index.list(status="awaiting_approval")
    assert total == 2 and all(r.status == "awaiting_approval" for r in rows)

    rows, total = index.list(severity="sev1")
    assert total == 1 and rows[0].incident_id == "sre-4"

    # Pagination: total reflects the full filtered set, page is bounded.
    page, total = index.list(limit=2, offset=0)
    assert total == 5 and len(page) == 2


@pytest.mark.unit
def test_list_sort_by_created_ascending(index):
    import time
    for i in range(3):
        index.upsert(f"sre-{i}")
        time.sleep(0.001)
    rows, _ = index.list(sort="created_at", descending=False)
    assert [r.incident_id for r in rows] == ["sre-0", "sre-1", "sre-2"]


@pytest.mark.unit
def test_awaiting_approval_filter(index):
    index.upsert("a", awaiting_approval=True)
    index.upsert("b", awaiting_approval=False)
    rows, total = index.list(awaiting_approval=True)
    assert total == 1 and rows[0].incident_id == "a"


@pytest.mark.unit
async def test_async_read_wrappers(index):
    index.upsert("sre-1", app_code="PAY-1")
    rows, total = await index.alist(app_code="PAY-1")
    assert total == 1
    row = await index.aget("sre-1")
    assert row.app_code == "PAY-1"
    assert await index.aget("nope") is None


@pytest.mark.unit
def test_row_json_roundtrip():
    row = IncidentIndexRow(incident_id="x", app_code="A", created_at=1.0, updated_at=2.0)
    assert IncidentIndexRow.from_json(row.to_json()) == row
    # Unknown keys are dropped, not fatal.
    assert IncidentIndexRow.from_json({"incident_id": "y", "junk": 1}).incident_id == "y"
