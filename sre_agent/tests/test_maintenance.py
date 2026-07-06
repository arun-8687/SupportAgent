"""Retention helpers degrade to no-ops without a Postgres backend."""
import pytest

from sre_agent import maintenance


@pytest.mark.unit
def test_prune_step_events_noop_without_db(monkeypatch):
    monkeypatch.setattr(maintenance.get_settings(), "database_url", None, raising=False)
    assert maintenance.prune_step_events() == 0


@pytest.mark.unit
def test_run_maintenance_summary_without_db(monkeypatch):
    monkeypatch.setattr(maintenance.get_settings(), "database_url", None, raising=False)
    summary = maintenance.run_maintenance()
    assert summary == {"checkpoints_pruned": 0, "step_event_partitions_dropped": 0}
