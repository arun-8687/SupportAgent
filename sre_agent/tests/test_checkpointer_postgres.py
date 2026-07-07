"""Postgres checkpointer integration test (gated on a real database).

Skips unless SRE_AGENT_TEST_DATABASE_URL is set and psycopg +
langgraph-checkpoint-postgres are installed — same pattern as the pgvector
integration test. Guards the create_checkpointer() connection-lifetime fix:
the saver must keep a live connection (from_conn_string's context manager
would close it on GC).
"""
import os

import pytest

DB_URL = os.environ.get("SRE_AGENT_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DB_URL, reason="SRE_AGENT_TEST_DATABASE_URL not set"
)


@pytest.fixture
def _pg_settings(monkeypatch):
    from sre_agent.config import get_settings

    monkeypatch.setenv("SRE_AGENT_DATABASE_URL", DB_URL)
    get_settings.cache_clear()
    yield
    monkeypatch.delenv("SRE_AGENT_DATABASE_URL", raising=False)
    get_settings.cache_clear()


@pytest.mark.integration
async def test_postgres_checkpointer_async_roundtrip(_pg_settings):
    import gc

    from sre_agent.graph.workflow import create_checkpointer

    checkpointer = create_checkpointer()
    # Force GC: a discarded connection/context-manager would be collected here
    # and close the connection out from under the saver.
    gc.collect()

    try:
        # The service drives the graph asynchronously, so the saver must answer
        # async calls — the sync PostgresSaver's aget_tuple raises
        # NotImplementedError. The lazy pool opens on this first async use.
        config = {"configurable": {"thread_id": "does-not-exist"}}
        assert await checkpointer.aget_tuple(config) is None
    finally:
        # Close the pool so the test's event loop can shut down cleanly.
        await checkpointer._pool_ref.close()
