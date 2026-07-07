"""Web API tests — offline (file stores + conftest service, no database)."""
import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient

from sre_agent.step_writer import StepEventWriter
from sre_agent.webapi.app import create_app


def principal_header(identity: str, roles) -> str:
    payload = {
        "auth_typ": "aad",
        "claims": [{"typ": "preferred_username", "val": identity}]
        + [{"typ": "roles", "val": r} for r in roles],
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


VIEWER = {"x-ms-client-principal": principal_header("viewer@corp", ["SRE.Viewer"])}
APPROVER = {"x-ms-client-principal": principal_header("approver@corp", ["SRE.Approver"])}


@pytest.fixture
async def paused_incident(service, step_events, azure_monitor_alert):
    """Run an alert to the approval pause, persisting its step timeline."""
    writer = StepEventWriter(step_events, batch_size=50, flush_interval=0.02)
    writer.start()
    result = await service.handle_alert(azure_monitor_alert)
    await asyncio.sleep(0.1)
    await writer.stop()
    return result


@pytest.fixture
def client(service, incident_index, step_events):
    app = create_app(service=service, incident_index=incident_index, step_events=step_events)
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------- #
# Reads (dev settings: permissive, dev principal)
# --------------------------------------------------------------------------- #

@pytest.mark.integration
def test_list_and_filter_incidents(client, paused_incident):
    r = client.get("/api/incidents")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "awaiting_approval"

    # Filter that excludes it -> empty.
    assert client.get("/api/incidents", params={"status": "resolved"}).json()["total"] == 0
    # Awaiting-approval filter includes it.
    assert client.get("/api/incidents", params={"awaiting_approval": True}).json()["total"] == 1


@pytest.mark.integration
def test_incident_detail_redacts_raw_alert(client, paused_incident):
    incident_id = paused_incident["incident_id"]
    r = client.get(f"/api/incidents/{incident_id}")
    assert r.status_code == 200
    state = r.json()["state"]
    assert state is not None
    # Raw provider payload must be redacted even behind auth.
    assert state["incident"]["alert"]["raw"] == "[redacted]"
    # But normalized fields survive.
    assert state["incident"]["service_name"]
    assert r.json()["awaiting_approval"] is True


@pytest.mark.integration
def test_unknown_incident_is_404(client):
    assert client.get("/api/incidents/does-not-exist").status_code == 404


@pytest.mark.integration
def test_timeline_is_ordered(client, paused_incident):
    incident_id = paused_incident["incident_id"]
    r = client.get(f"/api/incidents/{incident_id}/timeline")
    assert r.status_code == 200
    items = r.json()["items"]
    assert items, "expected a persisted step timeline"
    seqs = [e["seq"] for e in items]
    assert seqs == sorted(seqs)


@pytest.mark.integration
def test_metrics_summary(client, paused_incident):
    r = client.get("/api/metrics/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["awaiting_approval"] == 1


@pytest.mark.integration
def test_pending_approvals_joins_index(client, paused_incident):
    r = client.get("/api/approvals/pending")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["incident"]["status"] == "awaiting_approval"


@pytest.mark.integration
def test_me_reports_roles(client):
    r = client.get("/api/me", headers=VIEWER)
    assert r.status_code == 200
    assert "SRE.Viewer" in r.json()["roles"]


# --------------------------------------------------------------------------- #
# SSE
# --------------------------------------------------------------------------- #

@pytest.mark.integration
async def test_sse_generator_streams_and_resumes(step_events):
    """The SSE generator yields a hello frame, then new events, resumably."""
    from sre_agent.step_events import StepEvent
    from sre_agent.webapi.sse import step_event_stream

    step_events.append_many([
        StepEvent("i1", "triage", "completed", ts=1.0),
        StepEvent("i1", "verify", "completed", ts=2.0),
    ])
    stop = asyncio.Event()
    frames = []
    gen = step_event_stream(step_events, after_seq=0, incident_id="i1",
                            poll_interval=0.01, heartbeat_interval=999, stop=stop)
    async for frame in gen:
        frames.append(frame)
        if len([f for f in frames if "event: step" in f]) >= 2:
            stop.set()
            break
    await gen.aclose()

    assert frames[0].startswith(": connected")
    step_frames = [f for f in frames if "event: step" in f]
    assert len(step_frames) == 2
    # Each carries an id line for Last-Event-ID resume.
    assert all("id: " in f for f in step_frames)

    # Resuming after seq 1 yields only the newer event.
    stop2 = asyncio.Event()
    gen2 = step_event_stream(step_events, after_seq=1, incident_id="i1",
                             poll_interval=0.01, heartbeat_interval=999, stop=stop2)
    newer = []
    async for frame in gen2:
        if "event: step" in frame:
            newer.append(frame)
            stop2.set()
            break
    await gen2.aclose()
    assert len(newer) == 1 and '"seq": 2' in newer[0]


@pytest.mark.integration
def test_sse_routes_are_registered(service, incident_index, step_events):
    """Both live SSE endpoints are mounted (their body is streamed, not
    driven over TestClient which can't consume an infinite generator)."""
    app = create_app(service=service, incident_index=incident_index, step_events=step_events)
    paths = {r.path for r in app.routes}
    assert "/api/incidents/{incident_id}/events" in paths
    assert "/api/events" in paths


# --------------------------------------------------------------------------- #
# RBAC matrix. Auth gating (401/403) is enforced by the FastAPI dependencies
# BEFORE any route body runs, so these production cases need no live incident
# (running the graph under prod would require an LLM). The successful-approval
# path exercises the full graph resume and runs under dev settings with an
# explicit, verified approver header.
# --------------------------------------------------------------------------- #

@pytest.mark.integration
def test_rbac_read_requires_principal_in_prod(client, production_settings):
    assert client.get("/api/incidents").status_code == 401           # no principal
    assert client.get("/api/incidents", headers=VIEWER).status_code == 200


@pytest.mark.integration
def test_rbac_viewer_cannot_approve(client, production_settings):
    r = client.post("/api/incidents/sre-x/approval",
                    json={"approved": True}, headers=VIEWER)
    assert r.status_code == 403


@pytest.mark.integration
def test_approval_without_principal_is_401(client, production_settings):
    r = client.post("/api/incidents/sre-x/approval", json={"approved": True})
    assert r.status_code == 401


@pytest.mark.integration
def test_approver_header_resolves_paused_incident(client, paused_incident):
    # Dev settings: a supplied header is still honored as the real principal,
    # so the approver drives a genuine end-to-end resolution.
    incident_id = paused_incident["incident_id"]
    r = client.post(f"/api/incidents/{incident_id}/approval",
                    json={"approved": True, "reason": "looks safe"}, headers=APPROVER)
    assert r.status_code == 200
    assert r.json()["status"] in ("resolved", "verified", "mitigated")


# --------------------------------------------------------------------------- #
# SPA history fallback
# --------------------------------------------------------------------------- #

@pytest.mark.integration
def test_spa_deep_link_falls_back_to_index_html(service, incident_index, step_events, tmp_path):
    """A direct GET to a client-side route (deep link / hard refresh) must
    serve index.html so React Router can take over, not 404."""
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html><body>spa shell</body></html>")

    from sre_agent.config import get_settings

    settings = get_settings()
    original = settings.webapi_spa_dist_dir
    settings.webapi_spa_dist_dir = dist
    try:
        app = create_app(service=service, incident_index=incident_index, step_events=step_events)
    finally:
        settings.webapi_spa_dist_dir = original

    with TestClient(app) as c:
        for path in ("/", "/approvals", "/incidents/sre-123"):
            r = c.get(path)
            assert r.status_code == 200, path
            assert "spa shell" in r.text, path
        # API routes are unaffected by the catch-all.
        assert c.get("/api/incidents").status_code == 200


@pytest.mark.integration
def test_spa_fallback_blocks_path_traversal(service, incident_index, step_events, tmp_path):
    """The SPA fallback must not serve files outside the dist dir. A secret
    sits next to (but outside) dist; a traversal attempt must fall back to
    index.html, never leak it."""
    root = tmp_path / "root"
    dist = root / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html><body>spa shell</body></html>")
    secret = root / "secret.txt"
    secret.write_text("TOP-SECRET-DB-URL")

    from sre_agent.config import get_settings

    settings = get_settings()
    original = settings.webapi_spa_dist_dir
    settings.webapi_spa_dist_dir = dist
    try:
        app = create_app(service=service, incident_index=incident_index, step_events=step_events)
    finally:
        settings.webapi_spa_dist_dir = original

    with TestClient(app) as c:
        # A legitimate asset under dist is still served.
        (dist / "favicon.ico").write_text("icon-bytes")
        assert c.get("/favicon.ico").text == "icon-bytes"
        # Traversal attempts never leak the sibling secret; they fall through
        # to the SPA shell. (raw_path avoids the client normalizing "..".)
        for evil in ("/../secret.txt", "/..%2fsecret.txt", "/%2e%2e/secret.txt"):
            r = c.get(evil)
            assert "TOP-SECRET" not in r.text, evil
