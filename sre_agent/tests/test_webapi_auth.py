"""Bearer / oauth2-proxy auth path for the web API (AKS deployment)."""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from sre_agent.webapi import auth
from sre_agent.webapi.app import create_app


def _b64url(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(roles=(), identity="user@corp", extra=None) -> str:
    """An unsigned Entra-shaped JWT (oauth2-proxy forwards the real one).

    `roles` is written to the claim as-is (list or a bare string) so the
    parser's string/list handling is exercised faithfully.
    """
    header = _b64url({"alg": "none", "typ": "JWT"})
    roles_claim = roles if isinstance(roles, str) else list(roles)
    payload = {"preferred_username": identity, "roles": roles_claim}
    payload.update(extra or {})
    return f"{header}.{_b64url(payload)}.sig"


@pytest.fixture(autouse=True)
def _reset_warn():
    auth._UNVERIFIED_WARNED = False
    yield


# --------------------------------------------------------------------------- #
# Unit: token -> Principal
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_parse_token_reads_roles_and_identity():
    p = auth.parse_principal_from_token(make_jwt(roles=["SRE.Approver"], identity="a@corp"))
    assert p is not None
    assert p.identity == "a@corp"
    assert p.verified is True
    assert p.has_role(auth.APPROVER_ROLE)


@pytest.mark.unit
def test_parse_token_roles_as_string():
    p = auth.parse_principal_from_token(make_jwt(roles="SRE.Viewer"))
    assert p.has_role(auth.VIEWER_ROLE)


@pytest.mark.unit
def test_parse_token_falls_back_through_identity_claims():
    header = _b64url({"alg": "none"})
    payload = _b64url({"roles": ["SRE.Viewer"], "oid": "00000000-oid"})
    p = auth.parse_principal_from_token(f"{header}.{payload}.sig")
    assert p.identity == "00000000-oid"


@pytest.mark.unit
def test_parse_token_without_identity_is_none():
    header = _b64url({"alg": "none"})
    payload = _b64url({"roles": ["SRE.Viewer"]})  # no identity claim
    assert auth.parse_principal_from_token(f"{header}.{payload}.sig") is None


@pytest.mark.unit
def test_parse_token_malformed_is_none():
    assert auth.parse_principal_from_token("not-a-jwt") is None
    assert auth.parse_principal_from_token(None) is None


@pytest.mark.unit
def test_extract_token_from_supported_headers():
    assert auth._extract_token({"authorization": "Bearer abc"}) == "abc"
    assert auth._extract_token({"x-forwarded-access-token": "xyz"}) == "xyz"
    assert auth._extract_token({"x-auth-request-access-token": "qrs"}) == "qrs"
    # Authorization wins (ID token carries the app roles).
    assert auth._extract_token(
        {"authorization": "Bearer id", "x-forwarded-access-token": "acc"}
    ) == "id"
    assert auth._extract_token({}) is None


# --------------------------------------------------------------------------- #
# Integration: RBAC via bearer under production
# --------------------------------------------------------------------------- #

@pytest.fixture
def client(service, incident_index, step_events):
    app = create_app(service=service, incident_index=incident_index, step_events=step_events)
    with TestClient(app) as c:
        yield c


@pytest.mark.integration
def test_bearer_viewer_reads_but_cannot_approve(client, production_settings):
    viewer = {"authorization": f"Bearer {make_jwt(roles=['SRE.Viewer'])}"}
    assert client.get("/api/incidents", headers=viewer).status_code == 200
    r = client.post("/api/incidents/sre-x/approval", json={"approved": True}, headers=viewer)
    assert r.status_code == 403


@pytest.mark.integration
def test_bearer_approver_is_allowed_through_the_gate(client, production_settings):
    approver = {"x-forwarded-access-token": make_jwt(roles=["SRE.Approver"], identity="ops@corp")}
    # Unknown incident -> graceful 200 (not 403); proves the approver passed
    # both the role gate and the verified-identity check (bearer => verified).
    r = client.post("/api/incidents/does-not-exist/approval",
                    json={"approved": True}, headers=approver)
    assert r.status_code == 200
    assert r.json()["status"] == "unknown_or_not_pending"


@pytest.mark.integration
def test_no_token_is_401_in_prod(client, production_settings):
    assert client.get("/api/incidents").status_code == 401


@pytest.mark.integration
def test_bearer_mode_ignores_easyauth_header(client, production_settings, monkeypatch):
    monkeypatch.setattr(production_settings, "webapi_auth_mode", "bearer")
    # An Easy Auth header must be ignored when the mode is bearer-only.
    easyauth = {"x-ms-client-principal": base64.b64encode(
        json.dumps({"claims": [{"typ": "roles", "val": "SRE.Viewer"},
                               {"typ": "preferred_username", "val": "x@corp"}]}).encode()
    ).decode()}
    assert client.get("/api/incidents", headers=easyauth).status_code == 401
