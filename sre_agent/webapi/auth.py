"""
Entra RBAC for the web API — platform-independent.

The verified caller identity reaches the API one of two ways, depending on
where it runs; both resolve to the same `Principal` (identity + Entra app
roles) and the same gates:

  - **Easy Auth** (App Service / ASE): the platform injects the base64
    `X-MS-CLIENT-PRINCIPAL` header.
  - **Bearer / oauth2-proxy** (AKS / any k8s ingress): a reverse proxy
    terminates the Entra OIDC login and forwards the token as
    `Authorization: Bearer <jwt>` (or `X-Forwarded-Access-Token`). We read
    the `roles` + identity claims from the JWT — the SAME claim names Easy
    Auth surfaces — so the RBAC logic below is identical on both platforms.

Roles:
  - `SRE.Viewer`   — read the dashboard, incidents, timelines.
  - `SRE.Approver` — additionally approve/reject a paused mitigation.

`settings.webapi_auth_mode` selects the source ("easyauth" | "bearer" |
"auto", default auto). The bearer path trusts oauth2-proxy's upstream
validation by default; set `webapi_jwt_verify=true` (with the JWKS/issuer/
audience settings) for in-app signature verification too.

Enforcement is active in production (`settings.is_production`). Outside
production the API is permissive so `npm run dev` needs no auth proxy: a
missing principal becomes a local dev identity carrying both roles. A
principal that IS present is always honored as sent, so tests exercise the
real RBAC matrix via the production settings.
"""
import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional

from fastapi import Depends, HTTPException, Request, status

from sre_agent.config import get_settings

logger = logging.getLogger(__name__)

VIEWER_ROLE = "SRE.Viewer"
APPROVER_ROLE = "SRE.Approver"

# Entra emits app-role membership under "roles"; the WS-Fed role claim URI is
# accepted too for federated setups.
_ROLE_CLAIM_TYPES = (
    "roles",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
)
_IDENTITY_CLAIM_TYPES = (
    "preferred_username",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "name",
)

PRINCIPAL_HEADER = "x-ms-client-principal"

# JWT (bearer / oauth2-proxy) claim names for the same fields.
_JWT_IDENTITY_CLAIMS = ("preferred_username", "upn", "email", "unique_name", "name", "oid", "sub")
# Where a fronting proxy puts the forwarded token. oauth2-proxy in
# reverse-proxy mode sets X-Forwarded-Access-Token; the nginx auth_request
# pattern sets X-Auth-Request-Access-Token; --pass-authorization-header puts
# the ID token in Authorization (preferred — it carries the app roles).
_FORWARDED_TOKEN_HEADERS = ("x-forwarded-access-token", "x-auth-request-access-token")

# Warn once (not per request) if we're decoding tokens without verifying them.
_UNVERIFIED_WARNED = False


@dataclass(frozen=True)
class Principal:
    identity: str
    provider: str
    roles: FrozenSet[str]
    verified: bool  # True only when built from a real Easy Auth header

    def has_role(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)


def _dev_principal() -> Principal:
    """Local-dev identity: full access, but never counts as verified."""
    return Principal(
        identity="dev@localhost",
        provider="dev",
        roles=frozenset({VIEWER_ROLE, APPROVER_ROLE}),
        verified=False,
    )


def parse_principal(header_value: Optional[str]) -> Optional[Principal]:
    """Decode the X-MS-CLIENT-PRINCIPAL header into a Principal (or None)."""
    if not header_value:
        return None
    try:
        decoded = json.loads(base64.b64decode(header_value).decode("utf-8"))
    except Exception:
        logger.warning("Malformed X-MS-CLIENT-PRINCIPAL header")
        return None

    roles, identity = set(), None
    for claim in decoded.get("claims", []):
        typ, val = claim.get("typ"), claim.get("val")
        if typ in _ROLE_CLAIM_TYPES and val:
            roles.add(val)
        if identity is None and typ in _IDENTITY_CLAIM_TYPES and val:
            identity = val
    identity = identity or decoded.get("userId")
    if not identity:
        return None
    return Principal(
        identity=identity,
        provider=decoded.get("auth_typ", "aad"),
        roles=frozenset(roles),
        verified=True,
    )


# --------------------------------------------------------------------------- #
# Bearer / oauth2-proxy path (AKS and any k8s ingress)
# --------------------------------------------------------------------------- #

def _b64url_json(segment: str) -> Dict[str, Any]:
    """Decode one base64url JWT segment (payload) into a dict."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding).decode("utf-8"))


def _decode_token_claims(token: str) -> Optional[Dict[str, Any]]:
    """Return a JWT's claims.

    When `webapi_jwt_verify` is set (with JWKS + audience), the signature,
    audience, issuer, and expiry are verified with PyJWT. Otherwise the
    payload is decoded WITHOUT verification — safe only because a reverse
    proxy (oauth2-proxy) already validated the token upstream and the API is
    reachable only through it; a one-time warning records that trust.
    """
    global _UNVERIFIED_WARNED
    settings = get_settings()
    if settings.webapi_jwt_verify:
        return _verify_token_claims(token, settings)
    if not _UNVERIFIED_WARNED:
        logger.warning(
            "Bearer tokens are decoded WITHOUT signature verification "
            "(trusting the upstream oauth2-proxy). Set SRE_AGENT_WEBAPI_JWT_VERIFY=true "
            "with JWKS/issuer/audience for in-app verification."
        )
        _UNVERIFIED_WARNED = True
    try:
        return _b64url_json(token.split(".")[1])
    except Exception:
        logger.warning("Malformed bearer token; ignoring")
        return None


def _verify_token_claims(token: str, settings) -> Optional[Dict[str, Any]]:
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError:
        logger.error(
            "webapi_jwt_verify is on but PyJWT is not installed "
            "(pip install 'pyjwt[crypto]'); rejecting the token"
        )
        return None
    if not settings.webapi_jwt_jwks_url:
        logger.error("webapi_jwt_verify is on but webapi_jwt_jwks_url is unset")
        return None
    try:
        signing_key = PyJWKClient(settings.webapi_jwt_jwks_url).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.webapi_jwt_audience,
            issuer=settings.webapi_jwt_issuer,
            options={"verify_aud": bool(settings.webapi_jwt_audience),
                     "verify_iss": bool(settings.webapi_jwt_issuer)},
        )
    except Exception as exc:  # invalid signature / expired / wrong aud
        logger.warning("Bearer token failed verification: %s", exc)
        return None


def _extract_token(headers) -> Optional[str]:
    """Pull the JWT from Authorization: Bearer or a proxy-forwarded header.

    Authorization is checked first: with `--pass-authorization-header`,
    oauth2-proxy puts the ID token there, and the ID token reliably carries
    the Entra app roles.
    """
    authz = headers.get("authorization")
    if authz and authz.lower().startswith("bearer "):
        return authz[7:].strip()
    for header in _FORWARDED_TOKEN_HEADERS:
        forwarded = headers.get(header)
        if forwarded:
            return forwarded.strip()
    return None


def parse_principal_from_token(token: Optional[str]) -> Optional[Principal]:
    """Build a Principal from a forwarded Entra JWT (or None)."""
    if not token:
        return None
    claims = _decode_token_claims(token)
    if not claims:
        return None
    roles_claim = claims.get("roles")
    if isinstance(roles_claim, str):
        roles: List[str] = [roles_claim]
    else:
        roles = list(roles_claim or [])
    identity = next((claims[c] for c in _JWT_IDENTITY_CLAIMS if claims.get(c)), None)
    if not identity:
        return None
    return Principal(
        identity=str(identity),
        provider="aad",
        roles=frozenset(roles),
        verified=True,
    )


def current_principal(request: Request) -> Optional[Principal]:
    """Resolve the request's principal, applying the dev fallback off-prod.

    Source order follows `webapi_auth_mode`: easyauth header, forwarded
    bearer token, or (auto) both. Falls back to a dev identity off-prod.
    """
    mode = get_settings().webapi_auth_mode.strip().lower()

    if mode in ("easyauth", "auto"):
        principal = parse_principal(request.headers.get(PRINCIPAL_HEADER))
        if principal is not None:
            return principal

    if mode in ("bearer", "auto"):
        principal = parse_principal_from_token(_extract_token(request.headers))
        if principal is not None:
            return principal

    if get_settings().is_production:
        return None
    return _dev_principal()


def require_viewer(
    principal: Optional[Principal] = Depends(current_principal),
) -> Principal:
    """Gate reads. 401 without a principal; 403 without a read role (prod)."""
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    if get_settings().is_production and not principal.has_role(VIEWER_ROLE, APPROVER_ROLE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires the SRE.Viewer role")
    return principal


def require_approver(
    principal: Optional[Principal] = Depends(current_principal),
) -> Principal:
    """Gate approvals. 401 without a principal; 403 without the approver role."""
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    if get_settings().is_production and not principal.has_role(APPROVER_ROLE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires the SRE.Approver role")
    return principal
