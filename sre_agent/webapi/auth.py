"""
Entra (Easy Auth) RBAC for the web API.

App Service Authentication terminates the login and injects the verified
identity as the base64 `X-MS-CLIENT-PRINCIPAL` header. We parse it once into
a `Principal` (identity + Entra app roles) and gate every route on it:

  - `SRE.Viewer`   — read the dashboard, incidents, timelines.
  - `SRE.Approver` — additionally approve/reject a paused mitigation.

Enforcement is active in production (`settings.is_production`), which closes
today's open GET-status endpoint. Outside production the API is permissive so
`npm run dev` needs no auth proxy: a missing principal becomes a local dev
identity carrying both roles. A principal that IS present is always honored as
sent, so tests exercise the real RBAC matrix via the production settings.
"""
import base64
import json
import logging
from dataclasses import dataclass
from typing import FrozenSet, Optional

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


def current_principal(request: Request) -> Optional[Principal]:
    """Resolve the request's principal, applying the dev fallback off-prod."""
    principal = parse_principal(request.headers.get(PRINCIPAL_HEADER))
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
