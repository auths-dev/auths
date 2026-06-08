"""The FastAPI dependency: `Auths-Presentation` header → typed `Principal` or `HTTPException`.

Mirrors `auths_api::rp_auth`: a dependency factory `auths_principal(capability)` reads the
`Authorization` header, calls the injected `PresentationVerifier` (which consumes the
single-use challenge), enforces the capability, and RETURNS a `Principal` only on success. A
route that does not depend on it never receives a `Principal`, and the same dependency can
guard a whole `APIRouter` group via `dependencies=[Depends(...)]`.

Status mapping: malformed/missing/expired/revoked/wrong-audience/holder-not-current → 401
(with a `WWW-Authenticate: Bearer` header); missing capability → 403; store full → 503. The
nonce and signature are never logged.

The verifier is configured once via `configure(...)` (closed over by the factory) so handlers
stay declarative; `auths_principal` reads it from a module-level holder.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

from fastapi import HTTPException, Request

from .models import Capability, Principal
from .verifier import PresentationDenied, PresentationVerifier

# 401 responses MUST advertise the accepted scheme. We use `Bearer` (not the custom
# `Auths-Presentation`) so generic HTTP clients/proxies treat it as a standard challenge,
# matching the reference middleware's WWW-Authenticate contract.
_WWW_AUTHENTICATE = {"WWW-Authenticate": "Bearer"}


class _Config:
    """The once-configured verifier the factory closes over (set via `configure`)."""

    verifier: PresentationVerifier | None = None


def configure(verifier: PresentationVerifier) -> None:
    """Install the process-wide presentation verifier the dependency uses.

    Call once at app startup with either the production `KeriPresentationVerifier` or a fake
    (tests). All `auths_principal(...)` dependencies resolve against this verifier.

    Args:
    * `verifier`: The verifier (production or test fake) implementing `PresentationVerifier`.

    Usage:
    ```python
    configure(KeriPresentationVerifier(audience, store, load_inputs, pinned_roots))
    ```
    """
    _Config.verifier = verifier


def _now() -> datetime:
    """Sample the wall clock at the HTTP boundary (the presentation-layer clock read)."""
    return datetime.now(timezone.utc)


def _authenticate(request: Request, required: Capability | None) -> Principal:
    """Run the header → verifier → capability pipeline, raising `HTTPException` on failure."""
    verifier = _Config.verifier
    if verifier is None:
        raise HTTPException(status_code=500, detail="auths verifier not configured")

    header = request.headers.get("Authorization")
    if header is None:
        raise HTTPException(
            status_code=401, detail="authentication required", headers=_WWW_AUTHENTICATE
        )

    try:
        principal = verifier.verify(header, _now())
    except PresentationDenied as denied:
        headers = _WWW_AUTHENTICATE if denied.status_code == 401 else None
        raise HTTPException(
            status_code=denied.status_code, detail=denied.detail, headers=headers
        ) from denied

    if required is not None and not principal.authorize(required):
        raise HTTPException(status_code=403, detail="insufficient capability")

    return principal


def auths_principal(
    capability: Capability | None = None,
) -> Callable[[Request], Awaitable[Principal]]:
    """Build a FastAPI dependency yielding a verified `Principal` (or raising `HTTPException`).

    Use at the route level to receive the `Principal`, or at the router level
    (`APIRouter(dependencies=[Depends(auths_principal(cap))])`) to guard a whole group without
    binding the principal into each handler.

    Args:
    * `capability`: The capability the guarded route(s) require; omit to authenticate only.

    Usage:
    ```python
    @app.post("/v1/deploy")
    async def deploy(principal: Principal = Depends(auths_principal(Capability("deploy:prod")))):
        ...
    ```
    """

    async def dependency(request: Request) -> Principal:
        return _authenticate(request, capability)

    return dependency
