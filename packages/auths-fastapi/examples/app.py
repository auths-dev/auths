"""Example FastAPI app guarded by `auths-fastapi`.

Wires the production `KeriPresentationVerifier` once at startup, then shows three patterns:
* a route-level guard that receives a typed `Principal` (`POST /v1/deploy`);
* a router-level guard protecting a whole group (`/v1/admin/*`) without a per-handler
  `Principal` reference;
* an unguarded route that has no `Principal` reference at all.

`load_inputs` is the app's adapter from a credential SAID to its registry-resolved KEL/TEL
inputs — here a stub that raises (replace with a real registry lookup). `pinned_roots` is the
`.auths/roots` DID allowlist (DID-only; capabilities come from the verified credential).

Run with: `uvicorn examples.app:app`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI

from auths_fastapi import (
    Capability,
    ChallengeStore,
    KeriPresentationVerifier,
    Principal,
    PresentationInputs,
    auths_principal,
    challenge_router,
    configure,
    configure_mint,
)

AUDIENCE = "api.example.com"
PINNED_ROOTS = frozenset({"did:keri:Eexample-root-aid"})

store = ChallengeStore(max_live=10_000)


def load_inputs(credential_said: str) -> PresentationInputs:
    """Resolve a credential SAID to its KEL/TEL inputs (stub — wire to your registry).

    Args:
    * `credential_said`: The presented credential SAID to resolve.
    """
    raise LookupError(f"no registry adapter wired for {credential_said}")


configure(
    KeriPresentationVerifier(
        audience=AUDIENCE,
        challenges=store,
        load_inputs=load_inputs,
        pinned_roots=PINNED_ROOTS,
    )
)
configure_mint(store, AUDIENCE)

app = FastAPI(title="auths-fastapi example")
app.include_router(challenge_router)


@app.post("/v1/deploy")
async def deploy(
    principal: Principal = Depends(auths_principal(Capability("deploy:prod"))),
) -> dict[str, str]:
    """A route-level guarded handler — reachable only with a verified `deploy:prod` principal."""
    return {"deployed_by": principal.subject}


# Router-level guard: every route on this group requires `admin:read`, and the handlers need
# no `Principal` parameter to be protected.
admin = APIRouter(
    prefix="/v1/admin",
    dependencies=[Depends(auths_principal(Capability("admin:read")))],
)


@admin.get("/status")
async def admin_status() -> dict[str, str]:
    """Guarded purely by the router-level dependency (no `Principal` reference here)."""
    return {"status": "ok"}


app.include_router(admin)


@app.get("/v1/health")
async def health() -> dict[str, str]:
    """An unguarded route — no dependency, no `Principal`, open to everyone."""
    return {"status": "ok"}
