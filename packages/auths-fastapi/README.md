# auths-fastapi

A FastAPI dependency that authenticates an `Auths-Presentation` request and yields a typed
`Principal`, or raises `HTTPException`. It is the Python counterpart of the Axum reference
middleware in `crates/auths-api/src/rp_auth.rs`: an injectable verifier, a real single-use
challenge store, a verdict→status mapping, and a dependency that hands a handler a `Principal`
**only on success**.

## Scope

- **First-party only.** The relying party trusts credentials issued under DIDs it has pinned
  in `pinned_roots` (the `.auths/roots` model — DID-only; capabilities come from the verified
  credential, never the request). There is no federation or third-party issuer discovery.
- **Challenge mode is the default.** The interactive `GET /v1/auth/challenge` → single-use
  nonce → present flow is the v1 path and the one this package mints. A TTL binding is opt-in
  (non-interactive, no store entry to consume); within its TTL a TTL presentation can be
  replayed, so prefer the challenge binding unless you have a reason not to.
- **Single process.** The bundled `ChallengeStore` lives in one process's heap. Behind a load
  balancer fronting N nodes a nonce minted on one node is unknown to another, and the
  single-use guarantee holds only per node — supply a shared store backend for multi-node.

## Security notes

- The nonce and signature are **never logged** by this package; do not log the `Authorization`
  header in your own middleware either.
- 401 responses carry `WWW-Authenticate: Bearer` so generic clients treat them as a standard
  auth challenge.
- The expected audience is the relying party's **configured** audience, not the wire header.

## Install

```bash
pip install auths-fastapi            # the dependency + challenge store (fake-verifier testable)
pip install "auths-fastapi[native]"  # + the `auths` binding for the production verifier
pip install "auths-fastapi[client]"  # + httpx for fetch_challenge
```

## Usage

```python
from fastapi import Depends, FastAPI
from auths_fastapi import (
    Capability, ChallengeStore, KeriPresentationVerifier, Principal,
    PresentationInputs, auths_principal, challenge_router, configure, configure_mint,
)

AUDIENCE = "api.example.com"
store = ChallengeStore(max_live=10_000)

def load_inputs(credential_said: str) -> PresentationInputs:
    # Resolve the credential SAID to its KEL/TEL inputs from your registry.
    ...

configure(KeriPresentationVerifier(
    audience=AUDIENCE,
    challenges=store,
    load_inputs=load_inputs,
    pinned_roots=frozenset({"did:keri:Eroot"}),
))
configure_mint(store, AUDIENCE)

app = FastAPI()
app.include_router(challenge_router)  # GET /v1/auth/challenge

@app.post("/v1/deploy")
async def deploy(principal: Principal = Depends(auths_principal(Capability("deploy:prod")))):
    return {"deployed_by": principal.subject}
```

### Guard a whole group

```python
from fastapi import APIRouter, Depends

admin = APIRouter(
    prefix="/v1/admin",
    dependencies=[Depends(auths_principal(Capability("admin:read")))],
)

@admin.get("/status")          # protected by the router-level dependency; no Principal needed
async def admin_status():
    return {"status": "ok"}
```

A route that does **not** depend on `auths_principal(...)` receives no `Principal` and is
unauthenticated by construction.

### Client flow

```python
from auths_fastapi import fetch_challenge

issued = fetch_challenge("https://api.example.com/v1/auth/challenge")
# sign over issued.nonce, build the Auths-Presentation token, send it in Authorization.
```

## Status mapping

| Outcome                                                              | Status | Header                       |
| ------------------------------------------------------------------- | ------ | ---------------------------- |
| Verified, capability satisfied                                      | 200    | —                            |
| Missing/malformed header, expired, revoked, wrong audience, replay, holder-not-current, unpinned issuer | 401 | `WWW-Authenticate: Bearer` |
| Authenticated but missing the required capability                   | 403    | —                            |
| Challenge store at capacity                                         | 503    | —                            |

## Testing without the native binding

The crypto verify step is injected behind the `PresentationVerifier` protocol. Tests supply a
fake verifier over the **real** `ChallengeStore`, so replay/audience/expiry are genuinely
exercised with no binding installed (see `tests/test_dependency.py`). Run `pytest`.
