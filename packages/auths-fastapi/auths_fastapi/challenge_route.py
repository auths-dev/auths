"""The `/v1/auth/challenge` mint route and a client-side fetch helper.

Mirrors `auths_api::rp_auth::challenge_handler`: `GET /v1/auth/challenge` mints a fresh
single-use nonce bound to the configured audience and returns `{nonce, not_after}`; at
capacity it returns 503 rather than evicting a live nonce. `fetch_challenge` is the client
counterpart (httpx) that fetches one for signing.

The store is configured once via `configure_mint(...)`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from .challenge_store import ChallengeStore, IssuedChallenge, StoreFull


class _MintConfig:
    """The once-configured store + audience the mint route uses."""

    store: ChallengeStore | None = None
    audience: str | None = None


def configure_mint(store: ChallengeStore, audience: str) -> None:
    """Install the store + audience the `/v1/auth/challenge` route mints against.

    Args:
    * `store`: The single-use challenge store (shared with the verifier).
    * `audience`: This relying party's canonical audience.
    """
    _MintConfig.store = store
    _MintConfig.audience = audience


router = APIRouter()
"""The mint router; include with `app.include_router(challenge_router)`."""


@router.get("/v1/auth/challenge")
async def challenge_handler() -> dict[str, str]:
    """Mint a fresh CSPRNG nonce bound to this RP's audience.

    Returns `{nonce, not_after}`; raises 503 when the bounded store is full and 500 if the
    mint route was not configured.
    """
    store = _MintConfig.store
    audience = _MintConfig.audience
    if store is None or audience is None:
        raise HTTPException(status_code=500, detail="challenge mint not configured")
    try:
        issued = store.issue(audience, datetime.now(timezone.utc))
    except StoreFull as exc:
        raise HTTPException(status_code=503, detail="challenge store full") from exc
    return {"nonce": issued.nonce, "not_after": issued.not_after.isoformat()}


def fetch_challenge(url: str) -> IssuedChallenge:
    """Client helper: GET a challenge from `url` and parse it into an `IssuedChallenge`.

    Requires the `client` extra (httpx). Raises on a non-200 (e.g. 503 when the store is
    full).

    Args:
    * `url`: The full `/v1/auth/challenge` URL.

    Usage:
    ```python
    issued = fetch_challenge("https://api.example.com/v1/auth/challenge")
    ```
    """
    import httpx

    response = httpx.get(url)
    response.raise_for_status()
    body = response.json()
    return IssuedChallenge(
        nonce=body["nonce"],
        not_after=datetime.fromisoformat(body["not_after"]),
    )
