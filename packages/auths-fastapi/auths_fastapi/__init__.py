"""FastAPI middleware for Auths-Presentation request authentication.

Public surface:
* `auths_principal(capability)` — the FastAPI dependency yielding a verified `Principal`.
* `configure` — install the process-wide `PresentationVerifier`.
* `Principal` / `Capability` — the typed identity + authority models.
* `ChallengeStore` / `IssuedChallenge` / `StoreFull` — the single-use challenge store.
* `PresentationVerifier` (Protocol), `KeriPresentationVerifier`, `PresentationInputs`,
  `PresentationDenied` — the injectable verify seam and its production impl.
* `challenge_router` / `configure_mint` / `fetch_challenge` — the mint route + client helper.

First-party only: the relying party trusts credentials issued under DIDs it has pinned
(`pinned_roots`); there is no federation. The interactive challenge binding is the default.
"""

from .challenge_route import configure_mint, fetch_challenge
from .challenge_route import router as challenge_router
from .challenge_store import (
    DEFAULT_CHALLENGE_TTL,
    NONCE_LEN,
    ChallengeStore,
    IssuedChallenge,
    StoreFull,
)
from .dependency import auths_principal, configure
from .models import Capability, Principal
from .verifier import (
    KeriPresentationVerifier,
    LoadInputs,
    PresentationDenied,
    PresentationInputs,
    PresentationVerifier,
    WirePresentation,
    parse_presentation_header,
    parse_presentation_token,
)

__all__ = [
    "auths_principal",
    "configure",
    "Principal",
    "Capability",
    "ChallengeStore",
    "IssuedChallenge",
    "StoreFull",
    "NONCE_LEN",
    "DEFAULT_CHALLENGE_TTL",
    "PresentationVerifier",
    "KeriPresentationVerifier",
    "PresentationInputs",
    "PresentationDenied",
    "LoadInputs",
    "WirePresentation",
    "parse_presentation_header",
    "parse_presentation_token",
    "challenge_router",
    "configure_mint",
    "fetch_challenge",
]
