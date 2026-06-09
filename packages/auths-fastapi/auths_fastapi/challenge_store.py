"""Single-use challenge store for the interactive presentation path.

Mirrors `auths_rp::challenge::InMemoryChallengeStore`: a CSPRNG nonce minted by `issue` is
bound to an audience and consumed exactly once by `consume` (remove-on-read), giving genuine
single-use replay protection with no global seen-cache. The store is bounded (`max_live`) and
TTL-pruned so a `/v1/auth/challenge` flood cannot exhaust memory; at capacity `issue` raises
`StoreFull` rather than evicting a live nonce. `consume` runs after the caller's cheap
structural checks, so a third party cannot burn a legitimate client's nonce.

The clock is injected (`now: datetime`) — there is no hidden wall-clock read; the HTTP
boundary samples the clock and passes it down, matching the Rust clock-injection rule.
"""

from __future__ import annotations

import base64
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

NONCE_LEN = 32
"""The fixed nonce width, in bytes (matches `auths_rp::NONCE_LEN`)."""

DEFAULT_CHALLENGE_TTL = timedelta(seconds=120)
"""The default TTL ceiling for a minted challenge (matches `DEFAULT_CHALLENGE_TTL_SECS`)."""


class StoreFull(Exception):
    """The challenge store is at capacity — retry shortly (maps to HTTP 503)."""


@dataclass(frozen=True)
class IssuedChallenge:
    """A freshly minted challenge handed to the client.

    Args:
    * `nonce`: The base64url (no-pad) single-use nonce the client signs over.
    * `not_after`: The instant after which the challenge is no longer live.
    """

    nonce: str
    not_after: datetime


def _encode_nonce(raw: bytes) -> str:
    """Encode raw nonce bytes as base64url without padding (the wire form)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class ChallengeStore:
    """A bounded, TTL-pruned, single-use challenge store.

    Single-process only (an in-heap map). A multi-node deployment behind a load balancer
    must supply a shared backend so a nonce minted on one node is consumable on another and
    the remove-on-read guarantee holds across nodes; see the Rust load-balancer caveat.

    Args:
    * `max_live`: The maximum number of live challenges before `issue` raises `StoreFull`.
    * `ttl`: The lifetime of each minted challenge (defaults to 120s).

    Usage:
    ```python
    store = ChallengeStore(max_live=10_000)
    issued = store.issue("api.example.com", now)
    assert store.consume("api.example.com", issued.nonce, now)
    ```
    """

    def __init__(self, max_live: int, ttl: timedelta = DEFAULT_CHALLENGE_TTL) -> None:
        self._max_live = max_live
        self._ttl = ttl
        self._lock = threading.Lock()
        self._live: dict[tuple[str, str], datetime] = {}

    def issue(self, audience: str, now: datetime) -> IssuedChallenge:
        """Mint a fresh single-use challenge bound to `audience`.

        Prunes expired entries first; at capacity raises `StoreFull` rather than evicting a
        live nonce.

        Args:
        * `audience`: The relying party the presentation must bind to.
        * `now`: The current time, injected at the boundary.
        """
        nonce = _encode_nonce(secrets.token_bytes(NONCE_LEN))
        not_after = now + self._ttl
        with self._lock:
            self._prune(now)
            if len(self._live) >= self._max_live:
                raise StoreFull
            self._live[(audience, nonce)] = not_after
        return IssuedChallenge(nonce=nonce, not_after=not_after)

    def consume(self, audience: str, nonce: str, now: datetime) -> bool:
        """Consume a challenge once (remove-on-read), returning True exactly once.

        A second consume of the same nonce, an expired one, a wrong-audience one, or an
        unknown one all return False — the single-use replay protection. A wrong audience
        does not burn the nonce, so a third party cannot consume a legitimate client's.

        Args:
        * `audience`: The audience the client claims to bind to.
        * `nonce`: The base64url nonce the client presented.
        * `now`: The current time, injected at the boundary.
        """
        key = (audience, nonce)
        with self._lock:
            not_after = self._live.pop(key, None)
            return not_after is not None and not_after > now

    def live_count(self) -> int:
        """The number of currently-stored challenges (diagnostics / tests)."""
        with self._lock:
            return len(self._live)

    def _prune(self, now: datetime) -> None:
        """Drop every entry whose expiry has passed (caller holds the lock)."""
        expired = [key for key, not_after in self._live.items() if not_after <= now]
        for key in expired:
            del self._live[key]
