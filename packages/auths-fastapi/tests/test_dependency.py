"""Dependency + challenge-store tests over a FAKE verifier and the REAL `ChallengeStore`.

The fake verifier runs the SAME wire parse and consumes the SAME real challenge store as the
production path, so replay, wrong-audience, and expiry are genuinely exercised — no native
binding is installed. Each test reconfigures the dependency's verifier so the module-level
holder is deterministic.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from auths_fastapi import (
    Capability,
    ChallengeStore,
    Principal,
    PresentationDenied,
    auths_principal,
    challenge_router,
    configure,
    configure_mint,
    parse_presentation_header,
)

AUDIENCE = "api.example.com"
ISSUER = "did:keri:Eissuer"
SUBJECT = "did:keri:Esubject"


def _wire_token(audience: str, nonce: str) -> str:
    """Build a base64url(JSON) challenge-bound presentation token (signature is opaque here)."""
    document = {
        "credential_said": "ECredSAID",
        "audience": audience,
        "binding": {"challenge": {"nonce": nonce}},
        "signature_b64": base64.urlsafe_b64encode(b"\x09" * 64).rstrip(b"=").decode(),
    }
    raw = json.dumps(document).encode()
    return "Auths-Presentation " + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeVerifier:
    """A fake `PresentationVerifier` that exercises the REAL challenge store.

    It parses the wire token, consumes the challenge against the injected store (so replay,
    wrong-audience, and expiry are real), and returns a `Principal` carrying fixed caps. Only
    the cryptographic signature check is stubbed out.

    Args:
    * `challenges`: The shared real challenge store.
    * `caps`: The capabilities the returned principal carries.
    """

    def __init__(self, challenges: ChallengeStore, caps: tuple[Capability, ...]) -> None:
        self._challenges = challenges
        self._caps = caps

    def verify(self, wire_token: str, now: datetime) -> Principal:
        try:
            wire = parse_presentation_header(wire_token)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise PresentationDenied(400, "malformed presentation") from exc
        if not self._challenges.consume(wire.audience, wire.nonce, now):
            raise PresentationDenied(401, "challenge replayed, expired, or unknown")
        return Principal(issuer=ISSUER, subject=SUBJECT, caps=self._caps)


def _build_app(store: ChallengeStore, caps: tuple[Capability, ...]) -> FastAPI:
    """A minimal app: configure the fake verifier + mint route, guard `POST /v1/deploy`."""
    configure(FakeVerifier(store, caps))
    configure_mint(store, AUDIENCE)
    app = FastAPI()
    app.include_router(challenge_router)

    @app.post("/v1/deploy")
    async def deploy(
        principal: Principal = Depends(auths_principal(Capability("deploy:prod"))),
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    return app


@pytest.fixture
def store() -> ChallengeStore:
    return ChallengeStore(max_live=8)


def _mint(client: TestClient) -> str:
    """Mint a nonce via the real route and return it."""
    response = client.get("/v1/auth/challenge")
    assert response.status_code == 200
    return response.json()["nonce"]


def test_valid_presentation_returns_200_and_principal(store: ChallengeStore) -> None:
    client = TestClient(_build_app(store, (Capability("deploy:prod"),)))
    nonce = _mint(client)
    response = client.post("/v1/deploy", headers={"Authorization": _wire_token(AUDIENCE, nonce)})
    assert response.status_code == 200
    assert response.json() == {"subject": SUBJECT}


def test_replay_is_rejected_401(store: ChallengeStore) -> None:
    client = TestClient(_build_app(store, (Capability("deploy:prod"),)))
    nonce = _mint(client)
    header = {"Authorization": _wire_token(AUDIENCE, nonce)}
    assert client.post("/v1/deploy", headers=header).status_code == 200
    replay = client.post("/v1/deploy", headers=header)
    assert replay.status_code == 401
    assert replay.headers["WWW-Authenticate"] == "Bearer"


def test_wrong_audience_is_rejected_401(store: ChallengeStore) -> None:
    client = TestClient(_build_app(store, (Capability("deploy:prod"),)))
    nonce = _mint(client)
    token = _wire_token("evil.example.com", nonce)
    response = client.post("/v1/deploy", headers={"Authorization": token})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_expired_challenge_is_rejected_401(store: ChallengeStore) -> None:
    short = ChallengeStore(max_live=8, ttl=timedelta(seconds=0))
    client = TestClient(_build_app(short, (Capability("deploy:prod"),)))
    nonce = _mint(client)
    response = client.post("/v1/deploy", headers={"Authorization": _wire_token(AUDIENCE, nonce)})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_missing_capability_is_rejected_403(store: ChallengeStore) -> None:
    client = TestClient(_build_app(store, (Capability("read:logs"),)))
    nonce = _mint(client)
    response = client.post("/v1/deploy", headers={"Authorization": _wire_token(AUDIENCE, nonce)})
    assert response.status_code == 403


def test_missing_header_is_rejected_401(store: ChallengeStore) -> None:
    client = TestClient(_build_app(store, (Capability("deploy:prod"),)))
    response = client.post("/v1/deploy")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_store_full_returns_503() -> None:
    full = ChallengeStore(max_live=1)
    client = TestClient(_build_app(full, (Capability("deploy:prod"),)))
    assert client.get("/v1/auth/challenge").status_code == 200
    assert client.get("/v1/auth/challenge").status_code == 503


def test_challenge_mint_round_trip(store: ChallengeStore) -> None:
    client = TestClient(_build_app(store, (Capability("deploy:prod"),)))
    before = store.live_count()
    body = client.get("/v1/auth/challenge").json()
    assert "nonce" in body and "not_after" in body
    assert store.live_count() == before + 1


def test_router_level_guard_vs_unguarded(store: ChallengeStore) -> None:
    configure(FakeVerifier(store, (Capability("admin:read"),)))
    configure_mint(store, AUDIENCE)
    app = FastAPI()
    app.include_router(challenge_router)

    guarded = APIRouter(
        prefix="/v1/admin",
        dependencies=[Depends(auths_principal(Capability("admin:read")))],
    )

    @guarded.get("/status")
    async def admin_status() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(guarded)

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    client = TestClient(app)

    assert client.get("/v1/health").status_code == 200

    assert client.get("/v1/admin/status").status_code == 401

    nonce = _mint(client)
    token = _wire_token(AUDIENCE, nonce)
    assert client.get("/v1/admin/status", headers={"Authorization": token}).status_code == 200
