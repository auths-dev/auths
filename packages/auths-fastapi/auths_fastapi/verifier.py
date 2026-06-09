"""The injectable verification step: wire token → verified `Principal`.

Mirrors `auths_api::rp_auth::PresentationVerifier`: the crypto check is behind a Protocol so
the production KERI path and the tests share one dependency factory. The production
`KeriPresentationVerifier` parses the wire token, consumes the single-use challenge against
the REAL store, loads the KEL/TEL inputs (app-supplied), builds the camelCase
`VerifyPresentationRequest` bundle, calls the native `auths.verify_presentation`, enforces
pinned roots, and maps the status to a `Principal` or raises `PresentationDenied`.

Tests inject a fake verifier over the same real `ChallengeStore`, so replay/audience are
genuinely exercised with no native binding installed.

The nonce and signature are never logged here or by callers.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Protocol

from .challenge_store import ChallengeStore
from .models import Capability, Principal


class PresentationDenied(Exception):
    """A presentation was rejected; `status_code` is the HTTP class to surface.

    Args:
    * `status_code`: 400/401/403/503 per the verdict-to-status mapping.
    * `detail`: A coarse, non-sensitive reason (never the nonce or signature).
    """

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class PresentationVerifier(Protocol):
    """Turn a wire token into a verified `Principal`, consuming its challenge.

    The implementation owns the single-use consume so replay protection is enforced in one
    place. It raises `PresentationDenied` on any failure and returns a `Principal` only on a
    fully-valid, pinned-root presentation.
    """

    def verify(self, wire_token: str, now: datetime) -> Principal:
        """Verify `wire_token` as of `now`, consuming its single-use challenge.

        Args:
        * `wire_token`: The base64url(JSON) token from the `Authorization` header.
        * `now`: Verification time, injected at the HTTP boundary.
        """
        ...


@dataclass(frozen=True)
class WirePresentation:
    """The untrusted wire shape decoded from the `Auths-Presentation` token.

    Externally-tagged binding: exactly one of `challenge_nonce` / `ttl_nonce` is set.

    Args:
    * `credential_said`: The presented credential SAID.
    * `audience`: The audience the client claims to bind to.
    * `signature_b64url`: The presentation signature (base64url, no pad).
    * `challenge_nonce`: The interactive-mode nonce (base64url), if challenge-bound.
    * `ttl_nonce`: The TTL-mode nonce (base64url), if TTL-bound.
    * `ttl_not_after`: The TTL-mode expiry (RFC-3339), if TTL-bound.
    """

    credential_said: str
    audience: str
    signature_b64url: str
    challenge_nonce: str | None = None
    ttl_nonce: str | None = None
    ttl_not_after: str | None = None

    @property
    def nonce(self) -> str:
        """The bound nonce regardless of mode (base64url)."""
        value = self.challenge_nonce if self.challenge_nonce is not None else self.ttl_nonce
        if value is None:
            raise ValueError("presentation has no nonce")
        return value


def parse_presentation_token(token: str) -> WirePresentation:
    """Decode a base64url(JSON) presentation token into a `WirePresentation`.

    Raises `ValueError` on any structural problem; the caller maps that to HTTP 400/401.
    The token is never logged.

    Args:
    * `token`: The base64url(JSON) value after the `Auths-Presentation ` scheme.
    """
    raw = base64.urlsafe_b64decode(_pad(token))
    document = json.loads(raw)
    binding = document["binding"]
    if "challenge" in binding:
        return WirePresentation(
            credential_said=document["credential_said"],
            audience=document["audience"],
            signature_b64url=document["signature_b64"],
            challenge_nonce=binding["challenge"]["nonce"],
        )
    if "ttl" in binding:
        ttl = binding["ttl"]
        return WirePresentation(
            credential_said=document["credential_said"],
            audience=document["audience"],
            signature_b64url=document["signature_b64"],
            ttl_nonce=ttl["nonce"],
            ttl_not_after=ttl["not_after"],
        )
    raise ValueError("unknown presentation binding")


def parse_presentation_header(authorization: str) -> WirePresentation:
    """Parse an `Authorization: Auths-Presentation <token>` header value.

    The scheme is case-sensitive and separated by exactly one space. Raises `ValueError`
    (mapped to HTTP 400/401) for a missing/wrong scheme or a malformed token.

    Args:
    * `authorization`: The raw `Authorization` header value.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme != "Auths-Presentation":
        raise ValueError("wrong Authorization scheme")
    if not token.strip():
        raise ValueError("missing presentation token")
    return parse_presentation_token(token.strip())


def _pad(b64url: str) -> str:
    """Restore base64 padding stripped on the wire."""
    return b64url + "=" * (-len(b64url) % 4)


def _b64url_to_standard_b64(b64url: str) -> str:
    """Re-encode a base64url (no-pad) value as standard base64 (the bundle's encoding).

    The wire carries nonce/signature as URL-safe base64 without padding; the native
    `VerifyPresentationRequest` expects standard base64. Decode then re-encode rather than
    char-substituting so an invalid payload is caught here.

    Args:
    * `b64url`: A URL-safe, unpadded base64 string.
    """
    return base64.standard_b64encode(base64.urlsafe_b64decode(_pad(b64url))).decode("ascii")


@dataclass(frozen=True)
class PresentationInputs:
    """The KEL/TEL inputs the app resolves for a credential SAID.

    These are the registry-resolved documents the native verifier needs; the relying party
    supplies them via the `load_inputs` callback so this package stays free of storage/Git.
    Each KEL/TEL entry is a parsed JSON object (the native bundle embeds them inline).

    Args:
    * `credential`: The signed ACDC (`{"acdc": …, "signatureB64": …}`) object.
    * `issuer_kel`: The issuer's key event log events.
    * `subject_kel`: The subject (holder) KEL events.
    * `delegator_kel`: The subject's delegator KEL events (empty if none).
    * `tel`: The credential's transaction event log events.
    * `receipts`: Witness receipts (empty under first-party `warn` policy).
    """

    credential: dict[str, object]
    issuer_kel: list[dict[str, object]]
    subject_kel: list[dict[str, object]]
    delegator_kel: list[dict[str, object]] = field(default_factory=list)
    tel: list[dict[str, object]] = field(default_factory=list)
    receipts: list[dict[str, object]] = field(default_factory=list)


# The app-supplied loader: credential SAID → registry-resolved inputs (raises on not-found).
LoadInputs = Callable[[str], PresentationInputs]


# Status strings on the native `PresentationStatus` enum that this module maps to HTTP.
_STATUS_TO_HTTP = {
    "VALID": 200,
    "HOLDER_NOT_CURRENT_KEY": 401,
    "WRONG_AUDIENCE": 401,
    "NONCE_MISMATCH_OR_CONSUMED": 401,
    "EXPIRED": 401,
    "SUBJECT_KEL_INVALID": 401,
    "CREDENTIAL_NOT_VALID": 401,
    "MALFORMED_REQUEST": 400,
    "INPUT_TOO_LARGE": 400,
    "UNSUPPORTED_SCHEMA_VERSION": 400,
    "UNKNOWN": 401,
}


class KeriPresentationVerifier:
    """Production verifier: native KERI presentation authentication over an app registry.

    Flow (mirrors `authenticate_presentation`): parse the wire token → consume the
    single-use challenge against the real store → `load_inputs(credential_said)` →
    build the camelCase `VerifyPresentationRequest` (re-encoding base64url → standard
    base64) → `auths.verify_presentation(json)` → enforce pinned roots → map the status to a
    `Principal` or raise `PresentationDenied`.

    The expected audience is the relying party's CONFIGURED audience, never the wire header.
    `pinned_roots` is a DID-only allowlist (the `.auths/roots` model): the verified issuer
    (or its delegator root) must be pinned, else 401. Capabilities come from the credential,
    never from the request.

    Args:
    * `audience`: This relying party's canonical audience (the trust source).
    * `challenges`: The single-use challenge store shared with the mint route.
    * `load_inputs`: Resolves a credential SAID to its KEL/TEL inputs (raises if absent).
    * `pinned_roots`: The set of trusted issuer/delegator DIDs (fail-closed if empty).

    Usage:
    ```python
    verifier = KeriPresentationVerifier(
        audience="api.example.com",
        challenges=store,
        load_inputs=resolve_from_registry,
        pinned_roots={"did:keri:Eroot"},
    )
    ```
    """

    def __init__(
        self,
        audience: str,
        challenges: ChallengeStore,
        load_inputs: LoadInputs,
        pinned_roots: frozenset[str],
    ) -> None:
        self._audience = audience
        self._challenges = challenges
        self._load_inputs = load_inputs
        self._pinned_roots = pinned_roots

    def verify(self, wire_token: str, now: datetime) -> Principal:
        try:
            wire = parse_presentation_header(wire_token)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise PresentationDenied(400, "malformed presentation") from exc

        if not self._challenges.consume(wire.audience, wire.nonce, now):
            raise PresentationDenied(401, "challenge replayed, expired, or unknown")

        try:
            inputs = self._load_inputs(wire.credential_said)
        except LookupError as exc:
            raise PresentationDenied(401, "credential could not be resolved") from exc

        request = self._build_request(wire, inputs, now)
        report = _verify_presentation_native(json.dumps(request))
        return self._map_report(report)

    def _build_request(
        self, wire: WirePresentation, inputs: PresentationInputs, now: datetime
    ) -> dict[str, object]:
        """Assemble the camelCase `VerifyPresentationRequest` bundle for the native verifier.

        Wire nonce/signature are base64url (no pad); the bundle wants standard base64, so they
        are re-encoded here. The expected challenge is the configured store's nonce — the same
        value that was just consumed — re-encoded the same way.
        """
        return {
            "schemaVersion": 1,
            "envelope": {
                "credentialSaid": wire.credential_said,
                "audience": wire.audience,
                "binding": {
                    "mode": "challenge",
                    "nonceB64": _b64url_to_standard_b64(wire.nonce),
                },
                "signatureB64": _b64url_to_standard_b64(wire.signature_b64url),
            },
            "credential": inputs.credential,
            "issuerKel": inputs.issuer_kel,
            "subjectKel": inputs.subject_kel,
            "delegatorKel": inputs.delegator_kel,
            "tel": inputs.tel,
            "receipts": inputs.receipts,
            "witnessPolicy": "warn",
            "audience": self._audience,
            "expectedChallengeB64": _b64url_to_standard_b64(wire.nonce),
            "now": now.isoformat(),
        }

    def _map_report(self, report: object) -> Principal:
        """Map a native `PresentationReport` to a `Principal` or raise `PresentationDenied`."""
        status = getattr(report, "status")
        status_name = getattr(status, "name", str(status))
        if status_name != "VALID":
            raise PresentationDenied(
                _STATUS_TO_HTTP.get(status_name, 401), "presentation rejected"
            )

        issuer = getattr(report, "issuer")
        if issuer not in self._pinned_roots:
            raise PresentationDenied(401, "issuer is not a pinned root")

        caps = tuple(Capability(name) for name in (getattr(report, "caps") or []))
        return Principal(
            issuer=issuer,
            subject=getattr(report, "subject"),
            caps=caps,
            role=getattr(report, "role", None),
            expires_at=getattr(report, "expires_at", None),
        )


def _verify_presentation_native(request_json: str) -> object:
    """Call the native `auths.verify_presentation`, importing the optional binding lazily.

    Importing inside the call keeps the package importable (and its fake-verifier tests
    runnable) with no native binding installed.

    Args:
    * `request_json`: The camelCase `VerifyPresentationRequest` JSON document.
    """
    import auths

    # The native binding is an optional extra; do not couple static checking to whatever
    # build is installed (its typed surface is the binding package's own concern).
    native: Any = auths
    return native.verify_presentation(request_json)
