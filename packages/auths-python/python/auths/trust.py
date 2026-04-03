"""Trust pinning and identity verification levels."""
from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Optional

from auths._native import (
    get_pinned_identity as _get_pinned_identity,
    list_pinned_identities as _list_pinned_identities,
    pin_identity as _pin_identity,
    remove_pinned_identity as _remove_pinned_identity,
)
from auths._client import _map_error
from auths._errors import AuthsError


class TrustLevel(enum.Enum):
    """Trust level for a pinned identity.

    Values match the Rust ``TrustLevel`` enum in ``auths-core/src/trust/pinned.rs``.
    """

    TOFU = "tofu"
    """Accepted on first use (interactive prompt)."""
    MANUAL = "manual"
    """Manually pinned via CLI or ``--issuer-pk``."""
    ORG_POLICY = "org_policy"
    """Loaded from roots.json org policy file."""


@dataclass
class TrustEntry:
    """A pinned trusted identity."""

    did: str
    label: Optional[str]
    trust_level: str
    first_seen: str
    kel_sequence: Optional[int]
    pinned_at: str

    @property
    def trust_level_enum(self) -> TrustLevel:
        """Parse the trust_level string into a typed :class:`TrustLevel` enum."""
        return TrustLevel(self.trust_level)


class TrustService:
    """Resource service for trust anchor management."""

    def __init__(self, client):
        self._client = client

    def pin(
        self,
        did: str,
        label: str | None = None,
        trust_level: str = "manual",
        repo_path: str | None = None,
    ) -> TrustEntry:
        """Pin an identity as trusted.

        Args:
            did: The DID to trust (`did:keri:...` or `did:key:...`).
            label: Optional human-readable label.
            trust_level: One of "tofu", "manual", "org_policy".

        Usage:
            entry = client.trust.pin(identity.did, label="peer")
        """
        rp = repo_path or self._client.repo_path
        try:
            did_out, lbl, tl, first_seen, kel_seq, pinned_at = _pin_identity(
                did, rp, label, trust_level,
            )
            return TrustEntry(
                did=did_out,
                label=lbl,
                trust_level=tl,
                first_seen=first_seen,
                kel_sequence=kel_seq,
                pinned_at=pinned_at,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def remove(
        self,
        did: str,
        repo_path: str | None = None,
    ) -> None:
        """Remove a pinned identity from the trust store.

        Usage:
            client.trust.remove(identity.did)
        """
        rp = repo_path or self._client.repo_path
        try:
            _remove_pinned_identity(did, rp)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def list(
        self,
        repo_path: str | None = None,
    ) -> list[TrustEntry]:
        """List all pinned trusted identities.

        Usage:
            entries = client.trust.list()
        """
        rp = repo_path or self._client.repo_path
        try:
            raw = _list_pinned_identities(rp)
            data = json.loads(raw)
            return [
                TrustEntry(
                    did=e["did"],
                    label=e.get("label"),
                    trust_level=e["trust_level"],
                    first_seen=e["first_seen"],
                    kel_sequence=e.get("kel_sequence"),
                    pinned_at=e["pinned_at"],
                )
                for e in data
            ]
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def get(
        self,
        did: str,
        repo_path: str | None = None,
    ) -> TrustEntry | None:
        """Look up a specific pinned identity. Returns None if not pinned.

        Usage:
            entry = client.trust.get(identity.did)
        """
        rp = repo_path or self._client.repo_path
        try:
            result = _get_pinned_identity(did, rp)
            if result is None:
                return None
            did_out, lbl, tl, first_seen, kel_seq, pinned_at = result
            return TrustEntry(
                did=did_out,
                label=lbl,
                trust_level=tl,
                first_seen=first_seen,
                kel_sequence=kel_seq,
                pinned_at=pinned_at,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def is_trusted(
        self,
        did: str,
        repo_path: str | None = None,
    ) -> bool:
        """Check whether a DID is in the trust store.

        Usage:
            if client.trust.is_trusted(identity.did):
                print("Trusted!")
        """
        return self.get(did, repo_path=repo_path) is not None
