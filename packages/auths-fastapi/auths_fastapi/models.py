"""Typed principal and capability models.

Mirrors `auths_rp::principal` (`VerifiedPrincipal` / `Capability`): a `Principal` is
constructed only by a verifier on a successful verdict, so possessing one is proof the
holder demonstrated current key control. `authorize` returns a bool here (the FastAPI
dependency raises on failure); the capability is a typed wrapper, never a bare string —
authority is compared by value identity, not by magic-string equality at call sites.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    """A required-or-granted capability, compared by value (never a bare magic string).

    Args:
    * `name`: The capability string (e.g. `deploy:prod`).

    Usage:
    ```python
    needed = Capability("deploy:prod")
    assert needed == Capability("deploy:prod")
    ```
    """

    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Principal:
    """A verified, scoped identity yielded by a successful presentation verdict.

    There is no path to a `Principal` other than a verifier returning one from a `VALID`
    verdict, so a handler that receives a `Principal` is reachable only on an authenticated
    request. Capabilities come from the verified credential, never from the request.

    Args:
    * `issuer`: The credential issuer AID.
    * `subject`: The holder AID whose current key signed the presentation.
    * `caps`: The granted capabilities (immutable tuple).
    * `role`: An optional informational role claim.
    * `expires_at`: An optional credential expiry (RFC-3339).

    Usage:
    ```python
    principal = Principal(issuer="did:keri:E…", subject="did:keri:E…", caps=(Capability("deploy:prod"),))
    assert principal.authorize(Capability("deploy:prod"))
    ```
    """

    issuer: str
    subject: str
    caps: tuple[Capability, ...]
    role: str | None = None
    expires_at: str | None = None

    def authorize(self, capability: Capability) -> bool:
        """Whether this principal carries `capability`.

        Args:
        * `capability`: The capability the route/tool requires.
        """
        return capability in self.caps
