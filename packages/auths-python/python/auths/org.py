"""Organization management — Stripe-style API."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from auths._native import (
    add_org_member as _add_org_member,
    create_org as _create_org,
    list_org_members as _list_org_members,
    revoke_org_member as _revoke_org_member,
)
from auths._client import _map_error
from auths._errors import OrgError


@dataclass
class Org:
    """An organization identity."""

    prefix: str
    """KERI prefix of the organization identity."""
    did: str
    """The organization's DID (`did:keri:...`)."""
    label: str
    """Human-readable organization name."""
    repo_path: str
    """Path to the identity repository."""

    def __repr__(self):
        return f"Org(did={self.did!r}, label={self.label!r})"


@dataclass
class OrgMember:
    """A member within an organization."""

    member_did: str
    """Delegated `did:keri:` AID minted by the org for this member."""
    role: str
    """Member role: `"admin"`, `"member"`, or `"readonly"`."""
    capabilities: list[str]
    """Capabilities granted to this member."""
    org_did: str
    """DID of the organization that owns this membership."""
    member_prefix: str
    """KERI prefix of the member's delegated identity."""
    revoked: bool
    """Whether this membership has been revoked."""
    expires_at: Optional[str]
    """ISO 8601 expiry timestamp, or None for non-expiring memberships."""

    @property
    def is_admin(self) -> bool:
        """Whether this member has admin role."""
        return self.role == "admin"

    def __repr__(self):
        status = " revoked" if self.revoked else ""
        return f"OrgMember(did={self.member_did!r}, role={self.role!r}{status})"


class OrgService:
    """Resource service for organization operations."""

    def __init__(self, client):
        self._client = client

    def create(
        self,
        label: str,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> Org:
        """Create a new organization identity.

        Args:
            label: Human-readable name for the org.
            repo_path: Override identity store path.
            passphrase: Override passphrase.

        Returns:
            Org with the KERI prefix, DID, and label.

        Raises:
            OrgError: If organization creation fails.
            KeychainError: If the keychain is locked or inaccessible.

        Examples:
            ```python
            org = client.orgs.create("my-team")
            ```
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        try:
            prefix, did, lbl, rpath = _create_org(label, rp, pp)
            return Org(prefix=prefix, did=did, label=lbl, repo_path=rpath)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=OrgError) from exc

    def add_member(
        self,
        org_did: str,
        member_label: str,
        role: str = "member",
        capabilities: list[str] | None = None,
        repo_path: str | None = None,
        passphrase: str | None = None,
        expires_at: int | None = None,
    ) -> OrgMember:
        """Add a member to an organization.

        The organization mints a fresh delegated key for the member from the
        given label; the returned `member_did` is the new delegated AID.

        Args:
            org_did: The organization's DID (`did:keri:...`).
            member_label: Human-readable alias for the minted member key.
            role: One of `"admin"`, `"member"`, `"readonly"`.
            capabilities: Explicit capability list. If None, uses role defaults.
            expires_at: Optional Unix timestamp at which the membership expires.

        Returns:
            OrgMember with the minted member DID and membership details.

        Raises:
            OrgError: If the member cannot be added.

        Examples:
            ```python
            member = client.orgs.add_member(org.did, "alice", role="member")
            ```
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        caps_json = json.dumps(capabilities) if capabilities else None
        try:
            m_did, r, caps_str, o_did, prefix, revoked, expires = _add_org_member(
                org_did, member_label, role, rp, caps_json, pp, expires_at,
            )
            return OrgMember(
                member_did=m_did,
                role=r,
                capabilities=json.loads(caps_str) if caps_str else [],
                org_did=o_did,
                member_prefix=prefix,
                revoked=revoked,
                expires_at=expires,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=OrgError) from exc

    def revoke_member(
        self,
        org_did: str,
        member_did: str,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> OrgMember:
        """Revoke a member's authorization.

        Args:
            org_did: The organization's DID.
            member_did: The member's delegated DID to revoke.

        Returns:
            OrgMember with revoked status.

        Raises:
            OrgError: If the member cannot be revoked.

        Examples:
            ```python
            revoked = client.orgs.revoke_member(org.did, member.member_did)
            ```
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        try:
            m_did, r, caps_str, o_did, prefix, revoked, expires = _revoke_org_member(
                org_did, member_did, rp, pp,
            )
            return OrgMember(
                member_did=m_did,
                role=r,
                capabilities=json.loads(caps_str) if caps_str else [],
                org_did=o_did,
                member_prefix=prefix,
                revoked=revoked,
                expires_at=expires,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=OrgError) from exc

    def update_member(
        self,
        org_did: str,
        member_did: str,
        member_label: str,
        role: str | None = None,
        capabilities: list[str] | None = None,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> OrgMember:
        """Update a member by revoking the old delegation and minting a new one.

        Because the organization mints member keys, an update revokes the
        existing delegated DID and adds a fresh member under `member_label`.

        Args:
            org_did: The organization's DID.
            member_did: The existing delegated DID to revoke.
            member_label: Alias for the newly minted member key.
            role: New role. If None, defaults to `"member"`.
            capabilities: New capabilities. If None, uses role defaults.

        Returns:
            OrgMember for the freshly minted member.

        Raises:
            OrgError: If the member cannot be updated.

        Examples:
            ```python
            updated = client.orgs.update_member(
                org.did, member.member_did, "alice", role="admin"
            )
            ```
        """
        self.revoke_member(
            org_did, member_did,
            repo_path=repo_path, passphrase=passphrase,
        )
        return self.add_member(
            org_did, member_label, role=role or "member",
            capabilities=capabilities,
            repo_path=repo_path, passphrase=passphrase,
        )

    def list_members(
        self,
        org_did: str,
        include_revoked: bool = False,
        repo_path: str | None = None,
    ) -> list[OrgMember]:
        """List all members of an organization.

        Args:
            org_did: The organization's DID.
            include_revoked: If True, includes revoked members.

        Returns:
            List of OrgMember objects.

        Raises:
            OrgError: If the organization doesn't exist.

        Examples:
            ```python
            members = client.orgs.list_members(org.did)
            ```
        """
        rp = repo_path or self._client.repo_path
        try:
            members_json = _list_org_members(org_did, include_revoked, rp)
            raw = json.loads(members_json)
            return [
                OrgMember(
                    member_did=m["member_did"],
                    role=m.get("role") or "member",
                    capabilities=m.get("capabilities") or [],
                    org_did=org_did,
                    member_prefix=m.get("member_prefix", ""),
                    revoked=m["revoked"],
                    expires_at=m.get("expires_at"),
                )
                for m in raw
            ]
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=OrgError) from exc

    def get_member(
        self,
        org_did: str,
        member_did: str,
        repo_path: str | None = None,
    ) -> OrgMember | None:
        """Look up a specific member.

        Args:
            org_did: The organization's DID.
            member_did: The member's DID to look up.

        Returns:
            OrgMember if found, or None.

        Examples:
            ```python
            member = client.orgs.get_member(org.did, dev.did)
            ```
        """
        members = self.list_members(org_did, include_revoked=False, repo_path=repo_path)
        return next((m for m in members if m.member_did == member_did), None)
