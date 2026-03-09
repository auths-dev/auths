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
    did: str
    label: str
    repo_path: str

    def __repr__(self):
        return f"Org(did={self.did!r}, label={self.label!r})"


@dataclass
class OrgMember:
    """A member within an organization."""

    member_did: str
    role: str
    capabilities: list[str]
    issuer_did: str
    attestation_rid: str
    revoked: bool
    expires_at: Optional[str]

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

        Usage:
            org = client.orgs.create("my-team")
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
        member_did: str,
        role: str = "member",
        capabilities: list[str] | None = None,
        note: str | None = None,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> OrgMember:
        """Add a member to an organization.

        Args:
            org_did: The organization's DID (did:keri:...).
            member_did: The member's DID to add.
            role: One of "admin", "member", "readonly".
            capabilities: Explicit capability list. If None, uses role defaults.
            note: Optional human-readable note for the attestation.

        Usage:
            member = client.orgs.add_member(org.did, dev.did, role="member")
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        caps_json = json.dumps(capabilities) if capabilities else None
        try:
            m_did, r, caps_str, issuer, rid, revoked, expires = _add_org_member(
                org_did, member_did, role, caps_json, rp, pp, note,
            )
            return OrgMember(
                member_did=m_did,
                role=r,
                capabilities=json.loads(caps_str) if caps_str else [],
                issuer_did=issuer,
                attestation_rid=rid,
                revoked=revoked,
                expires_at=expires,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=OrgError) from exc

    def revoke_member(
        self,
        org_did: str,
        member_did: str,
        note: str | None = None,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> OrgMember:
        """Revoke a member's authorization.

        Args:
            org_did: The organization's DID.
            member_did: The member's DID to revoke.
            note: Optional human-readable note.

        Usage:
            revoked = client.orgs.revoke_member(org.did, dev.did)
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        try:
            m_did, r, caps_str, issuer, rid, revoked, expires = _revoke_org_member(
                org_did, member_did, rp, pp, note,
            )
            return OrgMember(
                member_did=m_did,
                role=r,
                capabilities=json.loads(caps_str) if caps_str else [],
                issuer_did=issuer,
                attestation_rid=rid,
                revoked=revoked,
                expires_at=expires,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=OrgError) from exc

    def update_member(
        self,
        org_did: str,
        member_did: str,
        role: str | None = None,
        capabilities: list[str] | None = None,
        note: str | None = None,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> OrgMember:
        """Update a member's role or capabilities.

        Args:
            org_did: The organization's DID.
            member_did: The member's DID to update.
            role: New role. If None, keeps current.
            capabilities: New capabilities. If None, uses role defaults.
            note: Optional note.

        Usage:
            updated = client.orgs.update_member(org.did, dev.did, role="admin")
        """
        self.revoke_member(
            org_did, member_did, note="superseded by update",
            repo_path=repo_path, passphrase=passphrase,
        )
        return self.add_member(
            org_did, member_did, role=role or "member",
            capabilities=capabilities, note=note,
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

        Usage:
            members = client.orgs.list_members(org.did)
        """
        rp = repo_path or self._client.repo_path
        try:
            members_json = _list_org_members(org_did, include_revoked, rp)
            raw = json.loads(members_json)
            return [
                OrgMember(
                    member_did=m["member_did"],
                    role=m["role"],
                    capabilities=m["capabilities"],
                    issuer_did=m["issuer_did"],
                    attestation_rid=m["attestation_rid"],
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
        """Look up a specific member. Returns None if not found.

        Args:
            org_did: The organization's DID.
            member_did: The member's DID to look up.

        Usage:
            member = client.orgs.get_member(org.did, dev.did)
        """
        members = self.list_members(org_did, include_revoked=False, repo_path=repo_path)
        return next((m for m in members if m.member_did == member_did), None)
