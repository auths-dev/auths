"""Tests for organization management service."""
import pytest

from auths import Auths
from auths._errors import AuthsError, OrgError
from auths.org import Org, OrgMember


def test_create_org(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="admin")

    org = client.orgs.create("my-team")
    assert org.did.startswith("did:keri:")
    assert org.label == "my-team"
    assert isinstance(org, Org)


def test_add_and_list_members(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    repo = str(admin_home / ".auths")
    admin_client = Auths(repo_path=repo, passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    member = admin_client.orgs.add_member(
        org.did, "alice", role="member", repo_path=repo,
    )
    assert member.role == "member"
    assert not member.revoked
    assert member.member_did.startswith("did:keri:")
    assert isinstance(member, OrgMember)

    members = admin_client.orgs.list_members(org.did, repo_path=repo)
    assert len(members) >= 1
    assert any(m.member_did == member.member_did for m in members)


def test_revoke_member(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    repo = str(admin_home / ".auths")
    admin_client = Auths(repo_path=repo, passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    member = admin_client.orgs.add_member(org.did, "bob", repo_path=repo)
    revoked = admin_client.orgs.revoke_member(
        org.did, member.member_did, repo_path=repo,
    )
    assert revoked.revoked

    active = admin_client.orgs.list_members(
        org.did, include_revoked=False, repo_path=repo,
    )
    assert member.member_did not in {m.member_did for m in active if not m.revoked}

    all_members = admin_client.orgs.list_members(
        org.did, include_revoked=True, repo_path=repo,
    )
    assert any(m.member_did == member.member_did for m in all_members)


def test_add_member_with_capabilities(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    repo = str(admin_home / ".auths")
    admin_client = Auths(repo_path=repo, passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    member = admin_client.orgs.add_member(
        org.did, "ci-runner", role="member",
        capabilities=["sign:artifact"], repo_path=repo,
    )
    assert "sign:artifact" in member.capabilities


def test_get_member(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    repo = str(admin_home / ".auths")
    admin_client = Auths(repo_path=repo, passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    member = admin_client.orgs.add_member(org.did, "dev", repo_path=repo)

    found = admin_client.orgs.get_member(
        org.did, member.member_did, repo_path=repo,
    )
    assert found is not None
    assert found.member_did == member.member_did

    not_found = admin_client.orgs.get_member(
        org.did, "did:keri:ENOTREAL", repo_path=repo,
    )
    assert not_found is None


def test_update_member(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    repo = str(admin_home / ".auths")
    admin_client = Auths(repo_path=repo, passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    member = admin_client.orgs.add_member(
        org.did, "dev", role="member", repo_path=repo,
    )
    updated = admin_client.orgs.update_member(
        org.did, member.member_did, "dev-admin", role="admin", repo_path=repo,
    )
    assert updated.role == "admin"
