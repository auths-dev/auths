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
    admin_client = Auths(repo_path=str(admin_home / ".auths"), passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    dev_home = tmp_path / "dev"
    dev_home.mkdir()
    dev_client = Auths(repo_path=str(dev_home / ".auths"), passphrase="Test-pass-123")
    dev_id = dev_client.identities.create(label="dev")

    member = admin_client.orgs.add_member(
        org.did, dev_id.did, role="member",
        repo_path=str(admin_home / ".auths"),
    )
    assert member.role == "member"
    assert not member.revoked
    assert isinstance(member, OrgMember)

    members = admin_client.orgs.list_members(
        org.did, repo_path=str(admin_home / ".auths"),
    )
    assert len(members) >= 1
    assert any(m.member_did == dev_id.did for m in members)


def test_revoke_member(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    admin_client = Auths(repo_path=str(admin_home / ".auths"), passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    dev_home = tmp_path / "dev"
    dev_home.mkdir()
    dev_client = Auths(repo_path=str(dev_home / ".auths"), passphrase="Test-pass-123")
    dev_id = dev_client.identities.create(label="dev")

    admin_client.orgs.add_member(
        org.did, dev_id.did,
        repo_path=str(admin_home / ".auths"),
    )
    revoked = admin_client.orgs.revoke_member(
        org.did, dev_id.did, note="offboarded",
        repo_path=str(admin_home / ".auths"),
    )
    assert revoked.revoked

    active = admin_client.orgs.list_members(
        org.did, include_revoked=False,
        repo_path=str(admin_home / ".auths"),
    )
    revoked_dids = {m.member_did for m in active if not m.revoked}
    assert dev_id.did not in revoked_dids or all(
        m.revoked for m in active if m.member_did == dev_id.did
    )

    all_members = admin_client.orgs.list_members(
        org.did, include_revoked=True,
        repo_path=str(admin_home / ".auths"),
    )
    assert any(m.member_did == dev_id.did for m in all_members)


def test_add_member_with_capabilities(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    admin_client = Auths(repo_path=str(admin_home / ".auths"), passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    ci_home = tmp_path / "ci"
    ci_home.mkdir()
    ci_client = Auths(repo_path=str(ci_home / ".auths"), passphrase="Test-pass-123")
    ci_id = ci_client.identities.create(label="ci-runner")

    member = admin_client.orgs.add_member(
        org.did, ci_id.did, role="member",
        capabilities=["sign:artifact"],
        repo_path=str(admin_home / ".auths"),
    )
    assert "sign:artifact" in member.capabilities


def test_get_member(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    admin_client = Auths(repo_path=str(admin_home / ".auths"), passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    dev_home = tmp_path / "dev"
    dev_home.mkdir()
    dev_client = Auths(repo_path=str(dev_home / ".auths"), passphrase="Test-pass-123")
    dev_id = dev_client.identities.create(label="dev")

    admin_client.orgs.add_member(
        org.did, dev_id.did,
        repo_path=str(admin_home / ".auths"),
    )

    found = admin_client.orgs.get_member(
        org.did, dev_id.did,
        repo_path=str(admin_home / ".auths"),
    )
    assert found is not None
    assert found.member_did == dev_id.did

    not_found = admin_client.orgs.get_member(
        org.did, "did:keri:ENOTREAL",
        repo_path=str(admin_home / ".auths"),
    )
    assert not_found is None


def test_update_member(tmp_path):
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    admin_client = Auths(repo_path=str(admin_home / ".auths"), passphrase="Test-pass-123")
    admin_client.identities.create(label="admin")
    org = admin_client.orgs.create("team")

    dev_home = tmp_path / "dev"
    dev_home.mkdir()
    dev_client = Auths(repo_path=str(dev_home / ".auths"), passphrase="Test-pass-123")
    dev_id = dev_client.identities.create(label="dev")

    admin_client.orgs.add_member(
        org.did, dev_id.did, role="member",
        repo_path=str(admin_home / ".auths"),
    )
    updated = admin_client.orgs.update_member(
        org.did, dev_id.did, role="admin",
        repo_path=str(admin_home / ".auths"),
    )
    assert updated.role == "admin"
