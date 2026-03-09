"""Tests for trust management service."""
from auths import Auths
from auths.trust import TrustEntry


def test_pin_and_list(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    identity = client.identities.create(label="peer")

    entry = client.trust.pin(identity.did, label="my-peer")
    assert entry.did == identity.did
    assert entry.trust_level == "manual"
    assert entry.label == "my-peer"
    assert isinstance(entry, TrustEntry)

    entries = client.trust.list()
    assert len(entries) == 1
    assert entries[0].did == identity.did


def test_remove_pinned(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    identity = client.identities.create(label="peer")

    client.trust.pin(identity.did)
    assert client.trust.is_trusted(identity.did)

    client.trust.remove(identity.did)
    assert not client.trust.is_trusted(identity.did)


def test_is_trusted_false_for_unknown(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    assert not client.trust.is_trusted("did:keri:ENOTREAL")


def test_pin_duplicate_is_idempotent(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    identity = client.identities.create(label="peer")

    client.trust.pin(identity.did, label="first-label")
    client.trust.pin(identity.did, label="updated-label")

    entries = client.trust.list()
    assert len(entries) == 1
    assert entries[0].label == "updated-label"


def test_get_returns_none_for_unknown(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    result = client.trust.get("did:keri:EUNKNOWN")
    assert result is None
