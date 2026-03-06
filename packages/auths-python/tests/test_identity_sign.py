"""Tests for keychain-backed identity signing (Phase 2)."""

import json

import pytest

from auths import Auths


@pytest.fixture
def auths(tmp_path):
    """Create an Auths client with a temp directory (registry auto-inits on first use)."""
    repo = tmp_path / "test-repo"
    repo.mkdir()
    return Auths(repo_path=str(repo), passphrase="Test-pass-123")


def test_sign_as_identity(auths):
    """Create identity then sign with it — the core lifecycle."""
    identity = auths.identities.create(label="test-key")
    sig = auths.sign_as(b"hello world", identity=identity.did)
    assert isinstance(sig, str)
    bytes.fromhex(sig)


def test_sign_action_as_identity(auths):
    """Create identity then sign an action envelope with it."""
    identity = auths.identities.create(label="test-key")
    envelope = auths.sign_action_as(
        "test-action", '{"key": "value"}', identity=identity.did
    )
    assert isinstance(envelope, str)
    parsed = json.loads(envelope)
    assert "signature" in parsed
    assert parsed["type"] == "test-action"
    assert parsed["identity"] == identity.did


def test_sign_as_unknown_identity_raises(auths):
    """Signing with a non-existent identity should raise an error."""
    from auths import CryptoError

    with pytest.raises((CryptoError, RuntimeError)):
        auths.sign_as(b"hello", identity="did:keri:nonexistent")


def test_sign_roundtrip(auths):
    """Sign with identity, verify the signature is valid hex of correct length."""
    identity = auths.identities.create(label="test-key")
    sig = auths.sign_as(b"hello world", identity=identity.did)
    sig_bytes = bytes.fromhex(sig)
    assert len(sig_bytes) == 64  # Ed25519 signature is 64 bytes
