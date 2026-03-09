"""Tests for keychain-backed identity signing (Phase 2)."""

import json

import pytest

from auths import Auths


def test_sign_as_identity(shared_auths_with_identity):
    """Create identity then sign with it — the core lifecycle."""
    auths, identity = shared_auths_with_identity
    sig = auths.sign_as(b"hello world", identity=identity.did)
    assert isinstance(sig, str)
    bytes.fromhex(sig)


def test_sign_action_as_identity(shared_auths_with_identity):
    """Create identity then sign an action envelope with it."""
    auths, identity = shared_auths_with_identity
    envelope = auths.sign_action_as(
        "test-action", '{"key": "value"}', identity=identity.did
    )
    assert isinstance(envelope, str)
    parsed = json.loads(envelope)
    assert "signature" in parsed
    assert parsed["type"] == "test-action"
    assert parsed["identity"] == identity.did


def test_sign_as_unknown_identity_raises(shared_auths_with_identity):
    """Signing with a non-existent identity should raise an error."""
    auths, _identity = shared_auths_with_identity
    from auths import CryptoError

    with pytest.raises((CryptoError, RuntimeError)):
        auths.sign_as(b"hello", identity="did:keri:nonexistent")


def test_sign_roundtrip(shared_auths_with_identity):
    """Sign with identity, verify the signature is valid hex of correct length."""
    auths, identity = shared_auths_with_identity
    sig = auths.sign_as(b"hello world", identity=identity.did)
    sig_bytes = bytes.fromhex(sig)
    assert len(sig_bytes) == 64  # Ed25519 signature is 64 bytes
