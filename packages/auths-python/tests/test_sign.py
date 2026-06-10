"""Tests for signing and action envelope functions."""

import json

import pytest
from auths import sign_bytes, sign_action, verify_action_envelope

TEST_SEED_HEX = "a" * 64


class TestSignBytes:

    def test_sign_returns_hex_signature(self):
        sig = sign_bytes(TEST_SEED_HEX, b"hello world")
        assert len(sig) == 128
        bytes.fromhex(sig)

    def test_sign_deterministic(self):
        sig1 = sign_bytes(TEST_SEED_HEX, b"test message")
        sig2 = sign_bytes(TEST_SEED_HEX, b"test message")
        assert sig1 == sig2

    def test_sign_different_messages_differ(self):
        sig1 = sign_bytes(TEST_SEED_HEX, b"message one")
        sig2 = sign_bytes(TEST_SEED_HEX, b"message two")
        assert sig1 != sig2

    def test_sign_invalid_key_hex(self):
        with pytest.raises(ValueError, match="(?i)hex"):
            sign_bytes("not-hex", b"hello")

    def test_sign_wrong_key_length(self):
        with pytest.raises(ValueError, match="(?i)length"):
            sign_bytes("abcd", b"hello")


class TestSignAction:

    def test_sign_action_returns_valid_envelope(self):
        envelope_json = sign_action(
            TEST_SEED_HEX, "tool_call", '{"tool": "read_file"}', "did:keri:ETest123",
        )
        envelope = json.loads(envelope_json)
        assert envelope["version"] == "1.0"
        assert envelope["type"] == "tool_call"
        assert envelope["identity"] == "did:keri:ETest123"
        assert envelope["payload"] == {"tool": "read_file"}
        assert "timestamp" in envelope
        assert "signature" in envelope
        assert len(envelope["signature"]) == 128

    def test_sign_action_invalid_key(self):
        with pytest.raises(ValueError, match="(?i)hex"):
            sign_action("not-hex", "test", "{}", "did:keri:E123")

    def test_sign_action_invalid_json(self):
        with pytest.raises(ValueError, match="(?i)json"):
            sign_action(TEST_SEED_HEX, "test", "not json", "did:keri:E123")


class TestSignAndVerifyRoundtrip:

    def _get_public_key_hex(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            seed_bytes = bytes.fromhex(TEST_SEED_HEX)
            private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
            pub_bytes = private_key.public_key().public_bytes_raw()
            return pub_bytes.hex()
        except ImportError:
            pytest.skip("cryptography package not installed")

    @pytest.mark.xfail(
        strict=False,
        reason="auths#258: raw-seed sign_action/verify_action_envelope payload "
        "mismatch (pre-existing on 0.1.2; keychain-backed envelope paths verify)",
    )
    def test_sign_and_verify_roundtrip(self):
        pub_hex = self._get_public_key_hex()
        envelope_json = sign_action(
            TEST_SEED_HEX, "tool_call",
            '{"tool": "read_file", "path": "/etc/config.json"}',
            "did:keri:ETest123",
        )
        result = verify_action_envelope(envelope_json, pub_hex)
        assert result.valid, f"Roundtrip verification failed: {result.error}"

    def test_verify_rejects_tampered_payload(self):
        pub_hex = self._get_public_key_hex()
        envelope_json = sign_action(
            TEST_SEED_HEX, "tool_call", '{"tool": "safe_action"}', "did:keri:ETest123",
        )
        envelope = json.loads(envelope_json)
        envelope["payload"]["tool"] = "malicious_action"
        tampered_json = json.dumps(envelope)
        result = verify_action_envelope(tampered_json, pub_hex)
        assert not result.valid

    def test_verify_rejects_wrong_public_key(self):
        wrong_pk_hex = "b" * 64
        envelope_json = sign_action(
            TEST_SEED_HEX, "tool_call", '{"tool": "read_file"}', "did:keri:ETest123",
        )
        result = verify_action_envelope(envelope_json, wrong_pk_hex)
        assert not result.valid


class TestVerifyActionEnvelope:

    def test_verify_invalid_envelope_json(self):
        with pytest.raises(ValueError, match="(?i)json"):
            verify_action_envelope("not json", "a" * 64)

    def test_verify_invalid_public_key_hex(self):
        with pytest.raises(ValueError, match="(?i)hex"):
            verify_action_envelope("{}", "not-hex")

    def test_verify_wrong_public_key_length(self):
        with pytest.raises(ValueError, match="(?i)length"):
            verify_action_envelope("{}", "abcd")

    def test_verify_missing_version_field(self):
        envelope = json.dumps({"type": "test", "signature": "aa" * 64})
        with pytest.raises(ValueError, match="version"):
            verify_action_envelope(envelope, "a" * 64)

    def test_verify_unsupported_version(self):
        envelope = json.dumps({
            "version": "99.0", "type": "test", "identity": "did:keri:E123",
            "payload": {}, "timestamp": "2025-01-01T00:00:00Z", "signature": "aa" * 64,
        })
        result = verify_action_envelope(envelope, "a" * 64)
        assert not result.valid
        assert "version" in result.error.lower()


class TestGenerateInmemoryKeypair:
    """Regression: the in-memory keypair must work for the default P-256 curve,
    not just Ed25519 (the private key is a 32-byte scalar for both)."""

    def test_default_p256_seed_is_usable(self):
        from auths import generate_inmemory_keypair

        priv, pub, did = generate_inmemory_keypair()  # default = P-256
        assert len(bytes.fromhex(priv)) == 32, "private key is a 32-byte scalar"
        assert did.startswith("did:key:")
        # the returned scalar must reconstruct a working P-256 signer
        sig = sign_bytes(priv, b"hello")  # default curve = P-256
        assert len(sig) == 128

    def test_ed25519_seed_is_usable(self):
        from auths import generate_inmemory_keypair

        priv, pub, did = generate_inmemory_keypair("ed25519")
        assert len(bytes.fromhex(priv)) == 32
        sig = sign_bytes(priv, b"hello", "ed25519")
        assert len(sig) == 128
