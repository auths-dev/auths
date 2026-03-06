"""Tests for the Auths client DX layer."""

import pytest
from auths import Auths, AuthsError, VerificationError, CryptoError, NetworkError
from auths._errors import KeychainError, StorageError, IdentityError

TEST_SEED_HEX = "a" * 64


def test_client_instantiation():
    auths = Auths()
    assert auths.repo_path == "~/.auths"


def test_client_with_repo_path():
    auths = Auths(repo_path="/tmp/test-repo")
    assert auths.repo_path == "/tmp/test-repo"


def test_verify_invalid_raises_crypto_error():
    auths = Auths()
    with pytest.raises(CryptoError) as exc_info:
        auths.verify(attestation_json="{}", issuer_key="bad-hex")
    assert exc_info.value.code is not None
    assert exc_info.value.message is not None


def test_sign_returns_hex_string():
    auths = Auths()
    sig = auths.sign(b"hello", private_key=TEST_SEED_HEX)
    assert isinstance(sig, str)
    bytes.fromhex(sig)


def test_sign_invalid_key_raises_crypto_error():
    auths = Auths()
    with pytest.raises(CryptoError) as exc_info:
        auths.sign(b"hello", private_key="bad-key")
    assert exc_info.value.code == "invalid_key"


def test_error_hierarchy():
    for cls in [VerificationError, CryptoError, KeychainError,
                StorageError, NetworkError, IdentityError]:
        assert issubclass(cls, AuthsError)


def test_error_has_code_and_message():
    err = AuthsError("something broke", code="test_error")
    assert err.code == "test_error"
    assert err.message == "something broke"
    assert "test_error" in repr(err)


def test_network_error_has_should_retry():
    err = NetworkError("timeout", code="timeout", should_retry=True)
    assert err.should_retry is True
