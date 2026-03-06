"""Tests for key rotation (fn-25.3).

These tests require AUTHS_KEYCHAIN_BACKEND=file and AUTHS_PASSPHRASE=test.
"""

import os
import tempfile

import pytest

from auths import Auths, RotationResult
from auths.rotation import RotationResult as RotationResultFromModule


@pytest.fixture
def auths_repo():
    """Create a temporary auths repo with an identity for rotation tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = os.path.join(tmpdir, "test-repo")
        os.environ["AUTHS_KEYCHAIN_BACKEND"] = "file"
        os.environ["AUTHS_PASSPHRASE"] = "test"
        auths = Auths(repo_path=repo_path, passphrase="test")
        try:
            identity = auths.identities.create(label="test-rotate", repo_path=repo_path)
            yield auths, identity
        except Exception:
            pytest.skip("Identity creation requires initialized git repo")
        finally:
            os.environ.pop("AUTHS_KEYCHAIN_BACKEND", None)
            os.environ.pop("AUTHS_PASSPHRASE", None)


class TestRotationResult:

    def test_rotation_result_fields(self):
        result = RotationResult(
            controller_did="did:keri:ETest123",
            new_key_fingerprint="abcdef0123456789",
            previous_key_fingerprint="9876543210fedcba",
            sequence=1,
        )
        assert result.controller_did == "did:keri:ETest123"
        assert result.new_key_fingerprint == "abcdef0123456789"
        assert result.previous_key_fingerprint == "9876543210fedcba"
        assert result.sequence == 1

    def test_rotation_result_repr(self):
        result = RotationResult(
            controller_did="did:keri:ETest123456789012345678901234567890",
            new_key_fingerprint="abcdef01234567890123456789",
            previous_key_fingerprint="9876543210fedcba",
            sequence=2,
        )
        r = repr(result)
        assert "RotationResult" in r
        assert "seq=2" in r


class TestImports:

    def test_rotation_result_importable_from_top_level(self):
        from auths import RotationResult
        assert RotationResult is not None

    def test_rotation_result_importable_from_module(self):
        from auths.rotation import RotationResult
        assert RotationResult is not None

    def test_rotate_identity_ffi_importable(self):
        from auths._native import rotate_identity_ffi
        assert rotate_identity_ffi is not None
