"""Tests for key rotation (fn-25.3)."""

import os
import tempfile

import pytest

from auths import Auths, IdentityRotationResult
from auths.rotation import IdentityRotationResult as IdentityRotationResultFromModule


@pytest.fixture
def auths_repo():
    """Create a temporary auths repo with an identity for rotation tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = os.path.join(tmpdir, "test-repo")
        auths = Auths(repo_path=repo_path, passphrase="Test-pass-123")
        try:
            identity = auths.identities.create(label="test-rotate", repo_path=repo_path)
            yield auths, identity
        except Exception:
            pytest.skip("Identity creation requires initialized git repo")


class TestIdentityRotationResult:

    def test_rotation_result_fields(self):
        result = IdentityRotationResult(
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
        result = IdentityRotationResult(
            controller_did="did:keri:ETest123456789012345678901234567890",
            new_key_fingerprint="abcdef01234567890123456789",
            previous_key_fingerprint="9876543210fedcba",
            sequence=2,
        )
        r = repr(result)
        assert "IdentityRotationResult" in r
        assert "seq=2" in r


class TestImports:

    def test_rotation_result_importable_from_top_level(self):
        from auths import IdentityRotationResult
        assert IdentityRotationResult is not None

    def test_rotation_result_importable_from_module(self):
        from auths.rotation import IdentityRotationResult
        assert IdentityRotationResult is not None

    def test_rotate_identity_ffi_importable(self):
        from auths._native import rotate_identity_ffi
        assert rotate_identity_ffi is not None


class TestRotationWithMultipleAgents:

    def test_rotate_with_two_delegated_agents(self):
        """Regression: rotation must work when 2+ agents are delegated."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            auths = Auths(repo_path=tmpdir, passphrase="Test-pass-123")
            operator = auths.identities.create(label="rotation-test")

            auths.identities.delegate_agent(
                operator.did, name="agent-a",
                capabilities=["deploy:staging"], expires_in=604_800,
            )
            auths.identities.delegate_agent(
                operator.did, name="agent-b",
                capabilities=["audit"], expires_in=7_776_000,
            )

            # Must NOT fail with "pre-committed next key '...-agent--next-0' not found"
            result = auths.identities.rotate(operator.did)
            assert result.sequence == 1
            assert result.controller_did == operator.did
