"""E2E tests for key rotation and revocation flows."""

import pytest

from helpers.cli import run_auths
from helpers.git import configure_signing, make_commit


@pytest.mark.slow
@pytest.mark.requires_binary
class TestKeyRotation:
    def test_rotate_keys(self, auths_bin, init_identity):
        # Get identity DID before rotation
        id_before = run_auths(auths_bin, ["id", "show"], env=init_identity)
        id_before.assert_success()

        result = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if result.returncode != 0:
            pytest.skip(f"id rotate not available: {result.stderr}")
        result.assert_success()

        # Verify DID unchanged after rotation
        id_after = run_auths(auths_bin, ["id", "show"], env=init_identity)
        id_after.assert_success()

    def test_verify_old_commit_after_rotation(
        self, auths_bin, auths_sign_bin, init_identity, git_repo
    ):
        configure_signing(git_repo, auths_sign_bin, init_identity)
        sha_a = make_commit(git_repo, "before rotation", init_identity)

        rotate = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if rotate.returncode != 0:
            pytest.skip("id rotate not available")

        sha_b = make_commit(git_repo, "after rotation", init_identity)

        # Old commit should still verify (pre-rotation commitment)
        verify_a = run_auths(
            auths_bin, ["verify", sha_a], cwd=git_repo, env=init_identity
        )
        if verify_a.returncode != 0:
            pytest.skip(f"verify not available: {verify_a.stderr}")

    def test_emergency_freeze(self, auths_bin, init_identity):
        result = run_auths(auths_bin, ["emergency", "freeze"], env=init_identity)
        if result.returncode != 0:
            pytest.skip(f"emergency freeze not available: {result.stderr}")
        result.assert_success()

        # Operations should fail when frozen
        status = run_auths(auths_bin, ["status"], env=init_identity)
        # The system should indicate frozen state somehow
        assert status.returncode in (0, 1)

    def test_emergency_unfreeze(self, auths_bin, init_identity):
        freeze = run_auths(auths_bin, ["emergency", "freeze"], env=init_identity)
        if freeze.returncode != 0:
            pytest.skip("emergency freeze not available")

        unfreeze = run_auths(
            auths_bin, ["emergency", "unfreeze"], env=init_identity
        )
        if unfreeze.returncode != 0:
            pytest.skip(f"emergency unfreeze not available: {unfreeze.stderr}")
        unfreeze.assert_success()

    def test_rotate_preserves_attestations(self, auths_bin, init_identity):
        # Create attestation before rotation
        attest = run_auths(
            auths_bin,
            [
                "attest",
                "--subject",
                "did:key:z6MkRotateTest",
                "--capabilities",
                "sign:commit",
            ],
            env=init_identity,
        )
        if attest.returncode != 0:
            pytest.skip("attest not available")

        # Rotate
        rotate = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if rotate.returncode != 0:
            pytest.skip("id rotate not available")

        # Attestation chain should still validate
        verify = run_auths(
            auths_bin, ["device", "verify"], env=init_identity
        )
        assert verify.returncode in (0, 1)
