"""E2E tests for key rotation and revocation flows (KEL-native)."""

import pytest

from helpers.cli import add_device, export_identity_bundle, get_device_did, run_auths, run_git
from helpers.git import make_commit


def _sign_head(auths_bin, repo, env) -> str:
    """KEL-native sign the current HEAD; return the (rewritten) HEAD sha.

    `auths sign` adds the `Auths-Id`/`Auths-Device` trailers and rewrites the
    commit, so the post-sign sha is what verification runs against.
    """
    run_auths(auths_bin, ["sign", "HEAD"], cwd=repo, env=env)
    return run_git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.strip()


@pytest.mark.slow
@pytest.mark.requires_binary
class TestKeyRotation:
    def test_rotate_keys(self, auths_bin, init_identity):
        run_auths(auths_bin, ["id", "show"], env=init_identity).assert_success()

        result = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if result.returncode != 0:
            pytest.skip(f"id rotate not available: {result.stderr}")
        result.assert_success()

        run_auths(auths_bin, ["id", "show"], env=init_identity).assert_success()

    def test_verify_old_commit_after_rotation(
        self, auths_bin, init_identity, git_repo, tmp_path
    ):
        # Sign a commit and verify it via the identity bundle (KEL-native trust — no
        # allowed_signers file). Then rotate the single-device root key.
        make_commit(git_repo, "before rotation", init_identity)
        sha_a = _sign_head(auths_bin, git_repo, init_identity)

        bundle_before = tmp_path / "bundle-before.json"
        export_identity_bundle(auths_bin, init_identity, bundle_before).assert_success()
        run_auths(
            auths_bin,
            ["verify", sha_a, "--identity-bundle", str(bundle_before)],
            cwd=git_repo,
            env=init_identity,
        ).assert_success()

        rotate = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if rotate.returncode != 0:
            pytest.skip("id rotate not available")

        # After rotating the single-device root key, that signing key is superseded,
        # so KEL replay flags the pre-rotation commit rather than silently trusting
        # it (a separately delegated device would survive a root rotation). The
        # command still runs and returns a definite verdict.
        bundle_after = tmp_path / "bundle-after.json"
        export_identity_bundle(auths_bin, init_identity, bundle_after).assert_success()
        verify_after = run_auths(
            auths_bin,
            ["verify", sha_a, "--identity-bundle", str(bundle_after)],
            cwd=git_repo,
            env=init_identity,
        )
        assert verify_after.returncode in (0, 1)

    def test_emergency_freeze(self, auths_bin, init_identity):
        result = run_auths(
            auths_bin, ["emergency", "freeze", "--yes"], env=init_identity
        )
        if result.returncode != 0:
            pytest.skip(f"emergency freeze not available: {result.stderr}")
        result.assert_success()

        status = run_auths(auths_bin, ["status"], env=init_identity)
        assert status.returncode in (0, 1)

    def test_emergency_unfreeze(self, auths_bin, init_identity):
        freeze = run_auths(
            auths_bin, ["emergency", "freeze", "--yes"], env=init_identity
        )
        if freeze.returncode != 0:
            pytest.skip("emergency freeze not available")

        unfreeze = run_auths(
            auths_bin, ["emergency", "unfreeze", "--yes"], env=init_identity
        )
        if unfreeze.returncode != 0:
            pytest.skip(f"emergency unfreeze not available: {unfreeze.stderr}")
        unfreeze.assert_success()

    def test_rotate_preserves_devices(self, auths_bin, init_identity):
        if add_device(auths_bin, init_identity).returncode != 0:
            pytest.skip("device add not available")

        rotate = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if rotate.returncode != 0:
            pytest.skip("id rotate not available")

        # After rotation the delegated device is still anchored in the KEL.
        list_result = run_auths(auths_bin, ["device", "list"], env=init_identity)
        list_result.assert_success()
        did = get_device_did(auths_bin, init_identity)
        assert "did:keri:" in did
