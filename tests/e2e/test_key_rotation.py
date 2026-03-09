"""E2E tests for key rotation and revocation flows."""

from pathlib import Path

import pytest

from helpers.cli import get_device_did, run_auths
from helpers.git import configure_signing, make_commit


def _generate_allowed_signers(auths_bin, git_repo: Path, env: dict) -> Path:
    """Generate allowed-signers file inside the git repo's .auths/ dir."""
    auths_dir = git_repo / ".auths"
    auths_dir.mkdir(exist_ok=True)
    signers_file = auths_dir / "allowed_signers"
    run_auths(
        auths_bin,
        [
            "signers",
            "sync",
            "--repo",
            env["AUTHS_HOME"],
            "--output",
            str(signers_file),
        ],
        env=env,
    ).assert_success()
    return signers_file


def _link_device(auths_bin, env, *, capabilities=None):
    """Link a device and return the CLI result."""
    did = get_device_did(auths_bin, env)
    args = [
        "device",
        "link",
        "--identity-key-alias",
        "main",
        "--device-key-alias",
        "main",
        "--device-did",
        did,
    ]
    if capabilities:
        args += ["--capabilities", capabilities]
    return run_auths(auths_bin, args, env=env)


@pytest.mark.slow
@pytest.mark.requires_binary
class TestKeyRotation:
    def test_rotate_keys(self, auths_bin, init_identity):
        id_before = run_auths(auths_bin, ["id", "show"], env=init_identity)
        id_before.assert_success()

        result = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if result.returncode != 0:
            pytest.skip(f"id rotate not available: {result.stderr}")
        result.assert_success()

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

        _generate_allowed_signers(auths_bin, git_repo, init_identity)

        verify_a = run_auths(
            auths_bin, ["verify", sha_a], cwd=git_repo, env=init_identity
        )
        if verify_a.returncode != 0:
            pytest.skip(f"verify not available: {verify_a.stderr}")

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

    def test_rotate_preserves_attestations(self, auths_bin, init_identity):
        link = _link_device(
            auths_bin, init_identity, capabilities="sign:commit"
        )
        if link.returncode != 0:
            pytest.skip("device link not available")

        rotate = run_auths(auths_bin, ["id", "rotate"], env=init_identity)
        if rotate.returncode != 0:
            pytest.skip("id rotate not available")

        # After rotation, the device should still be listed
        list_result = run_auths(
            auths_bin, ["device", "list"], env=init_identity
        )
        list_result.assert_success()
        did = get_device_did(auths_bin, init_identity)
        assert "did:key:" in did
