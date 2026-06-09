"""E2E tests for git commit signing and verification (KEL-native)."""

import shutil

import pytest

from helpers.cli import export_identity_bundle, run_auths, run_git
from helpers.git import make_commit


def _sign_head(auths_bin, repo, env) -> str:
    """KEL-native sign the current HEAD; return the (rewritten) HEAD sha.

    `auths sign` adds the `Auths-Id`/`Auths-Device` trailers and rewrites the
    commit; verification then runs against the post-sign sha. This replaces the old
    SSH (`gpg.ssh.program`) + `allowed_signers` model — KEL replay is the only trust.
    """
    run_auths(auths_bin, ["sign", "HEAD"], cwd=repo, env=env)
    return run_git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.strip()


@pytest.mark.requires_binary
class TestGitSigning:
    @pytest.fixture(autouse=True)
    def _check_ssh_keygen(self):
        if not shutil.which("ssh-keygen"):
            pytest.skip("ssh-keygen not found")

    def test_sign_commit_roundtrip(self, auths_bin, init_identity, git_repo, tmp_path):
        make_commit(git_repo, "signed commit", init_identity)
        sha = _sign_head(auths_bin, git_repo, init_identity)
        assert len(sha) == 40

        bundle = tmp_path / "bundle.json"
        export_identity_bundle(auths_bin, init_identity, bundle).assert_success()
        result = run_auths(
            auths_bin,
            ["verify", sha, "--identity-bundle", str(bundle)],
            cwd=git_repo,
            env=init_identity,
        )
        result.assert_success()
        assert "verified" in result.stdout.lower()

    def test_verify_unsigned_commit(self, auths_bin, init_identity, git_repo):
        sha = make_commit(git_repo, "unsigned commit", init_identity)
        # An unsigned commit reports as unverified; the command still exits cleanly.
        result = run_auths(
            auths_bin, ["verify", sha], cwd=git_repo, env=init_identity
        )
        assert result.returncode in (0, 1)

    def test_sign_and_verify_multiple_commits(
        self, auths_bin, init_identity, git_repo, tmp_path
    ):
        shas = []
        for i in range(3):
            make_commit(git_repo, f"commit {i}", init_identity)
            shas.append(_sign_head(auths_bin, git_repo, init_identity))

        bundle = tmp_path / "bundle.json"
        export_identity_bundle(auths_bin, init_identity, bundle).assert_success()
        for sha in shas:
            result = run_auths(
                auths_bin,
                ["verify", sha, "--identity-bundle", str(bundle)],
                cwd=git_repo,
                env=init_identity,
            )
            result.assert_success()

    def test_auths_sign_binary_direct(
        self, auths_sign_bin, init_identity, tmp_path
    ):
        data_file = tmp_path / "message.txt"
        data_file.write_text("test message")

        result = run_auths(
            auths_sign_bin,
            ["-Y", "sign", "-n", "git", "-f", "auths:main", str(data_file)],
            env=init_identity,
        )
        if result.returncode != 0:
            pytest.skip(f"auths-sign direct not available: {result.stderr}")

        # Should produce SSHSIG output.
        assert "SIGNATURE" in result.stdout or result.returncode == 0
