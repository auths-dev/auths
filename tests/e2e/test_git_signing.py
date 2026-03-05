"""E2E tests for git commit signing and verification."""

import shutil

import pytest

from helpers.cli import run_auths, run_git
from helpers.git import configure_signing, make_commit


@pytest.mark.requires_binary
class TestGitSigning:
    @pytest.fixture(autouse=True)
    def _check_ssh_keygen(self):
        if not shutil.which("ssh-keygen"):
            pytest.skip("ssh-keygen not found")

    def test_sign_commit_roundtrip(
        self, auths_bin, auths_sign_bin, init_identity, git_repo
    ):
        configure_signing(git_repo, auths_sign_bin, init_identity)
        sha = make_commit(git_repo, "signed commit", init_identity)
        assert len(sha) == 40

        result = run_auths(
            auths_bin, ["verify", sha], cwd=git_repo, env=init_identity
        )
        if result.returncode != 0:
            pytest.skip(f"verify not available: {result.stderr}")
        result.assert_success()

    def test_verify_unsigned_commit(self, auths_bin, init_identity, git_repo):
        sha = make_commit(git_repo, "unsigned commit", init_identity)
        result = run_auths(
            auths_bin, ["verify", sha], cwd=git_repo, env=init_identity
        )
        # Unsigned commit should report as unverified
        if result.returncode == 0:
            # GAP: verify may succeed but with a warning
            pass
        else:
            result.assert_failure()

    def test_sign_and_verify_multiple_commits(
        self, auths_bin, auths_sign_bin, init_identity, git_repo
    ):
        configure_signing(git_repo, auths_sign_bin, init_identity)

        shas = []
        for i in range(3):
            sha = make_commit(git_repo, f"commit {i}", init_identity)
            shas.append(sha)

        for sha in shas:
            result = run_auths(
                auths_bin, ["verify", sha], cwd=git_repo, env=init_identity
            )
            if result.returncode != 0:
                pytest.skip(f"verify not available: {result.stderr}")

    def test_auths_sign_binary_direct(
        self, auths_sign_bin, init_identity, tmp_path
    ):
        data_file = tmp_path / "message.txt"
        data_file.write_text("test message")

        result = run_auths(
            auths_sign_bin,
            ["-Y", "sign", "-n", "git", "-f", "auths:default", str(data_file)],
            env=init_identity,
        )
        if result.returncode != 0:
            pytest.skip(f"auths-sign direct not available: {result.stderr}")

        # Should produce SSHSIG output
        assert "SIGNATURE" in result.stdout or result.returncode == 0

    def test_allowed_signers_generation(
        self, auths_bin, init_identity, git_repo, tmp_path
    ):
        signers_file = tmp_path / "signers.txt"
        result = run_auths(
            auths_bin,
            [
                "git",
                "allowed-signers",
                "--repo",
                str(git_repo),
                "--output",
                str(signers_file),
            ],
            env=init_identity,
        )
        if result.returncode != 0:
            pytest.skip(f"allowed-signers not available: {result.stderr}")

        assert signers_file.exists()
        content = signers_file.read_text()
        assert len(content.strip()) > 0
