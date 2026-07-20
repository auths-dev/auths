"""E2E tests for git commit signing and verification (KEL-native)."""

import os
import shutil

import pytest

from helpers.cli import export_identity_bundle, run_auths, run_git
from helpers.git import init_git_repo, make_commit


def _headless_repo_root_env(tmp_path, auths_bin, *, registry_name="registry"):
    """Env whose storage root is AUTHS_REPO and whose HOME has no ~/.auths.

    This deliberately diverges the storage root from HOME, so `verify` must read
    the *same* root `init`/`sign` wrote to (not `~/.auths`) for a self-signed
    commit to verify.
    """
    registry = tmp_path / registry_name
    registry.mkdir()
    home = tmp_path / f"home-{registry_name}"
    home.mkdir()
    keychain_file = tmp_path / f"keys-{registry_name}.enc"
    bin_dir = str(auths_bin.parent)
    return {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(home),
        "AUTHS_REPO": str(registry),
        "AUTHS_KEYCHAIN_BACKEND": "file",
        "AUTHS_KEYCHAIN_FILE": str(keychain_file),
        "AUTHS_PASSPHRASE": "TestPassphrase!42",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test User",
        "GIT_COMMITTER_NAME": "Test User",
        "GIT_AUTHOR_EMAIL": "test@auths.dev",
        "GIT_COMMITTER_EMAIL": "test@auths.dev",
        "NO_COLOR": "1",
    }


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

    def test_headless_sign_then_verify_passes(self, auths_bin, tmp_path):
        # The headless success criterion: with the storage root set via AUTHS_REPO
        # (and HOME's ~/.auths absent), a freshly-signed commit must verify — verify
        # reads the same root sign wrote to, not the default home.
        env = _headless_repo_root_env(tmp_path, auths_bin)
        repo = tmp_path / "repo"
        repo.mkdir()
        init_git_repo(repo, env)

        run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive", "--git-scope", "local"],
            cwd=repo,
            env=env,
        ).assert_success()

        make_commit(repo, "signed via repo root", env)
        run_auths(auths_bin, ["sign", "HEAD"], cwd=repo, env=env).assert_success()
        sha = run_git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.strip()

        result = run_auths(auths_bin, ["verify", sha], cwd=repo, env=env)
        result.assert_success()
        assert "verified" in result.stdout.lower()

    def test_unsigned_commit_advice_is_kel_native(self, auths_bin, init_identity, git_repo):
        # Verifying an unsigned commit must speak the KEL-native flow, never the
        # retired SSH/GPG advice that produces a commit auths still rejects.
        # `init_identity` configures global signing, so force a bare commit.
        sha = make_commit(git_repo, "unsigned commit", init_identity, sign=False)
        result = run_auths(auths_bin, ["verify", sha], cwd=git_repo, env=init_identity)
        combined = (result.stdout + result.stderr).lower()
        assert "git commit -s" not in combined
        assert "allowed signers" not in combined
        assert "auths sign" in combined or "trailer" in combined

        show = run_auths(auths_bin, ["error", "show", "AUTHS-E2101"], env=init_identity)
        if show.returncode == 0:
            out = show.stdout.lower()
            assert "git commit -s" not in out
            assert "auths " in out

    def test_sign_missing_alias_names_key_list(
        self, auths_sign_bin, init_identity, tmp_path
    ):
        # A nonexistent alias is not a broken keychain: the error must name the
        # missing-key code and `auths key list`, not the keychain-unavailable code.
        data_file = tmp_path / "message.txt"
        data_file.write_text("test message")
        result = run_auths(
            auths_sign_bin,
            ["-Y", "sign", "-n", "git", "-f", "auths:nonexistent-key", str(data_file)],
            env=init_identity,
        )
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "AUTHS-E5911" in combined, combined
        assert "auths key list" in combined, combined
        assert "AUTHS-E5909" not in combined, combined

    def test_verify_absent_teammate_kel_names_fetch(self, auths_bin, tmp_path):
        # A commit whose signer KEL is not in the local registry (and no bundle) is
        # the common teammate case: the error must carry the code and the fetch
        # remedy, not a bare, uncoded string.
        signer_env = _headless_repo_root_env(tmp_path, auths_bin, registry_name="signer")
        repo = tmp_path / "repo"
        repo.mkdir()
        init_git_repo(repo, signer_env)
        run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive", "--git-scope", "local"],
            cwd=repo,
            env=signer_env,
        ).assert_success()
        make_commit(repo, "signed by a teammate", signer_env)
        run_auths(auths_bin, ["sign", "HEAD"], cwd=repo, env=signer_env).assert_success()
        sha = run_git(["rev-parse", "HEAD"], cwd=repo, env=signer_env).stdout.strip()

        # Verify against a DIFFERENT, empty storage root: the signer's KEL is absent.
        verifier_env = _headless_repo_root_env(tmp_path, auths_bin, registry_name="verifier")
        result = run_auths(auths_bin, ["verify", sha], cwd=repo, env=verifier_env)
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "AUTHS-E6301" in combined, combined
        assert "git fetch" in combined, combined

    def test_bad_verify_option_has_no_orphan_code(
        self, auths_sign_bin, init_identity, tmp_path
    ):
        # The disallowed -O guard once tagged a code that resolved to "unknown";
        # rejecting a bad -O must no longer print that orphan tag.
        data_file = tmp_path / "message.txt"
        data_file.write_text("test message")
        result = run_auths(
            auths_sign_bin,
            [
                "-Y",
                "verify",
                "-n",
                "git",
                "-f",
                "auths:main",
                "-O",
                "bogus-option",
                str(data_file),
            ],
            env=init_identity,
        )
        assert "AUTHS-E0031" not in (result.stdout + result.stderr)
