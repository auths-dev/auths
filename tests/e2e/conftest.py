"""Shared fixtures for Auths E2E tests."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from helpers.cli import run_auths
from helpers.git import init_git_repo


def _find_binary(env_var: str, name: str) -> Path | None:
    """Resolve a binary from env var, PATH, or target/debug."""
    if path := os.environ.get(env_var):
        p = Path(path)
        if p.exists():
            return p

    if found := shutil.which(name):
        return Path(found)

    workspace_root = Path(__file__).resolve().parent.parent.parent
    debug_path = workspace_root / "target" / "debug" / name
    if debug_path.exists():
        return debug_path

    return None


@pytest.fixture(scope="session")
def auths_bin():
    """Path to the `auths` binary."""
    path = _find_binary("AUTHS_BIN", "auths")
    if path is None:
        pytest.skip("auths binary not found (set AUTHS_BIN or build with cargo)")
    return path


@pytest.fixture(scope="session")
def auths_sign_bin():
    """Path to the `auths-sign` binary."""
    path = _find_binary("AUTHS_SIGN_BIN", "auths-sign")
    if path is None:
        pytest.skip("auths-sign binary not found (set AUTHS_SIGN_BIN or build with cargo)")
    return path


@pytest.fixture(scope="session")
def auths_verify_bin():
    """Path to the `auths-verify` binary."""
    path = _find_binary("AUTHS_VERIFY_BIN", "auths-verify")
    if path is None:
        pytest.skip("auths-verify binary not found (set AUTHS_VERIFY_BIN or build with cargo)")
    return path


@pytest.fixture(scope="session")
def auths_oidc_bridge_bin():
    """Path to the `auths-oidc-bridge` binary."""
    path = _find_binary("AUTHS_OIDC_BRIDGE_BIN", "auths-oidc-bridge")
    if path is None:
        pytest.skip("auths-oidc-bridge binary not found")
    return path


@pytest.fixture
def isolated_env(tmp_path, auths_bin):
    """Fully isolated environment for CLI tests."""
    auths_home = tmp_path / ".auths"
    auths_home.mkdir()
    keychain_file = auths_home / "keys.enc"

    bin_dir = str(auths_bin.parent)
    path = f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"

    return {
        "PATH": path,
        "HOME": str(tmp_path),
        "AUTHS_HOME": str(auths_home),
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


@pytest.fixture
def git_repo(tmp_path, isolated_env):
    """Temporary git repository with initial commit."""
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    init_git_repo(repo_path, isolated_env)
    return repo_path


@pytest.fixture
def init_identity(auths_bin, isolated_env):
    """Pre-initialized Auths identity."""
    result = run_auths(
        auths_bin,
        ["init", "--profile", "developer", "--non-interactive", "--skip-registration"],
        env=isolated_env,
    )
    result.assert_success()
    return isolated_env
