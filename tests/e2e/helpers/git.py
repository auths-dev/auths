"""Git helpers for Auths E2E tests."""

import os
import subprocess
from pathlib import Path


def init_git_repo(path: Path, env: dict[str, str]) -> Path:
    """Initialize a git repository with user config and initial commit."""
    subprocess.run(["git", "init", str(path)], env=env, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=path,
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@auths.dev"],
        cwd=path,
        env=env,
        check=True,
        capture_output=True,
    )

    readme = path / "README.md"
    readme.write_text("# Test repo\n")
    subprocess.run(["git", "add", "."], cwd=path, env=env, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=path,
        env=env,
        check=True,
        capture_output=True,
    )
    return path


def configure_signing(
    repo_path: Path, auths_sign_bin: Path, env: dict[str, str]
) -> None:
    """Configure a git repo for auths-based commit signing."""
    subprocess.run(
        ["git", "config", "gpg.format", "ssh"],
        cwd=repo_path,
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "gpg.ssh.program", str(auths_sign_bin)],
        cwd=repo_path,
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "commit.gpgsign", "true"],
        cwd=repo_path,
        env=env,
        check=True,
        capture_output=True,
    )


def make_commit(
    repo_path: Path, message: str, env: dict[str, str], sign: bool = True
) -> str:
    """Create a file, stage it, commit, and return the commit SHA.

    ``auths init`` (via the ``init_identity`` fixture) configures *global* git
    signing and installs a commit-trailer hook, so a bare ``git commit`` is
    signed. Pass ``sign=False`` to make a genuinely unsigned commit — it ignores
    global/system git config (so neither ``commit.gpgsign`` nor the hooks path
    apply) and adds ``--no-gpg-sign`` — for exercising the unsigned-commit path.
    """
    import uuid

    filename = f"file-{uuid.uuid4().hex[:8]}.txt"
    (repo_path / filename).write_text(f"{message}\n")
    subprocess.run(
        ["git", "add", filename],
        cwd=repo_path,
        env=env,
        check=True,
        capture_output=True,
    )
    commit_cmd = ["git", "commit", "-m", message]
    commit_env = env
    if not sign:
        commit_cmd = ["git", "commit", "--no-gpg-sign", "-m", message]
        commit_env = {
            **env,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    subprocess.run(
        commit_cmd,
        cwd=repo_path,
        env=commit_env,
        check=True,
        capture_output=True,
    )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
