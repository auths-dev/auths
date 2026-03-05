"""Git helpers for Auths E2E tests."""

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


def make_commit(repo_path: Path, message: str, env: dict[str, str]) -> str:
    """Create a file, stage it, commit, and return the commit SHA."""
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
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo_path,
        env=env,
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
