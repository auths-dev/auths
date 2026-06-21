"""Thin, read-only git helpers. The rig *observes* the repo; it never commits or merges."""
from __future__ import annotations

import subprocess
from pathlib import Path


def _git(args: list[str], cwd: Path) -> str:
    """Run a git command and return stdout, raising on failure (fail closed)."""
    out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def head(cwd: Path) -> str:
    """The current HEAD sha."""
    return _git(["rev-parse", "HEAD"], cwd).strip()


def changed_files(base: str, head_sha: str, cwd: Path) -> list[str]:
    """Repo-relative paths touched in `base..head_sha`."""
    out = _git(["diff", "--name-only", f"{base}..{head_sha}"], cwd)
    return [line for line in out.splitlines() if line]


def diff_text(base: str, head_sha: str, cwd: Path) -> str:
    """The full unified diff of `base..head_sha`."""
    return _git(["diff", f"{base}..{head_sha}"], cwd)
