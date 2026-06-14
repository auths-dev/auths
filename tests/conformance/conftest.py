"""Fixtures for the keripy conformance suite.

Locates the auths binary, gives each test an isolated `--repo` tmpdir, and
provides helpers to run auths and parse its JSON. The suite NEVER touches
`~/.auths`: every auths invocation is passed `--repo <tmpdir>`, and a
session-scoped guard fixture asserts `~/.auths` is not created or mutated by the
run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

# The release binary the spike used; overridable via AUTHS_BIN.
_DEFAULT_BIN = (
    Path(__file__).resolve().parents[2] / "target" / "release" / "auths"
)


def _find_binary() -> Path | None:
    if path := os.environ.get("AUTHS_BIN"):
        p = Path(path)
        if p.exists():
            return p
    if _DEFAULT_BIN.exists():
        return _DEFAULT_BIN
    if found := shutil.which("auths"):
        return Path(found)
    return None


@dataclass
class CLIResult:
    """The result of running an auths CLI command."""

    returncode: int
    stdout: str
    stderr: str

    def ok(self) -> "CLIResult":
        assert self.returncode == 0, (
            f"auths exited {self.returncode}\nstdout:\n{self.stdout}\n"
            f"stderr:\n{self.stderr}"
        )
        return self

    @property
    def json(self) -> dict:
        """Parse stdout as a single JSON object."""
        return json.loads(self.stdout)

    @property
    def json_lines(self) -> list[dict]:
        """Parse stdout as newline-delimited JSON objects (skipping blanks)."""
        return [
            json.loads(line)
            for line in self.stdout.splitlines()
            if line.strip()
        ]


@pytest.fixture(scope="session")
def auths_bin() -> Path:
    """Path to the auths binary (skip the suite cleanly if it's not built)."""
    path = _find_binary()
    if path is None:
        pytest.skip(
            "auths binary not found — set AUTHS_BIN or build "
            "(cargo build --release -p auths)"
        )
    return path


@pytest.fixture(scope="session", autouse=True)
def _guard_user_auths_dir():
    """Fail loudly if the suite ever creates or mutates ~/.auths.

    Records a fingerprint of ~/.auths before any test runs and re-checks it after
    the whole session. Every auths call in this suite passes --repo, so the real
    user store must be byte-identical across the run.
    """
    home_auths = Path.home() / ".auths"

    def fingerprint() -> tuple[bool, list[str]]:
        if not home_auths.exists():
            return (False, [])
        entries = sorted(
            f"{p.relative_to(home_auths)}:{p.stat().st_mtime_ns}:{p.stat().st_size}"
            for p in home_auths.rglob("*")
            if p.is_file()
        )
        return (True, entries)

    before = fingerprint()
    yield
    after = fingerprint()
    assert after == before, (
        "~/.auths was created or modified by the conformance suite — every "
        "auths invocation MUST pass --repo <tmpdir>.\n"
        f"before: existed={before[0]} files={len(before[1])}\n"
        f"after:  existed={after[0]} files={len(after[1])}"
    )


@pytest.fixture
def repo_dir(tmp_path) -> Path:
    """A fresh per-test `--repo` directory (never ~/.auths)."""
    d = tmp_path / "repo"
    d.mkdir()
    return d


@pytest.fixture
def run_auths(auths_bin, repo_dir):
    """Run `auths <args> --repo <tmpdir>` and capture output.

    `--repo` is appended automatically (unless already present) so no test can
    accidentally fall back to ~/.auths.
    """

    def _run(args: list[str], *, check: bool = True) -> CLIResult:
        full = list(args)
        if "--repo" not in full:
            full += ["--repo", str(repo_dir)]
        proc = subprocess.run(
            [str(auths_bin), *full],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "NO_COLOR": "1"},
        )
        result = CLIResult(proc.returncode, proc.stdout, proc.stderr)
        if check:
            result.ok()
        return result

    return _run


@pytest.fixture
def write_json(tmp_path):
    """Write an object as JSON to a tmp file and return its path."""

    def _write(name: str, obj) -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(obj, indent=2))
        return p

    return _write
