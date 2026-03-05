"""CLI runner helpers for Auths E2E tests."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CLIResult:
    """Result of running a CLI command."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def json(self) -> dict:
        """Parse stdout as JSON."""
        return json.loads(self.stdout)

    def assert_success(self) -> "CLIResult":
        """Assert the command exited with code 0."""
        assert self.returncode == 0, (
            f"Command failed with exit code {self.returncode}\n"
            f"stdout: {self.stdout}\n"
            f"stderr: {self.stderr}"
        )
        return self

    def assert_failure(self, exit_code: int | None = None) -> "CLIResult":
        """Assert the command failed."""
        if exit_code is not None:
            assert self.returncode == exit_code, (
                f"Expected exit code {exit_code}, got {self.returncode}\n"
                f"stderr: {self.stderr}"
            )
        else:
            assert self.returncode != 0, (
                f"Expected failure but got exit code 0\n"
                f"stdout: {self.stdout}"
            )
        return self


def run_auths(
    binary: Path,
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 30,
    stdin_data: str | None = None,
) -> CLIResult:
    """Run an auths CLI command and capture output."""
    result = subprocess.run(
        [str(binary)] + args,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=stdin_data,
    )
    return CLIResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def run_git(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 15,
) -> CLIResult:
    """Run a git command and capture output."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return CLIResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
