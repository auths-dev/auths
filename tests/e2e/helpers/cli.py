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


def get_identity_did(binary: Path, env: dict[str, str]) -> str:
    """Extract the controller DID from `auths id show --json`."""
    result = run_auths(binary, ["id", "show", "--json"], env=env)
    result.assert_success()
    return result.json["data"]["controller_did"]


def get_device_did(binary: Path, env: dict[str, str]) -> str:
    """Extract the first device DID from `auths status --json`."""
    result = run_auths(binary, ["status", "--json"], env=env)
    result.assert_success()
    devices = result.json["data"]["devices"]["devices_detail"]
    assert len(devices) > 0, "No devices found in status output"
    return devices[0]["device_did"]


def export_attestation(env: dict[str, str], out_path: Path) -> dict:
    """Extract the first attestation from the auths git repo to a file.

    Returns the parsed attestation JSON.
    """
    auths_home = Path(env["AUTHS_HOME"])

    ls = run_git(
        ["ls-tree", "-r", "--name-only", "refs/auths/registry"],
        cwd=auths_home,
        env=env,
    )
    ls.assert_success()

    att_path = None
    for line in ls.stdout.splitlines():
        if line.endswith("/attestation.json"):
            att_path = line
            break
    assert att_path is not None, "No attestation found in auths repo"

    show = run_git(
        ["show", f"refs/auths/registry:{att_path}"],
        cwd=auths_home,
        env=env,
    )
    show.assert_success()

    out_path.write_text(show.stdout)
    return json.loads(show.stdout)


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
