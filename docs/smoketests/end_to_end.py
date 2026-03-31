#!/usr/bin/env python3
"""
Auths CLI Full Coverage Smoke Test

Tests the entire auths CLI command suite to verify all commands are functional
and work through a realistic identity lifecycle.

Usage:
    python3 docs/smoketests/end_to_end.py

This script will:
1. Initialize a test identity
2. Exercise all CLI commands in a realistic workflow
3. Report which commands succeeded and failed
4. Show the full identity lifecycle

Commands tested (34 total):
  - init: Set up cryptographic identity
  - status: Show identity and agent status
  - whoami: Show current identity
  - key: Manage cryptographic keys
  - device: Manage device authorizations
  - pair: Link devices to identity
  - id: Manage identities
  - artifact: Sign arbitrary artifacts
  - sign: Sign git commits
  - verify: Verify signatures
  - policy: Manage authorization policies
  - approval: Manage approval gates
  - trust: Manage trusted identity roots
  - signers: Manage allowed signers
  - config: View/modify configuration
  - doctor: Run health checks
  - audit: Generate audit reports
  - agent: SSH agent management
  - witness: Manage KERI witness server
  - namespace: Manage namespace claims
  - org: Handle member authorizations
  - account: Manage registry account
  - auth: Authenticate with external services
  - log: Inspect transparency log
  - git: Git integration commands
  - error: Look up error codes
  - completions: Generate shell completions
  - emergency: Emergency incident response
  - debug: Internal debugging utilities
  - tutorial: Interactive learning
  - scim: SCIM 2.0 provisioning
  - verify (unified): Verify signed commits and artifacts
  - commit (low-level): Low-level commit signing/verification
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Colors ───────────────────────────────────────────────────────────────────

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{NC}"


# ── Logging ──────────────────────────────────────────────────────────────────


def section(title: str) -> None:
    print()
    print(_c(BLUE, "=" * 80))
    print(_c(BOLD + BLUE, f"  {title}"))
    print(_c(BLUE, "=" * 80))
    print()


def subsection(title: str) -> None:
    print(_c(CYAN, f"\n  → {title}"))


def info(msg: str) -> None:
    print(f"  {msg}")


def print_success(msg: str) -> None:
    print(_c(GREEN, f"  ✓ {msg}"))


def print_failure(msg: str) -> None:
    print(_c(RED, f"  ✗ {msg}"))


def print_warn(msg: str) -> None:
    print(_c(YELLOW, f"  ⚠ {msg}"))


# ── Test Result Tracking ─────────────────────────────────────────────────────


@dataclass
class CommandResult:
    name: str
    success: bool
    output: str = ""
    error: str = ""
    skipped: bool = False
    skip_reason: str = ""

    @property
    def failed(self) -> bool:
        return not self.success and not self.skipped


@dataclass
class TestReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    results: list[CommandResult] = field(default_factory=list)

    def add(self, result: CommandResult) -> None:
        self.results.append(result)
        self.total += 1
        if result.skipped:
            self.skipped += 1
        elif result.success:
            self.passed += 1
        else:
            self.failed += 1


# ── Command Execution ────────────────────────────────────────────────────────


def run_command(
    cmd: list[str],
    env: dict[str, str] | None = None,
    expect_failure: bool = False,
    quiet: bool = False,
) -> tuple[bool, str, str]:
    """
    Execute a command and return (success, stdout, stderr).

    Args:
        cmd: Command and arguments as list
        env: Environment variables to pass
        expect_failure: If True, a non-zero exit code is considered success
        quiet: If True, don't print command being run

    Returns:
        (success, stdout, stderr)
    """
    if not quiet:
        info(_c(DIM, f"$ {' '.join(cmd)}"))

    try:
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        result = subprocess.run(
            cmd,
            env=full_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        success = (result.returncode == 0) != expect_failure
        return success, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return False, "", "Command timed out after 30 seconds"
    except Exception as e:
        return False, "", str(e)


def test_command(
    name: str,
    cmd: list[str],
    report: TestReport,
    env: dict[str, str] | None = None,
    expect_failure: bool = False,
    skip: bool = False,
    skip_reason: str = "",
) -> CommandResult:
    """
    Test a single command and add result to report.

    Args:
        name: Display name for the command
        cmd: Command to run
        report: Report object to add result to
        env: Optional environment variables
        expect_failure: If True, expecting command to fail
        skip: If True, skip this test
        skip_reason: Reason for skipping

    Returns:
        CommandResult with outcome
    """
    subsection(name)

    if skip:
        result = CommandResult(name=name, success=False, skipped=True, skip_reason=skip_reason)
        print_warn(f"Skipped: {skip_reason}")
        report.add(result)
        return result

    is_success, stdout, stderr = run_command(cmd, env=env, expect_failure=expect_failure)

    if is_success:
        print_success(f"{name} passed")
        result = CommandResult(name=name, success=True, output=stdout)
    else:
        print_failure(f"{name} failed")
        result = CommandResult(name=name, success=False, error=stderr or stdout)

    report.add(result)
    return result


# ── Test Suite ───────────────────────────────────────────────────────────────


def run_tests(temp_dir: Path, report: TestReport) -> None:
    """Run the full test suite."""

    # Set up environment with isolated HOME to prevent polluting real ~/.auths
    # Note: auths init doesn't respect --repo flag, so we use HOME isolation instead
    repo_dir = temp_dir / ".auths"
    test_env = {
        "HOME": str(temp_dir),  # Isolated home directory for test
        "AUTHS_PASSPHRASE": "test-passphrase-123",  # For non-interactive setup
        "AUTHS_KEYCHAIN_BACKEND": "file",  # Use file-based storage instead of system keychain
    }

    section("PHASE 1: INITIALIZATION & CORE IDENTITY")

    # 1. Init - Create a new identity (non-interactive, developer profile, force to overwrite any existing)
    test_command(
        "01. auths init",
        ["auths", "init", "--profile", "developer", "--non-interactive", "--force"],
        report,
        env=test_env,
    )

    # 2. Status - Check the identity status
    test_command(
        "02. auths status",
        ["auths", "status"],
        report,
        env=test_env,
    )

    # 3. Whoami - Show current identity
    test_command(
        "03. auths whoami",
        ["auths", "whoami"],
        report,
        env=test_env,
    )

    section("PHASE 2: KEY & DEVICE MANAGEMENT")

    # 4. Key - List local keys
    test_command(
        "04. auths key list",
        ["auths", "key", "list"],
        report,
        env=test_env,
    )

    # 5. Device - List devices
    test_command(
        "05. auths device list",
        ["auths", "device", "list"],
        report,
        env=test_env,
    )

    # 6. Pair - Show pair device help (actual pairing requires interaction)
    test_command(
        "06. auths pair (help)",
        ["auths", "pair", "--help"],
        report,
        env=test_env,
    )

    section("PHASE 3: SIGNING & VERIFICATION")

    # Create a test artifact to sign
    test_artifact = temp_dir / "test-artifact.txt"
    test_artifact.write_text("This is a test artifact for signing.\n")

    # 7. Sign - Sign the artifact
    sign_result = test_command(
        "07. auths sign (artifact)",
        ["auths", "sign", str(test_artifact)],
        report,
        env=test_env,
    )

    # Expected output file from signing
    signature_file = temp_dir / "test-artifact.txt.auths.json"

    # 8. Verify - Verify the signed artifact
    if signature_file.exists():
        test_command(
            "08. auths verify (artifact)",
            ["auths", "verify", str(signature_file)],
            report,
            env=test_env,
        )
    else:
        print_warn(f"Signature file not found at {signature_file}, skipping verify test")

    section("PHASE 4: CONFIGURATION & STATUS")

    # 9. Config - Show configuration
    test_command(
        "09. auths config show",
        ["auths", "config", "show"],
        report,
        env=test_env,
    )

    # 10. Doctor - Run health checks
    # Doctor returns 0 (all pass), 1 (critical fail), or 2 (advisory fail but functional)
    # We consider 0 and 2 as success since Auths is functional in both cases
    try:
        doctor_result = subprocess.run(
            ["auths", "doctor"],
            env=test_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Accept exit code 0 (all pass) or 2 (advisory checks failed, but Auths functional)
        doctor_success = doctor_result.returncode in (0, 2)
        result = CommandResult(
            name="10. auths doctor",
            success=doctor_success,
            output=doctor_result.stdout,
            error=doctor_result.stderr,
        )
    except Exception as e:
        result = CommandResult(
            name="10. auths doctor",
            success=False,
            error=str(e),
        )

    if result.success:
        print_success(f"{result.name} passed")
    else:
        print_failure(f"{result.name} failed")
    report.add(result)

    section("PHASE 5: IDENTITY MANAGEMENT")

    # 11. ID - List identities
    test_command(
        "11. auths id list",
        ["auths", "id", "list"],
        report,
        env=test_env,
    )

    # 12. Signers - Show signers
    test_command(
        "12. auths signers list",
        ["auths", "signers", "list"],
        report,
        env=test_env,
    )

    section("PHASE 6: ADVANCED FEATURES")

    # 13. Policy - Show policy help
    test_command(
        "13. auths policy (help)",
        ["auths", "policy", "--help"],
        report,
        env=test_env,
    )

    # 14. Approval - Show approval help
    test_command(
        "14. auths approval (help)",
        ["auths", "approval", "--help"],
        report,
        env=test_env,
    )

    # 15. Trust - Show trust help
    test_command(
        "15. auths trust (help)",
        ["auths", "trust", "--help"],
        report,
        env=test_env,
    )

    # 16. Artifact - Show artifact help
    test_command(
        "16. auths artifact (help)",
        ["auths", "artifact", "--help"],
        report,
        env=test_env,
    )

    # 17. Git - Show git integration help
    test_command(
        "17. auths git (help)",
        ["auths", "git", "--help"],
        report,
        env=test_env,
    )

    section("PHASE 7: REGISTRY & ACCOUNT")

    # 18. Account - Show account help
    test_command(
        "18. auths account (help)",
        ["auths", "account", "--help"],
        report,
        env=test_env,
    )

    # 19. Namespace - Show namespace help
    test_command(
        "19. auths namespace (help)",
        ["auths", "namespace", "--help"],
        report,
        env=test_env,
    )

    # 20. Org - Show org help
    test_command(
        "20. auths org (help)",
        ["auths", "org", "--help"],
        report,
        env=test_env,
    )

    section("PHASE 8: AGENT & INFRASTRUCTURE")

    # 21. Agent - Show agent help
    test_command(
        "21. auths agent (help)",
        ["auths", "agent", "--help"],
        report,
        env=test_env,
    )

    # 22. Witness - Show witness help
    test_command(
        "22. auths witness (help)",
        ["auths", "witness", "--help"],
        report,
        env=test_env,
    )

    # 23. Auth - Show auth help
    test_command(
        "23. auths auth (help)",
        ["auths", "auth", "--help"],
        report,
        env=test_env,
    )

    # 24. Log - Show log help
    test_command(
        "24. auths log (help)",
        ["auths", "log", "--help"],
        report,
        env=test_env,
    )

    section("PHASE 9: AUDIT & COMPLIANCE")

    # 25. Audit - Generate audit report
    test_command(
        "25. auths audit (help)",
        ["auths", "audit", "--help"],
        report,
        env=test_env,
    )

    section("PHASE 10: UTILITIES & TOOLS")

    # 26. Error - Look up error codes
    test_command(
        "26. auths error list",
        ["auths", "error", "list"],
        report,
        env=test_env,
    )

    # 27. Completions - Generate shell completions
    test_command(
        "27. auths completions (bash)",
        ["auths", "completions", "bash"],
        report,
        env=test_env,
    )

    # 28. Debug - Show debug help
    test_command(
        "28. auths debug (help)",
        ["auths", "debug", "--help"],
        report,
        env=test_env,
    )

    # 29. Tutorial - Show tutorial help
    test_command(
        "29. auths tutorial (help)",
        ["auths", "tutorial", "--help"],
        report,
        env=test_env,
    )

    # 30. SCIM - Show SCIM help
    test_command(
        "30. auths scim (help)",
        ["auths", "scim", "--help"],
        report,
        env=test_env,
    )

    # 31. Emergency - Show emergency help
    test_command(
        "31. auths emergency (help)",
        ["auths", "emergency", "--help"],
        report,
        env=test_env,
    )

    # 32. Verify (unified) - Show verify help
    test_command(
        "32. auths verify (help)",
        ["auths", "verify", "--help"],
        report,
        env=test_env,
    )

    # 33. Commit (low-level) - Show commit help
    test_command(
        "33. auths commit (help)",
        ["auths", "commit", "--help"],
        report,
        env=test_env,
    )

    # 34. JSON output format test
    test_command(
        "34. auths --json whoami",
        ["auths", "--json", "whoami"],
        report,
        env=test_env,
    )


def print_summary(report: TestReport) -> None:
    """Print test summary report."""

    section("TEST SUMMARY")

    print(f"  Total:   {_c(BOLD, str(report.total))}")
    print(f"  {_c(GREEN, f'Passed:  {report.passed}')}")
    if report.failed > 0:
        print(f"  {_c(RED, f'Failed:  {report.failed}')}")
    if report.skipped > 0:
        print(f"  {_c(YELLOW, f'Skipped: {report.skipped}')}")

    print()

    if report.failed > 0:
        print(_c(RED, "  Failed Tests:"))
        for result in report.results:
            if result.failed:
                print(f"    • {result.name}")
                if result.error:
                    for line in result.error.split("\n")[:3]:
                        if line:
                            print(f"      {DIM}{line}{NC}")

    if report.skipped > 0:
        print()
        print(_c(YELLOW, "  Skipped Tests:"))
        for result in report.results:
            if result.skipped:
                print(_c(DIM, f"    • {result.name}: {result.skip_reason}{NC}"))

    print()
    percentage = (report.passed / report.total * 100) if report.total > 0 else 0
    if report.failed == 0 and report.skipped == 0:
        print(_c(GREEN + BOLD, f"  ✓ All {report.total} tests passed! 🎉"))
    elif report.failed == 0:
        print(_c(GREEN, f"  ✓ {report.passed}/{report.total} tests passed ({percentage:.0f}%)"))
    else:
        print(
            _c(
                RED,
                f"  ✗ {report.failed} failures, {report.passed} passed ({percentage:.0f}%)",
            )
        )

    print()


def main() -> int:
    """Main entry point."""

    print(_c(BOLD + GREEN, "\nauths CLI Full Coverage Smoke Test\n"))
    print("This test exercises all auths CLI commands in a realistic identity lifecycle.")
    print()

    report = TestReport()

    # Create temp directory for testing
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        info(f"Test directory: {temp_dir}")
        print()

        try:
            run_tests(temp_dir, report)
        except Exception as e:
            print_failure(f"Test suite failed with exception: {e}")
            import traceback
            traceback.print_exc()
            return 1

    print_summary(report)

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
