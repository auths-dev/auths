"""Diagnostic checks for identity and signing health."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from auths._native import run_diagnostics as _run_diagnostics
from auths._client import _map_error
from auths._errors import AuthsError


@dataclass
class Check:
    """A single diagnostic check result."""

    name: str
    passed: bool
    message: str
    fix_hint: Optional[str]


@dataclass
class DiagnosticReport:
    """Full health check report.

    Attributes:
        checks: Individual check results.
        all_passed: True if every check passed.
        version: Auths CLI/SDK version string (e.g. ``"0.9.0"``).
            Useful for support tickets and compatibility checks.
    """

    checks: list[Check]
    all_passed: bool
    version: str
    """Auths CLI/SDK version string (e.g. ``"0.9.0"``)."""


class DoctorService:
    """Resource service for system diagnostics."""

    #: Known diagnostic check names.
    AVAILABLE_CHECKS: list[str] = [
        "git_version",
        "ssh_keygen",
        "git_signing_config",
    ]

    def __init__(self, client):
        self._client = client

    @classmethod
    def available_checks(cls) -> list[str]:
        """Return the list of known diagnostic check names.

        Examples:
            ```python
            for name in DoctorService.available_checks():
                result = client.doctor.check_one(name)
            ```
        """
        return list(cls.AVAILABLE_CHECKS)

    def check(
        self,
        repo_path: str | None = None,
    ) -> DiagnosticReport:
        """Run all diagnostic checks.

        Usage:
            report = client.doctor.check()
            if not report.all_passed:
                for c in report.checks:
                    if not c.passed:
                        print(f"FAIL: {c.name} - {c.fix_hint}")
        """
        rp = repo_path or self._client.repo_path
        try:
            raw = _run_diagnostics(rp)
            data = json.loads(raw)
            checks = [
                Check(
                    name=c["name"],
                    passed=c["passed"],
                    message=c.get("message", ""),
                    fix_hint=c.get("fix_hint"),
                )
                for c in data["checks"]
            ]
            return DiagnosticReport(
                checks=checks,
                all_passed=data["all_passed"],
                version=data.get("version", ""),
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def check_one(
        self,
        name: str,
        repo_path: str | None = None,
    ) -> Check | None:
        """Run a single named diagnostic check.

        Usage:
            git_check = client.doctor.check_one("Git installed")
        """
        report = self.check(repo_path=repo_path)
        return next((c for c in report.checks if c.name == name), None)
