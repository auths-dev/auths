"""Tests for system diagnostics service."""
from auths import Auths
from auths.doctor import Check, DiagnosticReport


def test_doctor_returns_report(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    report = client.doctor.check()
    assert isinstance(report, DiagnosticReport)
    assert isinstance(report.all_passed, bool)
    assert len(report.checks) > 0
    assert all(isinstance(c, Check) for c in report.checks)


def test_doctor_checks_have_names(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    report = client.doctor.check()
    names = [c.name for c in report.checks]
    assert len(names) == len(set(names))


def test_doctor_check_one(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    git_check = client.doctor.check_one("Git installed")
    assert git_check is not None
    assert git_check.name == "Git installed"
    assert git_check.passed is True

    nonexistent = client.doctor.check_one("nonexistent check")
    assert nonexistent is None
