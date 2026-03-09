"""Tests for audit compliance reporting service."""
import subprocess

from auths import Auths
from auths.audit import AuditReport, AuditSummary, CommitRecord


def test_audit_with_unsigned_commits(tmp_path):
    repo_dir = tmp_path / "git-repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    readme = repo_dir / "README.md"
    readme.write_text("# Test Repo\n")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial commit"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )

    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    report = client.audit.report(repo_path=str(repo_dir))
    assert isinstance(report, AuditReport)
    assert report.summary.total_commits == 1
    assert report.summary.unsigned_commits == 1
    assert report.summary.signed_commits == 0


def test_audit_summary_properties(tmp_path):
    repo_dir = tmp_path / "git-repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    readme = repo_dir / "README.md"
    readme.write_text("# Test\n")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "first"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )

    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    report = client.audit.report(repo_path=str(repo_dir))
    s = report.summary
    assert s.total_commits == s.signed_commits + s.unsigned_commits
    assert 0.0 <= s.signing_rate <= 1.0


def test_audit_is_compliant_false_when_unsigned(tmp_path):
    repo_dir = tmp_path / "git-repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    readme = repo_dir / "README.md"
    readme.write_text("# Unsigned\n")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "unsigned commit"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )

    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    assert not client.audit.is_compliant(repo_path=str(repo_dir))


def test_audit_signing_rate_zero_for_empty(tmp_path):
    summary = AuditSummary(
        total_commits=0,
        signed_commits=0,
        unsigned_commits=0,
        auths_signed=0,
        gpg_signed=0,
        ssh_signed=0,
        verification_passed=0,
        verification_failed=0,
    )
    assert summary.signing_rate == 0.0


def test_audit_commit_records(tmp_path):
    repo_dir = tmp_path / "git-repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Dev"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "dev@example.com"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    readme = repo_dir / "README.md"
    readme.write_text("# Hello\n")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "hello world"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )

    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    report = client.audit.report(repo_path=str(repo_dir))
    assert len(report.commits) == 1
    c = report.commits[0]
    assert isinstance(c, CommitRecord)
    assert c.oid
    assert c.author_email == "dev@example.com"
    assert c.message == "hello world"
