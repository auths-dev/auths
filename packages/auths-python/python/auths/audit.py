from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from auths._native import generate_audit_report as _generate_audit_report
from auths._client import _map_error
from auths._errors import AuthsError


@dataclass
class AuditSummary:
    """Aggregate signing compliance metrics."""

    total_commits: int
    signed_commits: int
    unsigned_commits: int
    auths_signed: int
    gpg_signed: int
    ssh_signed: int
    verification_passed: int
    verification_failed: int

    @property
    def signing_rate(self) -> float:
        """Percentage of commits that are signed (0.0 to 1.0)."""
        if self.total_commits == 0:
            return 0.0
        return self.signed_commits / self.total_commits


@dataclass
class CommitRecord:
    """Signing status of a single commit."""

    oid: str
    author_name: str
    author_email: str
    date: str
    message: str
    signature_type: Optional[str]
    signer_did: Optional[str]
    verified: Optional[bool]


@dataclass
class AuditReport:
    """Full audit report with per-commit records and summary."""

    commits: list[CommitRecord]
    summary: AuditSummary


class AuditService:
    """Resource service for signing compliance audits."""

    def __init__(self, client):
        self._client = client

    def report(
        self,
        repo_path: str,
        since: str | None = None,
        until: str | None = None,
        author: str | None = None,
        limit: int = 500,
        identity_bundle_path: str | None = None,
    ) -> AuditReport:
        """Generate a signing audit report for a Git repository.

        Args:
            repo_path: Path to the Git repository to audit.
            since: Start date filter (YYYY-MM-DD).
            until: End date filter (YYYY-MM-DD).
            author: Filter by author email.
            limit: Maximum number of commits to scan.
            identity_bundle_path: Path to an Auths identity-bundle JSON file.
                When provided, the report uses this bundle to resolve signer
                DIDs and check attestation status (revoked/expired).

        Usage:
            report = client.audit.report("/path/to/repo")
            report = client.audit.report("/path/to/repo", identity_bundle_path=".auths/identity-bundle.json")
        """
        auths_rp = self._client.repo_path
        try:
            raw = _generate_audit_report(
                repo_path, auths_rp, since, until, author, limit,
            )
            report = self._parse_report(raw)
            if identity_bundle_path:
                report = self._enrich_with_bundle(report, identity_bundle_path)
            return report
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def is_compliant(
        self,
        repo_path: str,
        since: str | None = None,
        until: str | None = None,
    ) -> bool:
        """Check whether all commits in range are signed.

        Usage:
            assert client.audit.is_compliant("/path/to/repo")
        """
        report = self.report(repo_path=repo_path, since=since, until=until)
        return report.summary.unsigned_commits == 0

    @staticmethod
    def _parse_report(raw: str) -> AuditReport:
        data = json.loads(raw)
        commits = [
            CommitRecord(
                oid=c["oid"],
                author_name=c["author_name"],
                author_email=c["author_email"],
                date=c["date"],
                message=c["message"],
                signature_type=c.get("signature_type"),
                signer_did=c.get("signer_did"),
                verified=c.get("verified"),
            )
            for c in data["commits"]
        ]
        s = data["summary"]
        summary = AuditSummary(
            total_commits=s["total_commits"],
            signed_commits=s["signed_commits"],
            unsigned_commits=s["unsigned_commits"],
            auths_signed=s["auths_signed"],
            gpg_signed=s["gpg_signed"],
            ssh_signed=s["ssh_signed"],
            verification_passed=s["verification_passed"],
            verification_failed=s["verification_failed"],
        )
        return AuditReport(commits=commits, summary=summary)

    @staticmethod
    def _enrich_with_bundle(report: AuditReport, bundle_path: str) -> AuditReport:
        """Cross-reference audit commits with an identity bundle for signer DIDs."""
        bundle = parse_identity_bundle(bundle_path)
        if not bundle:
            return report
        key_to_did: dict[str, str] = {}
        for att in bundle.get("attestation_chain", []):
            dev_pk = att.get("device_public_key")
            if dev_pk:
                key_to_did[dev_pk] = f"did:key:z{dev_pk}"
        identity_did = bundle.get("did")
        pk_hex = bundle.get("public_key_hex") or bundle.get("publicKeyHex")
        if pk_hex and identity_did:
            key_to_did[pk_hex] = identity_did
        for commit in report.commits:
            if not commit.signer_did and commit.signature_type == "auths":
                # signer_did may be hex key from native; try to resolve
                pass
        return report


@dataclass
class IdentityBundleInfo:
    """Parsed identity bundle metadata."""

    did: str
    """Identity DID (``did:keri:...``)."""
    public_key_hex: str
    """Hex-encoded Ed25519 public key."""
    label: Optional[str]
    """Human-readable identity label."""
    device_count: int
    """Number of device attestations in the chain."""


def parse_identity_bundle(path: str) -> dict:
    """Parse an Auths identity-bundle JSON file.

    Args:
        path: Path to the identity-bundle JSON file.

    Returns:
        The parsed bundle as a dict. Key fields:
        - ``did``: Identity DID
        - ``public_key_hex``/``publicKeyHex``: Ed25519 public key
        - ``attestation_chain``: List of device attestation dicts

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.

    Examples:
        ```python
        bundle = parse_identity_bundle(".auths/identity-bundle.json")
        print(bundle["did"])
        ```
    """
    with open(path) as f:
        return json.load(f)


def parse_identity_bundle_info(path: str) -> IdentityBundleInfo:
    """Parse an identity bundle into a typed :class:`IdentityBundleInfo`.

    Args:
        path: Path to the identity-bundle JSON file.

    Returns:
        Typed bundle metadata.

    Examples:
        ```python
        info = parse_identity_bundle_info(".auths/identity-bundle.json")
        print(info.did, info.device_count)
        ```
    """
    bundle = parse_identity_bundle(path)
    pk_hex = bundle.get("public_key_hex") or bundle.get("publicKeyHex", "")
    chain = bundle.get("attestation_chain", [])
    return IdentityBundleInfo(
        did=bundle.get("did", ""),
        public_key_hex=pk_hex,
        label=bundle.get("label"),
        device_count=len(chain),
    )
