"""Typed presentation/credential verify (Epic D2 / fn-153.7).

Drives the in-process verify core against the cross-language fixture vectors emitted by the
Rust builders (fn-153.5), asserting the typed `Status` enum — never magic strings.
"""

from pathlib import Path

from auths import (
    CredentialStatus,
    PresentationStatus,
    verify_credential,
    verify_presentation,
)

FIXTURES = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "auths-verifier"
    / "tests"
    / "fixtures"
)


def _read(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_valid_presentation_carries_grant_facts() -> None:
    report = verify_presentation(_read("presentation_valid.json"))
    assert report.status is PresentationStatus.VALID
    assert report.subject is not None and report.subject.startswith("did:keri:")
    assert report.caps == ["sign"]


def test_valid_credential() -> None:
    report = verify_credential(_read("credential_valid.json"))
    assert report.status is CredentialStatus.VALID
    assert report.caps == ["sign"]


def test_revoked_credential_is_typed_status() -> None:
    report = verify_credential(_read("credential_revoked.json"))
    assert report.status is CredentialStatus.CREDENTIAL_REVOKED
    assert isinstance(report.revoked_at, int)


def test_malformed_input_returns_typed_report_not_exception() -> None:
    report = verify_presentation("{not json")
    assert report.status is PresentationStatus.MALFORMED_REQUEST
    assert report.message
