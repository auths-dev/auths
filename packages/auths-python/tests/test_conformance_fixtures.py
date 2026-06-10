"""Cross-language conformance: shared fixture vectors emitted by the Rust verifier.

Mirrors packages/auths-verifier-go/verifier_fixtures_test.go — loads the same
committed fixtures from crates/auths-verifier/tests/fixtures/ and asserts this
binding's typed verdicts match the canonical Rust verdicts (valid / revoked /
malformed), proving the Python binding does not diverge.

Skips when the native module is not built (run ``maturin develop``) or when the
fixtures are unavailable (package vendored outside the monorepo), matching the
Go test's skip behaviour.
"""

from pathlib import Path

import pytest

pytest.importorskip(
    "auths._native",
    reason="auths native module not built — run `maturin develop` first",
)

from auths import (  # noqa: E402
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
    path = FIXTURES / name
    if not path.is_file():
        pytest.skip(f"fixture {name} not available — run from the monorepo")
    return path.read_text()


def test_valid_presentation_fixture_matches_rust_verdict() -> None:
    report = verify_presentation(_read("presentation_valid.json"))
    assert report.status is PresentationStatus.VALID
    assert report.subject is not None and report.subject.startswith("did:keri:")
    assert report.caps == ["sign"]


def test_valid_credential_fixture_matches_rust_verdict() -> None:
    report = verify_credential(_read("credential_valid.json"))
    assert report.status is CredentialStatus.VALID
    assert report.caps == ["sign"]


def test_revoked_credential_fixture_is_rejected_with_typed_status() -> None:
    report = verify_credential(_read("credential_revoked.json"))
    assert report.status is CredentialStatus.CREDENTIAL_REVOKED
    assert report.status is not CredentialStatus.VALID
    assert isinstance(report.revoked_at, int)


def test_malformed_input_returns_typed_report_not_exception() -> None:
    report = verify_presentation("{not json")
    assert report.status is PresentationStatus.MALFORMED_REQUEST
    assert report.message
