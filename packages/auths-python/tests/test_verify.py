"""Tests for attestation verification functions."""

import pytest
from auths import (
    verify_attestation,
    verify_chain,
    verify_device_authorization,
    VerificationResult,
    VerificationReport,
    VerificationStatus,
    ChainLink,
)


class TestVerifyAttestation:

    def test_invalid_json_returns_error(self):
        result = verify_attestation("not valid json", "a" * 64)
        assert not result.valid
        assert result.error is not None
        assert "parse" in result.error.lower() or "json" in result.error.lower()

    def test_invalid_hex_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_attestation("{}", "not-hex")
        assert "hex" in str(exc_info.value).lower()

    def test_wrong_key_length_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_attestation("{}", "abcd")
        assert "length" in str(exc_info.value).lower()

    def test_verification_result_is_falsy_when_invalid(self):
        result = verify_attestation("{}", "a" * 64)
        assert not result
        assert not result.valid


class TestVerifyChain:

    def test_empty_chain_returns_report(self):
        report = verify_chain([], "a" * 64)
        assert isinstance(report, VerificationReport)
        assert isinstance(report.status, VerificationStatus)
        assert isinstance(report.chain, list)
        assert isinstance(report.warnings, list)

    def test_invalid_json_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_chain(["not valid json"], "a" * 64)
        assert "parse" in str(exc_info.value).lower()

    def test_invalid_root_key_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_chain([], "not-hex")
        assert "hex" in str(exc_info.value).lower()


class TestVerifyDeviceAuthorization:

    def test_empty_attestations_returns_report(self):
        report = verify_device_authorization(
            "did:keri:Eidentity", "did:key:zDevice", [], "a" * 64,
        )
        assert isinstance(report, VerificationReport)
        assert not report.is_valid()

    def test_invalid_json_raises_value_error(self):
        with pytest.raises(ValueError):
            verify_device_authorization(
                "did:keri:Eidentity", "did:key:zDevice", ["not valid json"], "a" * 64,
            )

    def test_invalid_pk_hex_raises_value_error(self):
        with pytest.raises(ValueError):
            verify_device_authorization(
                "did:keri:Eidentity", "did:key:zDevice", [], "not-hex",
            )


class TestTypes:

    def test_verification_status_types(self):
        report = verify_chain([], "a" * 64)
        status = report.status
        assert hasattr(status, "status_type")
        assert hasattr(status, "at")
        assert hasattr(status, "step")
        assert hasattr(status, "missing_link")
        assert hasattr(status, "is_valid")

    def test_chain_link_attributes(self):
        assert hasattr(ChainLink, "issuer")
        assert hasattr(ChainLink, "subject")
        assert hasattr(ChainLink, "valid")
        assert hasattr(ChainLink, "error")

    def test_verification_report_attributes(self):
        report = verify_chain([], "a" * 64)
        assert hasattr(report, "status")
        assert hasattr(report, "chain")
        assert hasattr(report, "warnings")
        assert hasattr(report, "is_valid")


class TestRepr:

    def test_verification_result_repr(self):
        result = verify_attestation("{}", "a" * 64)
        assert "VerificationResult" in repr(result)

    def test_verification_status_repr(self):
        report = verify_chain([], "a" * 64)
        assert "VerificationStatus" in repr(report.status)

    def test_verification_report_repr(self):
        report = verify_chain([], "a" * 64)
        assert "VerificationReport" in repr(report)
