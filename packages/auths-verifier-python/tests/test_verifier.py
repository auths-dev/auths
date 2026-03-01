"""Tests for auths_verifier Python package."""

import pytest
from auths_verifier import (
    verify_attestation,
    verify_chain,
    verify_device_authorization,
    VerificationResult,
    VerificationReport,
    VerificationStatus,
    ChainLink,
)


class TestVerifyAttestation:
    """Tests for verify_attestation function."""

    def test_invalid_json_returns_error(self):
        """Invalid JSON should return a VerificationResult with error."""
        result = verify_attestation("not valid json", "a" * 64)
        assert not result.valid
        assert result.error is not None
        assert "parse" in result.error.lower() or "json" in result.error.lower()

    def test_invalid_hex_raises_value_error(self):
        """Invalid hex should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            verify_attestation("{}", "not-hex")
        assert "hex" in str(exc_info.value).lower()

    def test_wrong_key_length_raises_value_error(self):
        """Wrong key length should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            verify_attestation("{}", "abcd")  # Too short
        assert "length" in str(exc_info.value).lower()

    def test_verification_result_is_falsy_when_invalid(self):
        """VerificationResult should be falsy when invalid."""
        result = verify_attestation("{}", "a" * 64)
        assert not result  # __bool__ returns False
        assert not result.valid


class TestVerifyChain:
    """Tests for verify_chain function."""

    def test_empty_chain_returns_report(self):
        """Empty chain should return a valid report."""
        report = verify_chain([], "a" * 64)
        assert isinstance(report, VerificationReport)
        assert isinstance(report.status, VerificationStatus)
        assert isinstance(report.chain, list)
        assert isinstance(report.warnings, list)

    def test_invalid_json_raises_value_error(self):
        """Invalid JSON in chain should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            verify_chain(["not valid json"], "a" * 64)
        assert "parse" in str(exc_info.value).lower()

    def test_invalid_root_key_raises_value_error(self):
        """Invalid root key should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            verify_chain([], "not-hex")
        assert "hex" in str(exc_info.value).lower()


class TestVerifyDeviceAuthorization:
    """Tests for verify_device_authorization function."""

    def test_empty_attestations_returns_report(self):
        """No attestations means device authorization fails."""
        report = verify_device_authorization(
            "did:key:identity",
            "did:key:device",
            [],
            "a" * 64,
        )
        assert isinstance(report, VerificationReport)
        assert not report.is_valid()

    def test_invalid_json_raises_value_error(self):
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError):
            verify_device_authorization(
                "did:key:identity",
                "did:key:device",
                ["not valid json"],
                "a" * 64,
            )

    def test_invalid_pk_hex_raises_value_error(self):
        """Invalid public key hex should raise ValueError."""
        with pytest.raises(ValueError):
            verify_device_authorization(
                "did:key:identity",
                "did:key:device",
                [],
                "not-hex",
            )


class TestTypes:
    """Tests for type definitions."""

    def test_verification_status_types(self):
        """VerificationStatus should have expected attributes."""
        # Create a report to get a status object
        report = verify_chain([], "a" * 64)
        status = report.status

        assert hasattr(status, "status_type")
        assert hasattr(status, "at")
        assert hasattr(status, "step")
        assert hasattr(status, "missing_link")
        assert hasattr(status, "is_valid")

    def test_chain_link_attributes(self):
        """ChainLink should have expected attributes."""
        # We can't easily create a ChainLink directly,
        # so we verify the class exists and has the expected structure
        assert hasattr(ChainLink, "issuer")
        assert hasattr(ChainLink, "subject")
        assert hasattr(ChainLink, "valid")
        assert hasattr(ChainLink, "error")

    def test_verification_report_attributes(self):
        """VerificationReport should have expected attributes."""
        report = verify_chain([], "a" * 64)

        assert hasattr(report, "status")
        assert hasattr(report, "chain")
        assert hasattr(report, "warnings")
        assert hasattr(report, "is_valid")


class TestRepr:
    """Tests for string representations."""

    def test_verification_result_repr(self):
        """VerificationResult should have readable repr."""
        result = verify_attestation("{}", "a" * 64)
        repr_str = repr(result)
        assert "VerificationResult" in repr_str

    def test_verification_status_repr(self):
        """VerificationStatus should have readable repr."""
        report = verify_chain([], "a" * 64)
        repr_str = repr(report.status)
        assert "VerificationStatus" in repr_str

    def test_verification_report_repr(self):
        """VerificationReport should have readable repr."""
        report = verify_chain([], "a" * 64)
        repr_str = repr(report)
        assert "VerificationReport" in repr_str
