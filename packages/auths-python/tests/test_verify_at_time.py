"""Tests for time-pinned verification (fn-25.1)."""

import pytest

from auths import Auths, verify_at_time, verify_at_time_with_capability


class TestVerifyAtTimeFFI:

    def test_invalid_rfc3339_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time("{}", "a" * 64, "not-a-date")
        msg = str(exc_info.value)
        assert "RFC 3339" in msg
        assert "not-a-date" in msg

    def test_timezone_naive_string_raises_with_hint(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time("{}", "a" * 64, "2024-06-15 00:00:00")
        msg = str(exc_info.value)
        assert "RFC 3339" in msg
        assert "2024-06-15 00:00:00" in msg

    def test_future_timestamp_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time("{}", "a" * 64, "2099-01-01T00:00:00Z")
        msg = str(exc_info.value)
        assert "future" in msg.lower()

    def test_valid_timestamp_with_invalid_attestation(self):
        result = verify_at_time("{}", "a" * 64, "2024-06-15T00:00:00Z")
        assert not result.valid
        assert result.error is not None

    def test_invalid_hex_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time("{}", "not-hex", "2024-06-15T00:00:00Z")
        assert "hex" in str(exc_info.value).lower()

    def test_wrong_key_length_raises_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time("{}", "abcd", "2024-06-15T00:00:00Z")
        assert "length" in str(exc_info.value).lower()


class TestVerifyAtTimeWithCapabilityFFI:

    def test_invalid_timestamp_raises(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time_with_capability("{}", "a" * 64, "bad", "sign")
        assert "RFC 3339" in str(exc_info.value)

    def test_valid_timestamp_invalid_attestation(self):
        result = verify_at_time_with_capability(
            "{}", "a" * 64, "2024-06-15T00:00:00Z", "sign"
        )
        assert not result.valid

    def test_future_timestamp_raises(self):
        with pytest.raises(ValueError) as exc_info:
            verify_at_time_with_capability(
                "{}", "a" * 64, "2099-01-01T00:00:00Z", "sign"
            )
        assert "future" in str(exc_info.value).lower()


class TestClientVerifyAtTime:

    def test_verify_with_at_parameter(self):
        auths = Auths()
        result = auths.verify("{}", "a" * 64, at="2024-06-15T00:00:00Z")
        assert not result.valid

    def test_verify_with_at_and_capability(self):
        auths = Auths()
        result = auths.verify(
            "{}", "a" * 64,
            at="2024-06-15T00:00:00Z",
            required_capability="sign",
        )
        assert not result.valid

    def test_verify_with_invalid_at_raises(self):
        auths = Auths()
        with pytest.raises(Exception):
            auths.verify("{}", "a" * 64, at="not-a-date")


class TestImports:

    def test_verify_at_time_importable_from_verify_module(self):
        from auths.verify import verify_at_time as vat
        assert vat is not None

    def test_verify_at_time_with_capability_importable(self):
        from auths.verify import verify_at_time_with_capability as vatc
        assert vatc is not None

    def test_importable_from_top_level(self):
        from auths import verify_at_time, verify_at_time_with_capability
        assert verify_at_time is not None
        assert verify_at_time_with_capability is not None
