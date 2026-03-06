"""Tests for attestation listing and query (fn-25.5)."""

import pytest

from auths import Attestation, AttestationService
from auths.attestation_query import Attestation as AttestationFromModule
from auths.attestation_query import AttestationService as AttestationServiceFromModule


class TestAttestationDataclass:

    def test_attestation_fields(self):
        att = Attestation(
            rid="abc123",
            issuer="did:keri:issuer",
            subject="did:key:zDevice",
            device_did="did:key:zDevice",
            capabilities=["sign", "deploy"],
            signer_type="Human",
            expires_at="2025-06-15T00:00:00Z",
            revoked_at=None,
            created_at="2025-01-01T00:00:00Z",
            delegated_by=None,
            json='{"rid":"abc123"}',
        )
        assert att.rid == "abc123"
        assert att.issuer == "did:keri:issuer"
        assert att.subject == "did:key:zDevice"
        assert att.device_did == "did:key:zDevice"
        assert att.capabilities == ["sign", "deploy"]
        assert att.signer_type == "Human"

    def test_is_active_when_not_revoked(self):
        att = Attestation(
            rid="r1", issuer="i", subject="s", device_did="s",
            capabilities=[], signer_type=None, expires_at=None,
            revoked_at=None, created_at=None, delegated_by=None, json="{}",
        )
        assert att.is_active is True
        assert att.is_revoked is False

    def test_is_revoked_when_revoked(self):
        att = Attestation(
            rid="r1", issuer="i", subject="s", device_did="s",
            capabilities=[], signer_type=None, expires_at=None,
            revoked_at="2025-01-01T00:00:00Z", created_at=None,
            delegated_by=None, json="{}",
        )
        assert att.is_active is False
        assert att.is_revoked is True

    def test_repr_shows_status_and_caps(self):
        att = Attestation(
            rid="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            issuer="did:keri:issuer",
            subject="did:key:z6MkTestDevice1234567890",
            device_did="did:key:z6MkTestDevice1234567890",
            capabilities=["sign", "deploy", "admin", "rotate"],
            signer_type="Agent",
            expires_at=None,
            revoked_at=None,
            created_at=None,
            delegated_by=None,
            json="{}",
        )
        r = repr(att)
        assert "Attestation" in r
        assert "active" in r
        assert "+1 more" in r

    def test_repr_revoked(self):
        att = Attestation(
            rid="short",
            issuer="i", subject="s", device_did="s",
            capabilities=[], signer_type=None, expires_at=None,
            revoked_at="2025-01-01T00:00:00Z", created_at=None,
            delegated_by=None, json="{}",
        )
        assert "revoked" in repr(att)


class TestImports:

    def test_attestation_importable_from_top_level(self):
        from auths import Attestation
        assert Attestation is not None

    def test_attestation_service_importable_from_top_level(self):
        from auths import AttestationService
        assert AttestationService is not None

    def test_attestation_importable_from_module(self):
        from auths.attestation_query import Attestation
        assert Attestation is not None

    def test_attestation_service_importable_from_module(self):
        from auths.attestation_query import AttestationService
        assert AttestationService is not None

    def test_ffi_functions_importable(self):
        from auths._native import (
            list_attestations,
            list_attestations_by_device,
            get_latest_attestation,
        )
        assert list_attestations is not None
        assert list_attestations_by_device is not None
        assert get_latest_attestation is not None
