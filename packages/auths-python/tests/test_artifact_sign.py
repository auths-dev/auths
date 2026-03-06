"""Tests for artifact attestation signing and publishing."""

from unittest.mock import MagicMock

import pytest

from auths import ArtifactPublishResult, ArtifactSigningResult
from auths.artifact import ArtifactPublishResult as ArtifactPublishFromModule
from auths.artifact import ArtifactSigningResult as ArtifactFromModule


class TestArtifactSigningResult:

    def test_fields(self):
        r = ArtifactSigningResult(
            attestation_json='{"rid":"sha256:abc"}',
            rid="sha256:abc123def456",
            digest="abc123def456",
            file_size=1024,
        )
        assert r.attestation_json == '{"rid":"sha256:abc"}'
        assert r.rid == "sha256:abc123def456"
        assert r.digest == "abc123def456"
        assert r.file_size == 1024

    def test_repr_shows_size(self):
        r = ArtifactSigningResult(
            attestation_json="{}",
            rid="sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            digest="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            file_size=2_500_000,
        )
        s = repr(r)
        assert "ArtifactSigningResult" in s
        assert "MB" in s

    def test_repr_small_file(self):
        r = ArtifactSigningResult(
            attestation_json="{}",
            rid="sha256:short",
            digest="short",
            file_size=512,
        )
        s = repr(r)
        assert "512 B" in s

    def test_repr_kb(self):
        r = ArtifactSigningResult(
            attestation_json="{}",
            rid="sha256:x",
            digest="x",
            file_size=15_360,
        )
        s = repr(r)
        assert "KB" in s


class TestImports:

    def test_importable_from_top_level(self):
        from auths import ArtifactSigningResult
        assert ArtifactSigningResult is not None

    def test_importable_from_module(self):
        from auths.artifact import ArtifactSigningResult
        assert ArtifactSigningResult is not None

    def test_ffi_functions_importable(self):
        from auths._native import sign_artifact, sign_artifact_bytes
        assert sign_artifact is not None
        assert sign_artifact_bytes is not None

    def test_sign_artifact_nonexistent_file(self):
        from auths._native import sign_artifact
        with pytest.raises(FileNotFoundError, match="not found"):
            sign_artifact("/nonexistent/path/file.bin", "main", "/tmp", None, None, None)


class TestArtifactPublishResult:

    def test_fields(self):
        r = ArtifactPublishResult(
            attestation_rid="rid-abc",
            package_name="npm:react@18.3.0",
            signer_did="did:keri:abc",
        )
        assert r.attestation_rid == "rid-abc"
        assert r.package_name == "npm:react@18.3.0"
        assert r.signer_did == "did:keri:abc"

    def test_package_name_none(self):
        r = ArtifactPublishResult(attestation_rid="x", package_name=None, signer_did="y")
        assert r.package_name is None

    def test_repr_truncates_long_rid(self):
        long_rid = "a" * 60
        r = ArtifactPublishResult(attestation_rid=long_rid, package_name=None, signer_did="did:keri:z")
        assert len(repr(r)) < len(long_rid) + 40
        assert "..." in repr(r)

    def test_repr_with_package(self):
        r = ArtifactPublishResult(attestation_rid="rid", package_name="npm:x", signer_did="did:keri:abc")
        assert "npm:x" in repr(r)

    def test_repr_without_package(self):
        r = ArtifactPublishResult(attestation_rid="rid", package_name=None, signer_did="did:keri:abc")
        assert "pkg" not in repr(r)

    def test_top_level_export(self):
        assert ArtifactPublishResult is ArtifactPublishFromModule


class TestPublishArtifactNative:

    def test_import(self):
        from auths._native import publish_artifact  # noqa: F401

    def test_invalid_json_raises(self):
        from auths._native import publish_artifact
        with pytest.raises((ValueError, RuntimeError)):
            publish_artifact("not-json", "http://localhost", None)

    def test_unreachable_host_raises(self):
        from auths._native import publish_artifact
        with pytest.raises((RuntimeError, OSError, ConnectionError)):
            publish_artifact('{"attestation":"x"}', "http://127.0.0.1:1", None)


class TestPublishArtifactClient:

    def test_method_exists(self):
        from auths import Auths
        assert hasattr(Auths, "publish_artifact")

    def test_returns_result_type(self, monkeypatch):
        import auths._native as native
        mock_raw = MagicMock()
        mock_raw.attestation_rid = "rid-1"
        mock_raw.package_name = "npm:foo"
        mock_raw.signer_did = "did:keri:abc"
        monkeypatch.setattr(native, "publish_artifact", lambda *_: mock_raw)
        from auths import Auths
        result = Auths().publish_artifact('{"a":1}', registry_url="http://x")
        assert isinstance(result, ArtifactPublishResult)
        assert result.attestation_rid == "rid-1"

    def test_duplicate_raises_storage_error(self, monkeypatch):
        import auths._native as native

        def _raise(*_):
            raise RuntimeError("duplicate_attestation: artifact attestation already published (duplicate RID)")

        monkeypatch.setattr(native, "publish_artifact", _raise)
        from auths import Auths
        from auths._errors import StorageError
        with pytest.raises(StorageError) as exc_info:
            Auths().publish_artifact('{"a":1}', registry_url="http://x")
        assert exc_info.value.code == "duplicate_attestation"

    def test_verification_failed_raises_verification_error(self, monkeypatch):
        import auths._native as native

        def _raise(*_):
            raise RuntimeError("verification_failed: signature rejected by registry")

        monkeypatch.setattr(native, "publish_artifact", _raise)
        from auths import Auths
        from auths._errors import VerificationError
        with pytest.raises(VerificationError) as exc_info:
            Auths().publish_artifact('{"a":1}', registry_url="http://x")
        assert exc_info.value.code == "verification_failed"

    def test_network_error_raises_network_error(self, monkeypatch):
        import auths._native as native

        def _raise(*_):
            raise RuntimeError("registry unreachable: connection refused")

        monkeypatch.setattr(native, "publish_artifact", _raise)
        from auths import Auths
        from auths._errors import NetworkError
        with pytest.raises(NetworkError):
            Auths().publish_artifact('{"a":1}', registry_url="http://x")
