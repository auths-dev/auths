"""Tests for artifact attestation signing (fn-25.6)."""

import pytest

from auths import ArtifactSigningResult
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
