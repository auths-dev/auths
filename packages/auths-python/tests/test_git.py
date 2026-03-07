"""Tests for auths.git module."""

import json
import os
import sys
from subprocess import CompletedProcess
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

# Stub the native module so git.py can be tested without the Rust extension built.
_native_stub = ModuleType("auths._native")
for _name in (
    "VerificationResult", "VerificationStatus", "ChainLink",
    "VerificationReport", "verify_attestation", "verify_chain",
    "verify_device_authorization",
    "verify_attestation_with_capability", "verify_chain_with_capability",
    "verify_at_time", "verify_at_time_with_capability",
    "verify_chain_with_witnesses",
    "sign_bytes", "sign_action", "verify_action_envelope",
    "sign_as_identity", "sign_action_as_identity",
    "sign_commit", "sign_artifact", "sign_artifact_bytes",
    "publish_artifact",
    "get_token",
    "generate_allowed_signers_file",
    "verify_commit_native",
    "create_identity", "create_agent_identity", "delegate_agent",
    "link_device_to_identity", "revoke_device_from_identity",
    "DelegatedAgentBundle", "AgentIdentityBundle",
    "PyIdentityRotationResult", "rotate_identity_ffi",
    "PyDeviceExtension", "extend_device_authorization_ffi",
    "PyCompiledPolicy", "PyEvalContext", "PyDecision", "compile_policy",
    "PyArtifactPublishResult", "PyArtifactResult",
    "PyCommitSignResult",
    "PyCommitVerificationResult", "verify_commit_native",
    "PyAttestation", "list_attestations", "list_attestations_by_device",
    "get_latest_attestation",
):
    setattr(_native_stub, _name, MagicMock())
sys.modules.setdefault("auths._native", _native_stub)

from auths.git import (  # noqa: E402
    CommitResult,
    ErrorCode,
    LayoutError,
    LayoutInfo,
    VerifyResult,
    discover_layout,
    generate_allowed_signers,
    verify_commit_range,
)

UNSIGNED_COMMIT = b"tree abc123\nauthor A <a@b.com> 1700000000 +0000\ncommitter A <a@b.com> 1700000000 +0000\n\nsome message\n"
GPG_COMMIT = b"tree abc123\nauthor A <a@b.com> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n wsBc...\n -----END PGP SIGNATURE-----\ncommitter A <a@b.com> 1700000000 +0000\n\nsome message\n"
SSH_COMMIT = (
    b"tree abc123\n"
    b"author A <a@b.com> 1700000000 +0000\n"
    b"committer A <a@b.com> 1700000000 +0000\n"
    b"gpgsig -----BEGIN SSH SIGNATURE-----\n"
    b" U1NIU0lH...\n"
    b" -----END SSH SIGNATURE-----\n"
    b"\n"
    b"some message\n"
)
SHA1 = "a" * 40
SHA2 = "b" * 40
SIGNER_HEX = "ab" * 32


def _make_proc(returncode=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _make_proc_bytes(returncode=0, stdout=b"", stderr=b""):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _subprocess_router(calls):
    call_index = [0]

    def side_effect(cmd, **kwargs):
        idx = call_index[0]
        call_index[0] += 1
        if idx < len(calls):
            return calls[idx]
        raise RuntimeError(f"Unexpected subprocess call #{idx}: {cmd}")

    return side_effect


class _FakeNativeResult:
    """Mimics PyCommitVerificationResult from Rust FFI."""

    def __init__(self, valid=False, signer_hex=None, error=None, error_code=None):
        self.valid = valid
        self.signer_hex = signer_hex
        self.error = error
        self.error_code = error_code

    def __bool__(self):
        return self.valid


class TestErrorCode:

    def test_all_codes_are_strings(self):
        codes = [
            ErrorCode.UNSIGNED, ErrorCode.GPG_NOT_SUPPORTED, ErrorCode.UNKNOWN_SIGNER,
            ErrorCode.INVALID_SIGNATURE, ErrorCode.NO_ATTESTATION_FOUND,
            ErrorCode.DEVICE_REVOKED, ErrorCode.DEVICE_EXPIRED,
            ErrorCode.LAYOUT_DISCOVERY_FAILED,
        ]
        for code in codes:
            assert isinstance(code, str)

    def test_code_count(self):
        codes = [
            attr for attr in dir(ErrorCode)
            if not attr.startswith("_") and isinstance(getattr(ErrorCode, attr), str)
        ]
        assert len(codes) == 8


class TestCommitResult:

    def test_success_has_no_error_code(self):
        r = CommitResult(commit_sha=SHA1, is_valid=True, signer="alice")
        assert r.error_code is None

    def test_failure_carries_error_code(self):
        r = CommitResult(
            commit_sha=SHA1, is_valid=False,
            error="No signature found", error_code=ErrorCode.UNSIGNED,
        )
        assert r.error_code == "UNSIGNED"


class TestVerifyCommitRangeUnsigned:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    @patch("auths.git._hex_keys_from_allowed_signers_file", return_value=[])
    @patch("auths.git.os.path.isfile", return_value=True)
    def test_unsigned_commit(self, mock_isfile, mock_hex_keys, mock_run, mock_native):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),                 # rev-list
            _make_proc_bytes(stdout=UNSIGNED_COMMIT),       # cat-file
        ])
        mock_native.return_value = _FakeNativeResult(
            valid=False, error="unsigned commit", error_code=ErrorCode.UNSIGNED,
        )
        result = verify_commit_range("HEAD~1..HEAD")
        assert len(result.commits) == 1
        assert result.commits[0].error_code == ErrorCode.UNSIGNED
        assert not result.commits[0].is_valid
        assert not result.passed


class TestVerifyCommitRangeGPG:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    @patch("auths.git._hex_keys_from_allowed_signers_file", return_value=[])
    @patch("auths.git.os.path.isfile", return_value=True)
    def test_gpg_commit(self, mock_isfile, mock_hex_keys, mock_run, mock_native):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc_bytes(stdout=GPG_COMMIT),
        ])
        mock_native.return_value = _FakeNativeResult(
            valid=False, error="GPG not supported", error_code=ErrorCode.GPG_NOT_SUPPORTED,
        )
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].error_code == ErrorCode.GPG_NOT_SUPPORTED


class TestVerifyCommitRangeUnknownSigner:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    @patch("auths.git._hex_keys_from_allowed_signers_file", return_value=[])
    @patch("auths.git.os.path.isfile", return_value=True)
    def test_unknown_signer(self, mock_isfile, mock_hex_keys, mock_run, mock_native):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc_bytes(stdout=SSH_COMMIT),
        ])
        mock_native.return_value = _FakeNativeResult(
            valid=False, error="unknown signer", error_code=ErrorCode.UNKNOWN_SIGNER,
        )
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].error_code == ErrorCode.UNKNOWN_SIGNER


class TestVerifyCommitRangeValid:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    @patch("auths.git._hex_keys_from_allowed_signers_file", return_value=[])
    @patch("auths.git.os.path.isfile", return_value=True)
    def test_valid_commit(self, mock_isfile, mock_hex_keys, mock_run, mock_native):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc_bytes(stdout=SSH_COMMIT),
        ])
        mock_native.return_value = _FakeNativeResult(valid=True, signer_hex=SIGNER_HEX)
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].is_valid
        assert result.commits[0].signer == SIGNER_HEX
        assert result.passed


class TestPolicyModes:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    @patch("auths.git._hex_keys_from_allowed_signers_file", return_value=[])
    @patch("auths.git.os.path.isfile", return_value=True)
    def test_warn_mode_passes_on_unsigned(self, mock_isfile, mock_hex_keys, mock_run, mock_native):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc_bytes(stdout=UNSIGNED_COMMIT),
        ])
        mock_native.return_value = _FakeNativeResult(
            valid=False, error="unsigned", error_code=ErrorCode.UNSIGNED,
        )
        result = verify_commit_range("HEAD~1..HEAD", mode="warn")
        assert result.passed
        assert "warn mode" in result.summary

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="mode must be"):
            verify_commit_range("HEAD~1..HEAD", mode="strict")


class TestDiscoverLayout:

    def test_bundle_file_found(self, tmp_path):
        auths_dir = tmp_path / ".auths"
        auths_dir.mkdir()
        bundle = auths_dir / "identity-bundle.json"
        bundle.write_text('{"identity_did": "did:keri:test"}')
        info = discover_layout(str(tmp_path))
        assert info.source == "file"
        assert info.bundle == str(bundle)

    @patch("auths.git.subprocess.run")
    def test_nothing_found_raises(self, mock_run, tmp_path):
        mock_run.return_value = _make_proc(stdout="")
        with pytest.raises(LayoutError) as exc_info:
            discover_layout(str(tmp_path))
        assert exc_info.value.code == ErrorCode.LAYOUT_DISCOVERY_FAILED


DEVICE_PK_HEX = "cd" * 32
DEVICE_DID = "did:key:z6DeviceAAA"


def _make_bundle(tmp_path, attestations=None, identity_pk_hex=None):
    if identity_pk_hex is None:
        identity_pk_hex = "ab" * 32
    bundle = {
        "identity_did": "did:keri:root",
        "public_key_hex": identity_pk_hex,
        "attestation_chain": attestations or [],
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    return str(path)


class TestAttestationRevoked:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    def test_revoked_device(self, mock_run, mock_native, tmp_path):
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": DEVICE_DID, "device_public_key": DEVICE_PK_HEX,
            "revoked": True, "timestamp": "2024-01-01T00:00:00Z",
        }])
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc_bytes(stdout=SSH_COMMIT),
        ])
        mock_native.return_value = _FakeNativeResult(valid=True, signer_hex=DEVICE_PK_HEX)
        result = verify_commit_range("HEAD~1..HEAD", identity_bundle=bundle_path)
        assert result.commits[0].error_code == ErrorCode.DEVICE_REVOKED


class TestAttestationExpired:

    @patch("auths._native.verify_commit_native")
    @patch("auths.git.subprocess.run")
    def test_expired_device(self, mock_run, mock_native, tmp_path):
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": DEVICE_DID, "device_public_key": DEVICE_PK_HEX,
            "revoked": False, "expires_at": "2020-01-01T00:00:00Z",
        }])
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc_bytes(stdout=SSH_COMMIT),
        ])
        mock_native.return_value = _FakeNativeResult(valid=True, signer_hex=DEVICE_PK_HEX)
        result = verify_commit_range("HEAD~1..HEAD", identity_bundle=bundle_path)
        assert result.commits[0].error_code == ErrorCode.DEVICE_EXPIRED


class TestGenerateAllowedSigners:

    def test_import(self):
        from auths.git import generate_allowed_signers  # noqa: F401

    def test_top_level_export(self):
        from auths import generate_allowed_signers as _gs
        assert callable(_gs)

    def test_nonexistent_repo_raises(self):
        native = sys.modules.get("auths._native")
        if isinstance(getattr(native, "generate_allowed_signers_file", None), MagicMock):
            pytest.skip("requires compiled native extension")
        with pytest.raises(RuntimeError):
            generate_allowed_signers("/nonexistent/path/auths_xyz_does_not_exist")
