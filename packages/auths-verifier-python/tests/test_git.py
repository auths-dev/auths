"""Tests for auths_verifier.git module."""

import json
import os
import sys
from subprocess import CompletedProcess
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

# Add the python source directory to the path so we can import auths_verifier.git
# without needing the native Rust extension (_native) to be built.
_python_src = os.path.join(os.path.dirname(__file__), "..", "python")
sys.path.insert(0, _python_src)

# Stub out the native module so __init__.py doesn't crash on import.
# We only need the names that __init__.py imports from _native.
_native_stub = ModuleType("auths_verifier._native")
for _name in (
    "VerificationResult", "VerificationStatus", "ChainLink",
    "VerificationReport", "verify_attestation", "verify_chain",
    "verify_device_authorization",
    "sign_bytes", "sign_action", "verify_action_envelope",
):
    setattr(_native_stub, _name, MagicMock())
sys.modules["auths_verifier._native"] = _native_stub

from auths_verifier.git import (  # noqa: E402
    CommitResult,
    ErrorCode,
    LayoutError,
    LayoutInfo,
    VerifyResult,
    discover_layout,
    verify_commit_range,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

# A minimal unsigned commit (no gpgsig header)
UNSIGNED_COMMIT = "tree abc123\nauthor A <a@b.com> 1700000000 +0000\ncommitter A <a@b.com> 1700000000 +0000\n\nsome message\n"

# A commit with a PGP signature
GPG_COMMIT = "tree abc123\nauthor A <a@b.com> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n wsBc...\n -----END PGP SIGNATURE-----\ncommitter A <a@b.com> 1700000000 +0000\n\nsome message\n"

# A commit with an SSH signature
SSH_COMMIT = (
    "tree abc123\n"
    "author A <a@b.com> 1700000000 +0000\n"
    "committer A <a@b.com> 1700000000 +0000\n"
    "gpgsig -----BEGIN SSH SIGNATURE-----\n"
    " U1NIU0lH...\n"
    " -----END SSH SIGNATURE-----\n"
    "\n"
    "some message\n"
)

SHA1 = "a" * 40
SHA2 = "b" * 40


def _make_proc(returncode=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _subprocess_router(calls):
    """Return a side_effect function that routes by command prefix."""
    call_index = [0]

    def side_effect(cmd, **kwargs):
        idx = call_index[0]
        call_index[0] += 1
        if idx < len(calls):
            return calls[idx]
        raise RuntimeError(f"Unexpected subprocess call #{idx}: {cmd}")

    return side_effect


# ---------------------------------------------------------------------------
# ErrorCode
# ---------------------------------------------------------------------------


class TestErrorCode:
    """Verify ErrorCode constants are stable strings."""

    def test_all_codes_are_strings(self):
        codes = [
            ErrorCode.UNSIGNED,
            ErrorCode.GPG_NOT_SUPPORTED,
            ErrorCode.UNKNOWN_SIGNER,
            ErrorCode.INVALID_SIGNATURE,
            ErrorCode.NO_ATTESTATION_FOUND,
            ErrorCode.DEVICE_REVOKED,
            ErrorCode.DEVICE_EXPIRED,
            ErrorCode.LAYOUT_DISCOVERY_FAILED,
        ]
        for code in codes:
            assert isinstance(code, str)

    def test_code_count(self):
        """There should be exactly 8 error codes."""
        codes = [
            attr
            for attr in dir(ErrorCode)
            if not attr.startswith("_") and isinstance(getattr(ErrorCode, attr), str)
        ]
        assert len(codes) == 8


# ---------------------------------------------------------------------------
# CommitResult with error_code
# ---------------------------------------------------------------------------


class TestCommitResult:
    """Verify CommitResult carries error_code correctly."""

    def test_success_has_no_error_code(self):
        r = CommitResult(commit_sha=SHA1, is_valid=True, signer="alice")
        assert r.error_code is None

    def test_failure_carries_error_code(self):
        r = CommitResult(
            commit_sha=SHA1,
            is_valid=False,
            error="No signature found",
            error_code=ErrorCode.UNSIGNED,
        )
        assert r.error_code == "UNSIGNED"


# ---------------------------------------------------------------------------
# verify_commit_range — single commit scenarios
# ---------------------------------------------------------------------------


class TestVerifyCommitRangeUnsigned:
    """Unsigned commit should produce UNSIGNED error code."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_unsigned_commit(self, mock_isfile, mock_run):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),     # git rev-list
            _make_proc(stdout=UNSIGNED_COMMIT),  # git cat-file
        ])
        result = verify_commit_range("HEAD~1..HEAD")
        assert isinstance(result, VerifyResult)
        assert len(result.commits) == 1
        assert result.commits[0].error_code == ErrorCode.UNSIGNED
        assert not result.commits[0].is_valid
        assert not result.passed
        assert result.mode == "enforce"


class TestVerifyCommitRangeGPG:
    """GPG-signed commit should produce GPG_NOT_SUPPORTED error code."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_gpg_commit(self, mock_isfile, mock_run):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),  # git rev-list
            _make_proc(stdout=GPG_COMMIT),   # git cat-file
        ])
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].error_code == ErrorCode.GPG_NOT_SUPPORTED


class TestVerifyCommitRangeUnknownSigner:
    """Signature from non-allowed signer should produce UNKNOWN_SIGNER."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_unknown_signer(self, mock_isfile, mock_run):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),  # git rev-list
            _make_proc(stdout=SSH_COMMIT),   # git cat-file
            _make_proc(returncode=1, stderr="no principal matched"),  # ssh-keygen verify
        ])
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].error_code == ErrorCode.UNKNOWN_SIGNER


class TestVerifyCommitRangeInvalidSignature:
    """ssh-keygen failure (not principal-related) should produce INVALID_SIGNATURE."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_invalid_signature(self, mock_isfile, mock_run):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),  # git rev-list
            _make_proc(stdout=SSH_COMMIT),   # git cat-file
            _make_proc(returncode=1, stderr="Could not verify signature"),  # ssh-keygen verify
        ])
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].error_code == ErrorCode.INVALID_SIGNATURE


class TestVerifyCommitRangeValid:
    """Valid SSH-signed commit should have is_valid=True and no error_code."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_valid_commit(self, mock_isfile, mock_run):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),  # git rev-list
            _make_proc(stdout=SSH_COMMIT),   # git cat-file
            _make_proc(stdout="Good signature"),  # ssh-keygen verify
            _make_proc(stdout="alice@example.com"),  # ssh-keygen find-principals
        ])
        result = verify_commit_range("HEAD~1..HEAD")
        assert result.commits[0].is_valid
        assert result.commits[0].error_code is None
        assert result.commits[0].signer == "alice@example.com"
        assert result.passed
        assert "1/1 commits verified" in result.summary


# ---------------------------------------------------------------------------
# Policy modes
# ---------------------------------------------------------------------------


class TestPolicyModes:
    """Verify warn/enforce mode behavior."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_enforce_mode_fails_on_unsigned(self, mock_isfile, mock_run):
        """enforce mode: one unsigned commit should make passed=False."""
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=UNSIGNED_COMMIT),
        ])
        result = verify_commit_range("HEAD~1..HEAD", mode="enforce")
        assert not result.passed
        assert result.mode == "enforce"
        assert "failed" in result.summary

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_warn_mode_passes_on_unsigned(self, mock_isfile, mock_run):
        """warn mode: one unsigned commit should still have passed=True."""
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=UNSIGNED_COMMIT),
        ])
        result = verify_commit_range("HEAD~1..HEAD", mode="warn")
        assert result.passed
        assert result.mode == "warn"
        assert "warn mode" in result.summary

    def test_invalid_mode_raises(self):
        """Invalid mode should raise ValueError."""
        with pytest.raises(ValueError, match="mode must be"):
            verify_commit_range("HEAD~1..HEAD", mode="strict")


# ---------------------------------------------------------------------------
# Empty commit range
# ---------------------------------------------------------------------------


class TestEmptyRange:
    """Empty commit range should return passed=True with no error_code."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_empty_range(self, mock_isfile, mock_run):
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=""),  # git rev-list returns nothing
        ])
        result = verify_commit_range("origin/main..HEAD")
        assert result.passed
        assert len(result.commits) == 0
        assert result.summary == "No commits to verify"


# ---------------------------------------------------------------------------
# Layout discovery
# ---------------------------------------------------------------------------


class TestDiscoverLayout:
    """Verify discover_layout() finds identity data or raises LayoutError."""

    def test_bundle_file_found(self, tmp_path):
        """Should find .auths/identity-bundle.json when it exists."""
        auths_dir = tmp_path / ".auths"
        auths_dir.mkdir()
        bundle = auths_dir / "identity-bundle.json"
        bundle.write_text('{"identity_did": "did:keri:test"}')

        info = discover_layout(str(tmp_path))
        assert info.source == "file"
        assert info.bundle == str(bundle)

    @patch("auths_verifier.git.subprocess.run")
    def test_git_refs_found(self, mock_run, tmp_path):
        """Should find refs/auths/* when no bundle file exists."""
        mock_run.return_value = _make_proc(stdout="refs/auths/identity\nrefs/auths/devices\n")

        info = discover_layout(str(tmp_path))
        assert info.source == "git-refs"
        assert len(info.refs) == 2

    @patch("auths_verifier.git.subprocess.run")
    def test_nothing_found_raises(self, mock_run, tmp_path):
        """Should raise LayoutError when no identity data exists."""
        mock_run.return_value = _make_proc(stdout="")

        with pytest.raises(LayoutError) as exc_info:
            discover_layout(str(tmp_path))
        assert exc_info.value.code == ErrorCode.LAYOUT_DISCOVERY_FAILED
        assert "export-bundle" in str(exc_info.value)


class TestLayoutDiscoveryIntegration:
    """Verify layout discovery integrates into verify_commit_range()."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=False)
    def test_layout_failure_returns_sentinel(self, mock_isfile, mock_run):
        """When no layout found, return CommitResult with <layout> sentinel."""
        # discover_layout calls subprocess for git for-each-ref
        mock_run.return_value = _make_proc(stdout="")

        result = verify_commit_range("HEAD~1..HEAD")
        assert len(result.commits) == 1
        assert result.commits[0].commit_sha == "<layout>"
        assert result.commits[0].error_code == ErrorCode.LAYOUT_DISCOVERY_FAILED
        assert not result.passed  # enforce mode default

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=False)
    def test_git_refs_found_but_not_supported(self, mock_isfile, mock_run):
        """When refs/auths/* found but no bundle, return explicit not-supported error."""
        mock_run.return_value = _make_proc(stdout="refs/auths/identity\n")

        result = verify_commit_range("HEAD~1..HEAD")
        assert len(result.commits) == 1
        assert result.commits[0].commit_sha == "<layout>"
        assert result.commits[0].error_code == ErrorCode.LAYOUT_DISCOVERY_FAILED
        assert "git-ref-based verification is not yet supported" in result.commits[0].error
        assert "export-bundle" in result.commits[0].error


# ---------------------------------------------------------------------------
# Identity bundle loading
# ---------------------------------------------------------------------------


class TestIdentityBundle:
    """Verify identity bundle creates correct allowed_signers."""

    @patch("auths_verifier.git.subprocess.run")
    def test_bundle_loads_and_verifies(self, mock_run, tmp_path):
        """Should load bundle, create temp signers, and verify."""
        bundle = tmp_path / "bundle.json"
        bundle.write_text('{"public_key_hex": "' + "ab" * 32 + '"}')

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),     # git rev-list
            _make_proc(stdout=UNSIGNED_COMMIT),  # git cat-file (unsigned)
        ])

        result = verify_commit_range(
            "HEAD~1..HEAD",
            identity_bundle=str(bundle),
        )
        assert len(result.commits) == 1
        assert result.commits[0].error_code == ErrorCode.UNSIGNED


# ---------------------------------------------------------------------------
# Attestation chain verification (DEVICE_REVOKED, DEVICE_EXPIRED, NO_ATTESTATION_FOUND)
# ---------------------------------------------------------------------------


def _make_bundle(tmp_path, attestations=None, identity_pk_hex=None):
    """Create a temporary identity-bundle.json with an attestation chain."""
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


# A device key distinct from the root identity key
DEVICE_PK_HEX = "cd" * 32
DEVICE_DID = "did:key:z6DeviceAAA"


class TestAttestationRevoked:
    """Bundle with a revoked device attestation should produce DEVICE_REVOKED."""

    @patch("auths_verifier.git.subprocess.run")
    def test_revoked_device(self, mock_run, tmp_path):
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": DEVICE_DID,
            "device_public_key": DEVICE_PK_HEX,
            "revoked": True,
            "timestamp": "2024-01-01T00:00:00Z",
        }])

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),          # git rev-list
            _make_proc(stdout=SSH_COMMIT),            # git cat-file
            _make_proc(stdout="Good signature"),      # ssh-keygen verify
            _make_proc(stdout=DEVICE_DID),            # ssh-keygen find-principals
        ])
        result = verify_commit_range(
            "HEAD~1..HEAD", identity_bundle=bundle_path,
        )
        assert len(result.commits) == 1
        assert not result.commits[0].is_valid
        assert result.commits[0].error_code == ErrorCode.DEVICE_REVOKED
        assert result.commits[0].signer == DEVICE_DID
        assert "revoked" in result.commits[0].error


class TestAttestationExpired:
    """Bundle with an expired device attestation should produce DEVICE_EXPIRED."""

    @patch("auths_verifier.git.subprocess.run")
    def test_expired_device(self, mock_run, tmp_path):
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": DEVICE_DID,
            "device_public_key": DEVICE_PK_HEX,
            "revoked": False,
            "expires_at": "2020-01-01T00:00:00Z",  # well in the past
        }])

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=SSH_COMMIT),
            _make_proc(stdout="Good signature"),
            _make_proc(stdout=DEVICE_DID),
        ])
        result = verify_commit_range(
            "HEAD~1..HEAD", identity_bundle=bundle_path,
        )
        assert len(result.commits) == 1
        assert not result.commits[0].is_valid
        assert result.commits[0].error_code == ErrorCode.DEVICE_EXPIRED
        assert result.commits[0].signer == DEVICE_DID
        assert "expired" in result.commits[0].error


class TestAttestationValid:
    """Bundle with a valid (non-revoked, non-expired) attestation should pass."""

    @patch("auths_verifier.git.subprocess.run")
    def test_valid_device_attestation(self, mock_run, tmp_path):
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": DEVICE_DID,
            "device_public_key": DEVICE_PK_HEX,
            "revoked": False,
            "expires_at": "2099-12-31T23:59:59Z",  # far future
        }])

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=SSH_COMMIT),
            _make_proc(stdout="Good signature"),
            _make_proc(stdout=DEVICE_DID),
        ])
        result = verify_commit_range(
            "HEAD~1..HEAD", identity_bundle=bundle_path,
        )
        assert len(result.commits) == 1
        assert result.commits[0].is_valid
        assert result.commits[0].error_code is None
        assert result.commits[0].signer == DEVICE_DID

    @patch("auths_verifier.git.subprocess.run")
    def test_no_expires_at_is_valid(self, mock_run, tmp_path):
        """Attestation with no expires_at should be treated as non-expiring."""
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": DEVICE_DID,
            "device_public_key": DEVICE_PK_HEX,
            "revoked": False,
        }])

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=SSH_COMMIT),
            _make_proc(stdout="Good signature"),
            _make_proc(stdout=DEVICE_DID),
        ])
        result = verify_commit_range(
            "HEAD~1..HEAD", identity_bundle=bundle_path,
        )
        assert result.commits[0].is_valid
        assert result.commits[0].error_code is None


class TestNoAttestationFound:
    """Signer DID not in attestation chain should produce NO_ATTESTATION_FOUND."""

    @patch("auths_verifier.git.subprocess.run")
    def test_signer_not_in_chain(self, mock_run, tmp_path):
        """Device DID verified by ssh-keygen but has no attestation entry."""
        bundle_path = _make_bundle(tmp_path, attestations=[{
            "subject": "did:key:z6SomeOtherDevice",
            "device_public_key": "ef" * 32,
            "revoked": False,
        }])

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=SSH_COMMIT),
            _make_proc(stdout="Good signature"),
            _make_proc(stdout=DEVICE_DID),  # returns a DID not in the chain
        ])
        result = verify_commit_range(
            "HEAD~1..HEAD", identity_bundle=bundle_path,
        )
        assert len(result.commits) == 1
        assert not result.commits[0].is_valid
        assert result.commits[0].error_code == ErrorCode.NO_ATTESTATION_FOUND
        assert result.commits[0].signer == DEVICE_DID

    @patch("auths_verifier.git.subprocess.run")
    def test_root_key_signer_passes(self, mock_run, tmp_path):
        """Signer matched root identity key (wildcard) should pass through."""
        bundle_path = _make_bundle(tmp_path, attestations=[])

        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n"),
            _make_proc(stdout=SSH_COMMIT),
            _make_proc(stdout="Good signature"),
            _make_proc(returncode=1, stdout=""),  # find-principals fails → "allowed signer"
        ])
        result = verify_commit_range(
            "HEAD~1..HEAD", identity_bundle=bundle_path,
        )
        assert result.commits[0].is_valid
        assert result.commits[0].error_code is None


# ---------------------------------------------------------------------------
# Multiple commits
# ---------------------------------------------------------------------------


class TestMultipleCommits:
    """Verify behavior with multiple commits in range."""

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_mixed_results_enforce(self, mock_isfile, mock_run):
        """One unsigned + one valid in enforce mode: passed=False.

        git rev-list returns newest-first (SHA1, SHA2), but verify_commit_range
        reverses to chronological order, so SHA2 is verified first.
        """
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n{SHA2}\n"),  # git rev-list (newest first)
            # After reversal: SHA2 first, SHA1 second
            _make_proc(stdout=UNSIGNED_COMMIT),        # cat-file SHA2 (unsigned)
            _make_proc(stdout=SSH_COMMIT),             # cat-file SHA1 (signed)
            _make_proc(stdout="Good signature"),       # ssh-keygen verify
            _make_proc(stdout="alice@example.com"),    # ssh-keygen find-principals
        ])
        result = verify_commit_range("HEAD~2..HEAD")
        assert len(result.commits) == 2
        assert not result.commits[0].is_valid  # SHA2 unsigned (chronologically first)
        assert result.commits[1].is_valid      # SHA1 valid (chronologically second)
        assert not result.passed
        assert "1/2 commits failed" in result.summary

    @patch("auths_verifier.git.subprocess.run")
    @patch("auths_verifier.git.os.path.isfile", return_value=True)
    def test_mixed_results_warn(self, mock_isfile, mock_run):
        """One unsigned + one valid in warn mode: passed=True."""
        mock_run.side_effect = _subprocess_router([
            _make_proc(stdout=f"{SHA1}\n{SHA2}\n"),
            # After reversal: SHA2 first, SHA1 second
            _make_proc(stdout=UNSIGNED_COMMIT),
            _make_proc(stdout=SSH_COMMIT),
            _make_proc(stdout="Good signature"),
            _make_proc(stdout="alice@example.com"),
        ])
        result = verify_commit_range("HEAD~2..HEAD", mode="warn")
        assert result.passed
        assert "warn mode" in result.summary
