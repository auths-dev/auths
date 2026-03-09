"""Git commit signature verification using native Rust verification.

Enumerates commits via ``git rev-list``, reads raw commit objects via
``git cat-file``, and verifies SSH signatures natively through the
``auths._native.verify_commit_native`` FFI bridge — no ``ssh-keygen``
subprocess required.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone


def generate_allowed_signers(repo_path: str = "~/.auths") -> str:
    """Generate an allowed_signers file content from live Auths storage.

    Reads device attestations from the Git-backed identity store and
    formats them for ``gpg.ssh.allowedSignersFile``. Revoked attestations
    and devices with undecodable keys are silently skipped.

    Args:
        repo_path: Path to the Auths identity repository.

    Returns:
        Formatted allowed_signers file content, or an empty string if no
        attestations are found. Write this to a file or pass to
        ``verify_commit_range``.

    Usage:
        content = generate_allowed_signers()
        Path(".auths/allowed_signers").write_text(content)
    """
    from auths._native import generate_allowed_signers_file

    return generate_allowed_signers_file(repo_path)


class ErrorCode:
    """Stable error codes for commit verification failures."""

    UNSIGNED = "UNSIGNED"
    GPG_NOT_SUPPORTED = "GPG_NOT_SUPPORTED"
    UNKNOWN_SIGNER = "UNKNOWN_SIGNER"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    NO_ATTESTATION_FOUND = "NO_ATTESTATION_FOUND"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DEVICE_EXPIRED = "DEVICE_EXPIRED"
    LAYOUT_DISCOVERY_FAILED = "LAYOUT_DISCOVERY_FAILED"


@dataclass
class CommitResult:
    """Result of verifying a single commit's SSH signature."""

    commit_sha: str
    """Git commit SHA that was verified."""
    is_valid: bool
    """Whether the commit's signature is valid."""
    signer: str | None = None
    """Hex-encoded public key of the signer, if identified."""
    error: str | None = None
    """Human-readable error message on failure."""
    error_code: str | None = None
    """Machine-readable error code (see `ErrorCode`)."""


@dataclass
class VerifyResult:
    """Wrapper around commit verification results."""

    commits: list[CommitResult]
    """Per-commit verification results."""
    passed: bool
    """Overall pass/fail for the batch."""
    mode: str
    """Verification mode: `"enforce"` or `"warn"`."""
    summary: str
    """Human-readable summary (e.g. `"3/3 commits verified"`)."""


@dataclass
class LayoutInfo:
    """Resolved location of Auths identity data in a repository."""

    bundle: str | None = None
    """Path to identity-bundle JSON file, if found."""
    refs: list[str] | None = None
    """Git ref names under `refs/auths/`, if found."""
    source: str = ""
    """How the layout was discovered: `"file"` or `"git-refs"`."""


class LayoutError(Exception):
    """Raised when Auths identity data cannot be found in the repo."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def discover_layout(repo_root: str = ".") -> LayoutInfo:
    """Try to find Auths identity data in the repo.

    Checks ``.auths/identity-bundle.json`` then ``refs/auths/*``.
    Raises :class:`LayoutError` if missing.
    """
    bundle_path = os.path.join(repo_root, ".auths", "identity-bundle.json")
    if os.path.isfile(bundle_path):
        return LayoutInfo(bundle=bundle_path, source="file")

    proc = subprocess.run(
        ["git", "for-each-ref", "refs/auths/", "--format=%(refname)"],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return LayoutInfo(refs=proc.stdout.strip().splitlines(), source="git-refs")

    raise LayoutError(
        ErrorCode.LAYOUT_DISCOVERY_FAILED,
        "No .auths/identity-bundle.json or refs/auths/* found. "
        "Run: auths id export-bundle --output .auths/identity-bundle.json",
    )


def verify_commit_range(
    commit_range: str,
    identity_bundle: str | None = None,
    allowed_signers: str = ".auths/allowed_signers",
    mode: str = "enforce",
) -> VerifyResult:
    """Verify SSH signatures for every commit in *commit_range*.

    Args:
        commit_range: A git revision range (e.g. ``origin/main..HEAD``).
        identity_bundle: Path to an Auths identity-bundle JSON file.
        allowed_signers: Path to an ssh-keygen allowed_signers file.
        mode: ``"enforce"`` or ``"warn"``.

    Returns:
        VerifyResult with per-commit results and a pass/fail decision.
    """
    if mode not in ("enforce", "warn"):
        raise ValueError(f"mode must be 'enforce' or 'warn', got {mode!r}")

    allowed_keys_hex: list[str] = []
    attestation_lookup: dict[str, dict] | None = None

    if identity_bundle is not None:
        allowed_keys_hex, attestation_lookup = _allowed_signers_from_bundle(
            identity_bundle
        )
    elif not os.path.isfile(allowed_signers):
        try:
            layout = discover_layout()
            if layout.bundle:
                allowed_keys_hex, attestation_lookup = _allowed_signers_from_bundle(
                    layout.bundle
                )
            elif layout.source == "git-refs":
                result = CommitResult(
                    commit_sha="<layout>",
                    is_valid=False,
                    error=(
                        "Found refs/auths/* but git-ref-based verification "
                        "is not yet supported. Export a file-based bundle: "
                        "auths id export-bundle --output "
                        ".auths/identity-bundle.json"
                    ),
                    error_code=ErrorCode.LAYOUT_DISCOVERY_FAILED,
                )
                return VerifyResult(
                    commits=[result],
                    passed=(mode == "warn"),
                    mode=mode,
                    summary=f"Layout discovery: git-refs not yet supported ({mode} mode)",
                )
        except LayoutError as exc:
            result = CommitResult(
                commit_sha="<layout>",
                is_valid=False,
                error=str(exc),
                error_code=ErrorCode.LAYOUT_DISCOVERY_FAILED,
            )
            return VerifyResult(
                commits=[result],
                passed=(mode == "warn"),
                mode=mode,
                summary=f"Layout discovery failed ({mode} mode)",
            )
    else:
        # Legacy path: read allowed_signers file and extract hex keys
        allowed_keys_hex = _hex_keys_from_allowed_signers_file(allowed_signers)

    shas = list(reversed(_rev_list(commit_range)))
    if not shas:
        return VerifyResult(
            commits=[], passed=True, mode=mode, summary="No commits to verify"
        )

    results: list[CommitResult] = []
    for sha in shas:
        results.append(_verify_one(sha, allowed_keys_hex, attestation_lookup))

    total = len(results)
    failures = sum(1 for r in results if not r.is_valid)

    if failures == 0:
        summary = f"{total}/{total} commits verified"
    elif mode == "warn":
        summary = f"{failures}/{total} commits failed (warn mode: not blocking)"
    else:
        summary = f"{failures}/{total} commits failed"

    passed = (failures == 0) if mode == "enforce" else True

    return VerifyResult(commits=results, passed=passed, mode=mode, summary=summary)


def verify_commits(
    shas: list[str],
    identity_bundle: str | None = None,
    allowed_signers: str = ".auths/allowed_signers",
    mode: str = "enforce",
) -> VerifyResult:
    """Verify SSH signatures for an explicit list of commit SHAs.

    Args:
        shas: List of commit SHA strings.
        identity_bundle: Path to an Auths identity-bundle JSON file.
        allowed_signers: Path to an ssh-keygen allowed_signers file.
        mode: ``"enforce"`` or ``"warn"``.

    Returns:
        VerifyResult with per-commit results and a pass/fail decision.
    """
    if mode not in ("enforce", "warn"):
        raise ValueError(f"mode must be 'enforce' or 'warn', got {mode!r}")

    allowed_keys_hex: list[str] = []
    attestation_lookup: dict[str, dict] | None = None

    if identity_bundle is not None:
        allowed_keys_hex, attestation_lookup = _allowed_signers_from_bundle(
            identity_bundle
        )
    elif os.path.isfile(allowed_signers):
        allowed_keys_hex = _hex_keys_from_allowed_signers_file(allowed_signers)

    if not shas:
        return VerifyResult(
            commits=[], passed=True, mode=mode, summary="No commits to verify"
        )

    results: list[CommitResult] = []
    for sha in shas:
        results.append(_verify_one(sha, allowed_keys_hex, attestation_lookup))

    total = len(results)
    failures = sum(1 for r in results if not r.is_valid)

    if failures == 0:
        summary = f"{total}/{total} commits verified"
    elif mode == "warn":
        summary = f"{failures}/{total} commits failed (warn mode: not blocking)"
    else:
        summary = f"{failures}/{total} commits failed"

    passed = (failures == 0) if mode == "enforce" else True

    return VerifyResult(commits=results, passed=passed, mode=mode, summary=summary)


def _rev_list(commit_range: str) -> list[str]:
    proc = subprocess.run(
        ["git", "rev-list", commit_range], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.strip().splitlines() if line]


def _get_raw_commit(sha: str) -> bytes | None:
    """Read raw commit object bytes via git cat-file.

    Args:
        sha: Git commit SHA.

    Returns:
        Raw commit bytes, or None on failure.
    """
    proc = subprocess.run(
        ["git", "cat-file", "commit", sha], capture_output=True
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def _verify_one(
    sha: str,
    allowed_keys_hex: list[str],
    attestation_lookup: dict[str, dict] | None = None,
) -> CommitResult:
    from auths._native import verify_commit_native

    commit_content = _get_raw_commit(sha)
    if commit_content is None:
        return CommitResult(
            commit_sha=sha,
            is_valid=False,
            error="Failed to read commit",
            error_code=ErrorCode.INVALID_SIGNATURE,
        )

    result = verify_commit_native(commit_content, allowed_keys_hex)

    if not result.valid:
        return CommitResult(
            commit_sha=sha,
            is_valid=False,
            error=result.error or "Verification failed",
            error_code=result.error_code or ErrorCode.INVALID_SIGNATURE,
        )

    signer = result.signer_hex

    if attestation_lookup is not None and signer is not None:
        status = _check_attestation_status(signer, attestation_lookup)
        if status is not None:
            return CommitResult(
                commit_sha=sha,
                is_valid=False,
                signer=signer,
                error=status[0],
                error_code=status[1],
            )

    return CommitResult(commit_sha=sha, is_valid=True, signer=signer)


def _check_attestation_status(
    signer_key_hex: str,
    attestation_lookup: dict[str, dict],
) -> tuple | None:
    if signer_key_hex not in attestation_lookup:
        return None

    att = attestation_lookup[signer_key_hex]

    if att.get("revoked", False):
        revoked_at = att.get("timestamp", "unknown time")
        return (
            f"Device {signer_key_hex} was revoked (attestation timestamp: {revoked_at})",
            ErrorCode.DEVICE_REVOKED,
        )

    expires_at = att.get("expires_at")
    if expires_at is not None:
        try:
            exp_dt = _parse_datetime(expires_at)
            if datetime.now(timezone.utc) > exp_dt:
                return (
                    f"Device {signer_key_hex} attestation expired at {expires_at}",
                    ErrorCode.DEVICE_EXPIRED,
                )
        except (ValueError, TypeError):
            pass

    return None


def _parse_datetime(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _allowed_signers_from_bundle(
    bundle_path: str,
) -> tuple[list[str], dict[str, dict]]:
    """Extract allowed Ed25519 public keys (hex) from an identity bundle.

    Args:
        bundle_path: Path to an Auths identity-bundle JSON file.

    Returns:
        Tuple of (hex_keys, attestation_lookup) where hex_keys is a list
        of hex-encoded 32-byte Ed25519 public keys and attestation_lookup
        maps device_public_key hex to the attestation dict.
    """
    with open(bundle_path) as f:
        bundle = json.load(f)

    pk_hex = bundle.get("public_key_hex") or bundle.get("publicKeyHex")
    if not pk_hex:
        raise ValueError("Identity bundle missing public_key_hex field")

    pk_bytes = bytes.fromhex(pk_hex)
    if len(pk_bytes) != 32:
        raise ValueError(
            f"Invalid Ed25519 public key length: expected 32 bytes, got {len(pk_bytes)}"
        )

    keys: list[str] = []
    attestation_lookup: dict[str, dict] = {}

    chain = bundle.get("attestation_chain", [])
    for att in chain:
        dev_pk_hex = att.get("device_public_key")
        if not dev_pk_hex:
            continue
        try:
            dev_pk_bytes = bytes.fromhex(dev_pk_hex)
            if len(dev_pk_bytes) != 32:
                continue
        except (ValueError, TypeError):
            continue
        keys.append(dev_pk_hex)
        attestation_lookup[dev_pk_hex] = att

    # Identity key itself is also an allowed signer
    keys.append(pk_hex)

    return (keys, attestation_lookup)


def _hex_keys_from_allowed_signers_file(path: str) -> list[str]:
    """Extract Ed25519 public keys as hex from an allowed_signers file.

    Each line has format: ``<principal> ssh-ed25519 <base64-blob>``
    The base64 blob is SSH wire format: u32-len "ssh-ed25519" + u32-len <32-byte-key>.

    Args:
        path: Path to an ssh-keygen allowed_signers file.

    Returns:
        List of hex-encoded 32-byte Ed25519 public keys.
    """
    import base64
    import struct

    keys: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            # Format: principal key-type base64-blob [comment]
            if len(parts) < 3 or parts[1] != "ssh-ed25519":
                continue
            try:
                blob = base64.b64decode(parts[2])
                # SSH wire format: u32-len + key-type-string + u32-len + key-bytes
                offset = 0
                type_len = struct.unpack(">I", blob[offset : offset + 4])[0]
                offset += 4 + type_len
                key_len = struct.unpack(">I", blob[offset : offset + 4])[0]
                offset += 4
                key_bytes = blob[offset : offset + key_len]
                if len(key_bytes) == 32:
                    keys.append(key_bytes.hex())
            except (ValueError, struct.error, IndexError):
                continue
    return keys
