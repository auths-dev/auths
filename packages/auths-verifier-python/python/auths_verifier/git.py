"""Git commit signature verification using SSH signing.

Mirrors the logic in auths-cli's verify_commit.rs: enumerates commits via
``git rev-list``, extracts SSH signatures via ``git cat-file``, and verifies
using ``ssh-keygen -Y verify`` with an allowed_signers file or identity bundle.

When an identity bundle is provided, the attestation chain is inspected to
check device revocation and expiration status — matching the Rust verifier's
``verify_single_attestation`` logic.

Prerequisites: ``git`` and ``ssh-keygen`` must be on PATH.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional


class ErrorCode:
    """Stable error codes for commit verification failures.

    Machine-parseable constants for CI automation. Each failed
    ``CommitResult`` carries one of these in its ``error_code`` field.
    """

    UNSIGNED = "UNSIGNED"
    """Commit has no signature at all."""

    GPG_NOT_SUPPORTED = "GPG_NOT_SUPPORTED"
    """Commit uses GPG, not SSH."""

    UNKNOWN_SIGNER = "UNKNOWN_SIGNER"
    """Signed, but signer not in allowed_signers."""

    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    """Signature present but verification failed."""

    NO_ATTESTATION_FOUND = "NO_ATTESTATION_FOUND"
    """Signed by a valid key, but no matching identity/device attestation exists."""

    DEVICE_REVOKED = "DEVICE_REVOKED"
    """Device attestation was revoked."""

    DEVICE_EXPIRED = "DEVICE_EXPIRED"
    """Device attestation past expires_at."""

    LAYOUT_DISCOVERY_FAILED = "LAYOUT_DISCOVERY_FAILED"
    """Could not find identity bundle or refs/auths/* in repo."""


@dataclass
class CommitResult:
    """Result of verifying a single commit's SSH signature (evidence)."""

    commit_sha: str
    is_valid: bool
    signer: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class VerifyResult:
    """Wrapper around commit verification results (decision).

    ``passed`` reflects the policy decision: in ``enforce`` mode it is
    ``False`` when any commit fails; in ``warn`` mode it is always ``True``.
    """

    commits: List[CommitResult]
    passed: bool
    mode: str
    summary: str


@dataclass
class LayoutInfo:
    """Resolved location of Auths identity data in a repository."""

    bundle: Optional[str] = None
    refs: Optional[List[str]] = None
    source: str = ""  # "file" or "git-refs"


class LayoutError(Exception):
    """Raised when Auths identity data cannot be found in the repo."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def discover_layout(repo_root: str = ".") -> LayoutInfo:
    """Try to find Auths identity data in the repo.

    Checks in order:

    1. ``.auths/identity-bundle.json`` (default convention)
    2. ``refs/auths/*`` (Git ref storage)

    Returns :class:`LayoutInfo` with resolved paths.
    Raises :class:`LayoutError` with ``LAYOUT_DISCOVERY_FAILED`` if missing.
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
    identity_bundle: Optional[str] = None,
    allowed_signers: str = ".auths/allowed_signers",
    mode: str = "enforce",
) -> VerifyResult:
    """Verify SSH signatures for every commit in *commit_range*.

    Parameters
    ----------
    commit_range:
        A git revision range such as ``origin/main..HEAD`` or ``HEAD~3..HEAD``.
    identity_bundle:
        Path to an Auths identity-bundle JSON file.  When provided, device
        keys from the attestation chain are used for verification, and each
        device's revocation/expiration status is checked.
    allowed_signers:
        Path to an ``ssh-keygen`` allowed_signers file.  Ignored when
        *identity_bundle* is set.
    mode:
        ``"enforce"`` (default) exits non-zero on any failure.
        ``"warn"`` logs failures but ``passed`` is always ``True``.

    Returns
    -------
    VerifyResult
        Wrapper with per-commit results, a ``passed`` decision, and a
        human-readable ``summary``.

    Raises
    ------
    ValueError
        If *mode* is not ``"enforce"`` or ``"warn"``.
    """
    if mode not in ("enforce", "warn"):
        raise ValueError(f"mode must be 'enforce' or 'warn', got {mode!r}")

    signers_path = allowed_signers
    tmp_signers = None
    attestation_lookup: Optional[Dict[str, dict]] = None

    try:
        # --- Layout discovery ------------------------------------------------
        if identity_bundle is not None:
            signers_path, tmp_signers, attestation_lookup = (
                _allowed_signers_from_bundle(identity_bundle)
            )
        elif not os.path.isfile(allowed_signers):
            try:
                layout = discover_layout()
                if layout.bundle:
                    signers_path, tmp_signers, attestation_lookup = (
                        _allowed_signers_from_bundle(layout.bundle)
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

        # --- Enumerate commits -----------------------------------------------
        shas = list(reversed(_rev_list(commit_range)))  # chronological order
        if not shas:
            return VerifyResult(
                commits=[],
                passed=True,
                mode=mode,
                summary="No commits to verify",
            )

        # --- Verify each commit ----------------------------------------------
        results: List[CommitResult] = []
        for sha in shas:
            results.append(_verify_one(sha, signers_path, attestation_lookup))

        # --- Build decision --------------------------------------------------
        total = len(results)
        failures = sum(1 for r in results if not r.is_valid)

        if failures == 0:
            summary = f"{total}/{total} commits verified"
        elif mode == "warn":
            summary = (
                f"{failures}/{total} commits failed "
                f"(warn mode: not blocking)"
            )
        else:
            summary = f"{failures}/{total} commits failed"

        passed = (failures == 0) if mode == "enforce" else True

        return VerifyResult(
            commits=results,
            passed=passed,
            mode=mode,
            summary=summary,
        )
    finally:
        if tmp_signers is not None:
            try:
                os.unlink(tmp_signers)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _rev_list(commit_range: str) -> List[str]:
    """Return commit SHAs in *commit_range* (newest-first from git).

    The caller reverses this list so that verification output is chronological.
    """
    proc = subprocess.run(
        ["git", "rev-list", commit_range],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.strip().splitlines() if line]


def _verify_one(
    sha: str,
    signers_path: str,
    attestation_lookup: Optional[Dict[str, dict]] = None,
) -> CommitResult:
    """Verify the SSH signature of a single commit.

    When *attestation_lookup* is provided (identity-bundle mode), the
    signer's device attestation is checked for revocation and expiration
    after the SSH signature is verified.
    """
    sig_info = _get_commit_signature(sha)
    if sig_info is None:
        return CommitResult(
            commit_sha=sha,
            is_valid=False,
            error="No signature found",
            error_code=ErrorCode.UNSIGNED,
        )
    if sig_info == "gpg":
        return CommitResult(
            commit_sha=sha,
            is_valid=False,
            error="GPG signatures not supported, use SSH signing",
            error_code=ErrorCode.GPG_NOT_SUPPORTED,
        )

    signature, payload = sig_info

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sig", delete=False) as sf:
        sf.write(signature)
        sig_path = sf.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dat", delete=False) as pf:
        pf.write(payload)
        payload_path = pf.name

    try:
        proc = subprocess.run(
            [
                "ssh-keygen",
                "-Y", "verify",
                "-f", signers_path,
                "-I", "*",
                "-n", "git",
                "-s", sig_path,
            ],
            input=payload,
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            if "no principal matched" in stderr or "NONE_ACCEPTED" in stderr:
                return CommitResult(
                    commit_sha=sha,
                    is_valid=False,
                    error="Signature from non-allowed signer",
                    error_code=ErrorCode.UNKNOWN_SIGNER,
                )
            return CommitResult(
                commit_sha=sha,
                is_valid=False,
                error=f"Signature verification failed: {stderr}",
                error_code=ErrorCode.INVALID_SIGNATURE,
            )

        # SSH signature is valid — identify who signed.
        signer = _find_principal(signers_path, sig_path)

        # If we have attestation data, check device status.
        if attestation_lookup is not None:
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
    finally:
        for p in (sig_path, payload_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def _check_attestation_status(
    principal: Optional[str],
    attestation_lookup: Dict[str, dict],
) -> Optional[tuple]:
    """Check device attestation for revocation/expiration.

    Returns ``None`` if the device is in good standing, or a
    ``(error_message, error_code)`` tuple if not.
    """
    if principal is None or principal == "allowed signer":
        # Wildcard match or no principal found — can't look up attestation.
        return None

    if principal not in attestation_lookup:
        # The SSH key verified and we know the signer DID, but there is
        # no device attestation for it in the bundle's attestation_chain.
        # This typically means the key was signed by the root identity
        # key directly (legacy/fallback) without an attestation record.
        return (
            f"No device attestation found for signer {principal}",
            ErrorCode.NO_ATTESTATION_FOUND,
        )

    att = attestation_lookup[principal]

    # --- 1. Check revocation (matches verify.rs:138-143) ---
    if att.get("revoked", False):
        revoked_at = att.get("timestamp", "unknown time")
        return (
            f"Device {principal} was revoked (attestation timestamp: {revoked_at})",
            ErrorCode.DEVICE_REVOKED,
        )

    # --- 2. Check expiration (matches verify.rs:145-153) ---
    expires_at = att.get("expires_at")
    if expires_at is not None:
        try:
            exp_dt = _parse_datetime(expires_at)
            if datetime.now(timezone.utc) > exp_dt:
                return (
                    f"Device {principal} attestation expired at {expires_at}",
                    ErrorCode.DEVICE_EXPIRED,
                )
        except (ValueError, TypeError):
            pass  # unparseable timestamp — don't block on it

    return None  # device is in good standing


def _parse_datetime(value: str) -> datetime:
    """Parse an RFC 3339 / ISO 8601 timestamp string to a datetime.

    Handles both ``Z`` suffix and ``+00:00`` offset.
    """
    # Python 3.11+ datetime.fromisoformat handles Z, but 3.8-3.10 don't.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _find_principal(signers_path: str, sig_path: str) -> Optional[str]:
    """Use ``ssh-keygen -Y find-principals`` to identify who signed."""
    proc = subprocess.run(
        ["ssh-keygen", "-Y", "find-principals", "-f", signers_path, "-s", sig_path],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return "allowed signer"


def _get_commit_signature(sha: str):
    """Extract SSH signature + payload from a commit.

    Returns ``None`` if unsigned, ``"gpg"`` for GPG, or a
    ``(signature, payload)`` tuple for SSH.
    """
    proc = subprocess.run(
        ["git", "cat-file", "commit", sha],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git cat-file failed: {proc.stderr.strip()}")

    content = proc.stdout

    if "-----BEGIN PGP SIGNATURE-----" in content:
        return "gpg"

    if "-----BEGIN SSH SIGNATURE-----" in content:
        return _extract_ssh_signature(content)

    return None


def _extract_ssh_signature(content: str):
    """Parse the gpgsig header out of raw commit text.

    Returns ``(signature_str, payload_str)``.
    """
    in_signature = False
    sig_lines: List[str] = []
    payload_lines: List[str] = []
    header_done = False

    for line in content.splitlines():
        if line.startswith("gpgsig "):
            in_signature = True
            sig_lines.append(line[len("gpgsig "):])
        elif in_signature:
            if line.startswith(" "):
                sig_lines.append(line[1:])
            else:
                in_signature = False
                if line == "":
                    header_done = True
                else:
                    payload_lines.append(line)
        elif not header_done:
            if line == "":
                header_done = True
            elif not line.startswith("gpgsig"):
                payload_lines.append(line)
        else:
            payload_lines.append(line)

    if not sig_lines:
        return None

    signature = "\n".join(sig_lines)
    payload = "\n".join(payload_lines)
    return (signature, payload)


def _allowed_signers_from_bundle(bundle_path: str):
    """Create a temporary allowed_signers file from an identity bundle.

    Extracts device keys from the ``attestation_chain`` (each with its
    ``subject`` DID as the principal) plus the root identity key.  Returns
    a three-tuple: ``(signers_path, cleanup_path, attestation_lookup)``.

    The *attestation_lookup* maps principal (subject DID) → attestation
    dict, so callers can check revocation/expiration after SSH verify.
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

    lines: List[str] = []
    attestation_lookup: Dict[str, dict] = {}

    # --- Device keys from attestation chain --------------------------------
    chain = bundle.get("attestation_chain", [])
    for att in chain:
        dev_pk_hex = att.get("device_public_key")
        subject = att.get("subject")
        if not dev_pk_hex or not subject:
            continue
        try:
            dev_pk_bytes = bytes.fromhex(dev_pk_hex)
            if len(dev_pk_bytes) != 32:
                continue
        except (ValueError, TypeError):
            continue
        ssh_pubkey = _format_ed25519_as_ssh(dev_pk_bytes)
        lines.append(f"{subject} {ssh_pubkey}")
        # Keep the latest attestation per subject (later entries override).
        attestation_lookup[subject] = att

    # --- Root identity key (fallback / legacy) -----------------------------
    identity_did = bundle.get("identity_did", "*")
    ssh_pubkey = _format_ed25519_as_ssh(pk_bytes)
    lines.append(f"{identity_did} {ssh_pubkey}")

    fd, path = tempfile.mkstemp(suffix=".allowed_signers")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")

    return (path, path, attestation_lookup)


def _format_ed25519_as_ssh(public_key: bytes) -> str:
    """Encode a raw 32-byte Ed25519 key as an SSH public key string.

    Mirrors ``format_ed25519_as_ssh`` in verify_commit.rs.
    """
    key_type = b"ssh-ed25519"
    blob = struct.pack(">I", len(key_type)) + key_type
    blob += struct.pack(">I", len(public_key)) + public_key
    encoded = base64.b64encode(blob).decode("ascii")
    return f"ssh-ed25519 {encoded}"
