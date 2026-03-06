"""Git commit signature verification using SSH signing.

Mirrors the logic in auths-cli's verify_commit.rs: enumerates commits via
``git rev-list``, extracts SSH signatures via ``git cat-file``, and verifies
using ``ssh-keygen -Y verify`` with an allowed_signers file or identity bundle.
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
    is_valid: bool
    signer: str | None = None
    error: str | None = None
    error_code: str | None = None


@dataclass
class VerifyResult:
    """Wrapper around commit verification results."""

    commits: list[CommitResult]
    passed: bool
    mode: str
    summary: str


@dataclass
class LayoutInfo:
    """Resolved location of Auths identity data in a repository."""

    bundle: str | None = None
    refs: list[str] | None = None
    source: str = ""


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

    signers_path = allowed_signers
    tmp_signers = None
    attestation_lookup: dict[str, dict] | None = None

    try:
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

        shas = list(reversed(_rev_list(commit_range)))
        if not shas:
            return VerifyResult(
                commits=[], passed=True, mode=mode, summary="No commits to verify"
            )

        results: list[CommitResult] = []
        for sha in shas:
            results.append(_verify_one(sha, signers_path, attestation_lookup))

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
    finally:
        if tmp_signers is not None:
            try:
                os.unlink(tmp_signers)
            except OSError:
                pass


def _rev_list(commit_range: str) -> list[str]:
    proc = subprocess.run(
        ["git", "rev-list", commit_range], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.strip().splitlines() if line]


def _verify_one(
    sha: str,
    signers_path: str,
    attestation_lookup: dict[str, dict] | None = None,
) -> CommitResult:
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
                "-Y",
                "verify",
                "-f",
                signers_path,
                "-I",
                "*",
                "-n",
                "git",
                "-s",
                sig_path,
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

        signer = _find_principal(signers_path, sig_path)

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
    principal: str | None,
    attestation_lookup: dict[str, dict],
) -> tuple | None:
    if principal is None or principal == "allowed signer":
        return None

    if principal not in attestation_lookup:
        return (
            f"No device attestation found for signer {principal}",
            ErrorCode.NO_ATTESTATION_FOUND,
        )

    att = attestation_lookup[principal]

    if att.get("revoked", False):
        revoked_at = att.get("timestamp", "unknown time")
        return (
            f"Device {principal} was revoked (attestation timestamp: {revoked_at})",
            ErrorCode.DEVICE_REVOKED,
        )

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
            pass

    return None


def _parse_datetime(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _find_principal(signers_path: str, sig_path: str) -> str | None:
    proc = subprocess.run(
        ["ssh-keygen", "-Y", "find-principals", "-f", signers_path, "-s", sig_path],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return "allowed signer"


def _get_commit_signature(sha: str):
    proc = subprocess.run(
        ["git", "cat-file", "commit", sha], capture_output=True, text=True
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
    in_signature = False
    sig_lines: list[str] = []
    payload_lines: list[str] = []
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

    lines: list[str] = []
    attestation_lookup: dict[str, dict] = {}

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
        attestation_lookup[subject] = att

    identity_did = bundle.get("identity_did", "*")
    ssh_pubkey = _format_ed25519_as_ssh(pk_bytes)
    lines.append(f"{identity_did} {ssh_pubkey}")

    fd, path = tempfile.mkstemp(suffix=".allowed_signers")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")

    return (path, path, attestation_lookup)


def _format_ed25519_as_ssh(public_key: bytes) -> str:
    key_type = b"ssh-ed25519"
    blob = struct.pack(">I", len(key_type)) + key_type
    blob += struct.pack(">I", len(public_key)) + public_key
    encoded = base64.b64encode(blob).decode("ascii")
    return f"ssh-ed25519 {encoded}"
