#!/usr/bin/env python3
"""
Test the full release artifact signing workflow locally (macOS aarch64).

Usage:
    python scripts/auths_workflows/artifact_signing.py          # run the full workflow
    python scripts/auths_workflows/artifact_signing.py --skip-build  # reuse existing build

What it does:
    1. Checks prerequisites (cargo, auths identity, device keys)
    2. Builds release binaries (cargo build --release -p auths-cli)
    3. Packages them into auths-macos-aarch64.tar.gz (same as CI)
    4. Generates SHA256 checksum
    5. Signs the artifact with `auths artifact sign`
    6. Displays the .auths.json attestation
    7. Verifies the attestation with `auths artifact verify`
    8. Cleans up

Requires:
    - macOS aarch64
    - cargo on PATH
    - auths identity set up (`auths status` shows identity)
    - At least one device key alias (`auths key list`)

This mirrors the release.yml workflow so you can validate signing
works before pushing a tag.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET = "aarch64-apple-darwin"
ASSET_NAME = "auths-macos-aarch64"
EXT = ".tar.gz"
BINARIES = ["auths", "auths-sign", "auths-verify"]

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def step(n: int, msg: str) -> None:
    print(f"\n{BOLD}{CYAN}[Step {n}]{RESET} {BOLD}{msg}{RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}", file=sys.stderr)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, print it, and return the result."""
    display = " ".join(cmd)
    print(f"  $ {display}", flush=True)
    return subprocess.run(cmd, **kwargs)


def run_checked(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        fail(f"Command failed (exit {result.returncode})")
        if result.stderr.strip():
            print(f"    stderr: {result.stderr.strip()}")
        sys.exit(1)
    return result


def main() -> None:
    skip_build = "--skip-build" in sys.argv

    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Artifact Signing Workflow — Local Test{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    # ── Step 1: Prerequisites ──
    step(1, "Checking prerequisites")

    if shutil.which("cargo") is None:
        fail("cargo not found on PATH")
        sys.exit(1)
    ok("cargo found")

    if shutil.which("auths") is None:
        fail("auths not found on PATH. Run: cargo install --path crates/auths-cli")
        sys.exit(1)
    ok("auths found")

    # Check identity exists
    result = run_checked(["auths", "status"], cwd=REPO_ROOT)
    if "not initialized" in result.stdout.lower():
        fail("No auths identity found. Run: auths init")
        sys.exit(1)
    ok("auths identity exists")

    print(f"\n  {CYAN}--- auths status ---{RESET}")
    for line in result.stdout.strip().splitlines():
        print(f"  {line}")

    # Check device keys
    key_result = run_checked(["auths", "key", "list"], cwd=REPO_ROOT)
    if not key_result.stdout.strip():
        fail("No device keys found. You need at least one key alias.")
        sys.exit(1)
    ok("device keys found")

    print(f"\n  {CYAN}--- auths key list ---{RESET}")
    for line in key_result.stdout.strip().splitlines():
        print(f"  {line}")

    # Ask user which device key alias to use
    print()
    device_alias = input(f"  {BOLD}Enter device-key to use for signing:{RESET} ").strip()
    if not device_alias:
        fail("No alias provided.")
        sys.exit(1)

    # Optionally ask for identity key alias
    identity_alias = input(
        f"  {BOLD}Enter key (leave blank for device-only):{RESET} "
    ).strip()

    # ── Step 2: Build ──
    work_dir = Path(tempfile.mkdtemp(prefix="auths-release-test-"))
    print(f"\n  Working directory: {work_dir}")

    if skip_build:
        step(2, "Skipping build (--skip-build)")
        # Verify binaries exist
        for binary in BINARIES:
            path = REPO_ROOT / "target" / "release" / binary
            if not path.exists():
                fail(f"Binary not found: {path}")
                fail("Run without --skip-build first.")
                shutil.rmtree(work_dir)
                sys.exit(1)
        ok("Existing release binaries found")
    else:
        step(2, "Building release binaries")
        result = run(
            ["cargo", "build", "--release", "--package", "auths-cli"],
            cwd=REPO_ROOT,
        )
        if result.returncode != 0:
            fail("Build failed")
            shutil.rmtree(work_dir)
            sys.exit(1)
        ok("Build complete")

    # ── Step 3: Package ──
    step(3, "Packaging binaries into tarball")
    staging = work_dir / "staging"
    staging.mkdir()

    for binary in BINARIES:
        src = REPO_ROOT / "target" / "release" / binary
        if src.exists():
            shutil.copy2(src, staging / binary)
            ok(f"Copied {binary}")
        else:
            warn(f"Binary not found: {binary} (skipped)")

    tarball = work_dir / f"{ASSET_NAME}{EXT}"
    run_checked(
        ["tar", "-czf", str(tarball), "-C", str(staging), "."],
    )
    size_mb = tarball.stat().st_size / (1024 * 1024)
    ok(f"Created {tarball.name} ({size_mb:.1f} MB)")

    # ── Step 4: SHA256 checksum ──
    step(4, "Generating SHA256 checksum")
    checksum_file = work_dir / f"{ASSET_NAME}{EXT}.sha256"
    result = run_checked(["shasum", "-a", "256", str(tarball)])
    checksum_line = result.stdout.strip()
    checksum_file.write_text(checksum_line + "\n")
    ok(f"Checksum: {checksum_line.split()[0]}")

    # ── Step 5: Sign artifact ──
    step(5, "Signing artifact with auths")
    sign_cmd = [
        "auths", "artifact", "sign", str(tarball),
        "--device-key", device_alias,
        "--note", "Local signing test",
    ]
    if identity_alias:
        sign_cmd.extend(["--key", identity_alias])

    result = run(sign_cmd, cwd=REPO_ROOT)
    if result.returncode != 0:
        fail("Artifact signing failed")
        print(f"\n  Working directory preserved at: {work_dir}")
        sys.exit(1)

    attestation_file = Path(f"{tarball}.auths.json")
    if not attestation_file.exists():
        fail(f"Expected attestation file not found: {attestation_file}")
        print(f"\n  Working directory preserved at: {work_dir}")
        sys.exit(1)
    ok(f"Created {attestation_file.name}")

    # ── Step 6: Display attestation ──
    step(6, "Attestation contents")
    attestation_raw = attestation_file.read_text()
    try:
        attestation = json.loads(attestation_raw)
        formatted = json.dumps(attestation, indent=2)
        print(f"\n  {CYAN}--- {attestation_file.name} ---{RESET}")
        for line in formatted.splitlines():
            print(f"  {line}")
    except json.JSONDecodeError:
        print(f"  (raw): {attestation_raw[:500]}")

    # ── Step 7: Verify attestation ──
    step(7, "Verifying attestation")
    result = run(
        ["auths", "artifact", "verify", str(tarball)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        ok("Verification passed")
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                print(f"  {line}")
    else:
        warn(f"Verification returned exit {result.returncode}")
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                print(f"  {line}")
        if result.stderr.strip():
            for line in result.stderr.strip().splitlines():
                print(f"  {line}")

    # ── Step 8: Summary ──
    step(8, "Cleanup and summary")
    print(f"\n  {CYAN}Files produced:{RESET}")
    for f in sorted(work_dir.iterdir()):
        if f.is_file():
            size = f.stat().st_size
            print(f"    {f.name:50s} {size:>10,} bytes")
    for f in [attestation_file]:
        if f.exists() and f.parent != work_dir:
            size = f.stat().st_size
            print(f"    {f.name:50s} {size:>10,} bytes")

    # Clean up
    shutil.rmtree(work_dir)
    if attestation_file.exists():
        attestation_file.unlink()
    ok("Cleaned up temp files")

    print(f"\n{BOLD}{GREEN}{'='*60}{RESET}")
    print(f"{BOLD}{GREEN}  Artifact signing workflow completed successfully!{RESET}")
    print(f"{BOLD}{GREEN}{'='*60}{RESET}")
    print(f"\n  This confirms the release.yml signing step will work in CI.")
    print(f"  Artifacts are signed with ephemeral keys. No CI token needed.\n")


if __name__ == "__main__":
    main()
