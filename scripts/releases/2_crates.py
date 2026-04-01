#!/usr/bin/env python3
"""
Publish all workspace crates to crates.io in dependency order.

Usage:
    python scripts/releases/2_crates.py              # dry-run (shows what would happen)
    python scripts/releases/2_crates.py --publish     # publish all crates to crates.io

What it does:
    1. Reads the version from [workspace.package] in Cargo.toml
    2. Checks that the version is not already published on crates.io
    3. Checks that the git tag v{version} exists (run github.py first)
    4. Checks that cargo login is configured
    5. Publishes crates in dependency order with sleeps between batches

Requires:
    - python3 (no external dependencies)
    - cargo on PATH with a valid crates.io token (cargo login)
    - network access to crates.io
    - git tag v{version} must exist (run github.py --push first)

Publish order (dependency layers):
    Batch 1: auths, auths-crypto, auths-jwt, auths-verifier, auths-telemetry, auths-utils
    Batch 2: auths-policy
    Batch 3: auths-keri, auths-pairing-protocol
    Batch 3: auths-core, auths-index
    Batch 4: auths-infra-http, auths-mcp-server
    Batch 5: auths-id  (depends on core, crypto, policy, verifier, infra-http)
    Batch 6: auths-storage, auths-sdk, auths-radicle, auths-pairing-daemon  (depend on auths-id/core)
    Batch 7: auths-infra-git  (depends on auths-sdk)
    Batch 8: auths-cli
"""

import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

CARGO_TOML = Path(__file__).resolve().parents[2] / "Cargo.toml"
CRATES_IO_API = "https://crates.io/api/v1/crates"

PUBLISH_BATCHES: list[list[str]] = [
    ["auths", "auths-crypto", "auths-jwt", "auths-verifier", "auths-telemetry", "auths-utils"],
    ["auths-policy", "auths-oidc-port"],
    ["auths-keri", "auths-pairing-protocol"],
    ["auths-core", "auths-index"],
    ["auths-infra-http", "auths-mcp-server", "auths-transparency"],
    ["auths-id"],
    ["auths-storage", "auths-pairing-daemon"],
    ["auths-sdk"],
    ["auths-infra-git"],
    ["auths-cli"],
]

SLEEP_BETWEEN_BATCHES = 60


def get_workspace_version() -> str:
    text = CARGO_TOML.read_text()
    match = re.search(r'^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL)
    if not match:
        in_workspace_package = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == "[workspace.package]":
                in_workspace_package = True
                continue
            if in_workspace_package and stripped.startswith("["):
                break
            if in_workspace_package:
                m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
                if m:
                    return m.group(1)
        print("ERROR: Could not find version in [workspace.package] in Cargo.toml", file=sys.stderr)
        sys.exit(1)
    return match.group(1)


def get_crate_published_version(crate_name: str) -> str | None:
    url = f"{CRATES_IO_API}/{crate_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "auths-release-script/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data["crate"]["max_version"]
    except Exception:
        return None


def tag_exists(tag: str) -> bool:
    result = subprocess.run(
        ["git", "tag", "-l", tag],
        capture_output=True,
        text=True,
        cwd=CARGO_TOML.parent,
    )
    return bool(result.stdout.strip())


def cargo_login_configured() -> bool:
    result = subprocess.run(
        ["cargo", "login", "--help"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False
    # Try a dry-run publish to check token — just verify cargo config exists
    result = subprocess.run(
        ["cargo", "publish", "-p", "auths", "--dry-run"],
        capture_output=True,
        text=True,
        cwd=CARGO_TOML.parent,
    )
    if "no token found" in result.stderr.lower() or "no upload token" in result.stderr.lower():
        return False
    return True


def publish_crate(crate_name: str) -> bool:
    print(f"  Publishing {crate_name}...", flush=True)
    result = subprocess.run(
        ["cargo", "publish", "-p", crate_name],
        capture_output=True,
        text=True,
        cwd=CARGO_TOML.parent,
    )
    if result.returncode != 0:
        if "already exists" in result.stderr:
            print(f"  {crate_name} already published — skipping.", flush=True)
            return True
        print(f"  ERROR: cargo publish -p {crate_name} failed (exit {result.returncode})", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return False
    print(f"  {crate_name} published.", flush=True)
    return True


def main() -> None:
    publish = "--publish" in sys.argv

    version = get_workspace_version()
    tag = f"v{version}"
    all_crates = [crate for batch in PUBLISH_BATCHES for crate in batch]

    print(f"Workspace version: {version}")
    print(f"Crates to publish: {len(all_crates)}")

    # Check which crates still need publishing
    already_published = []
    needs_publish = []
    for crate_name in all_crates:
        pub_ver = get_crate_published_version(crate_name)
        if pub_ver == version:
            already_published.append(crate_name)
        else:
            needs_publish.append(crate_name)

    print(f"Already at {version}: {len(already_published)}")
    print(f"Need publishing:    {len(needs_publish)}")
    if already_published:
        print(f"  Skipping: {', '.join(already_published)}")
    if not needs_publish:
        print(f"\nAll {len(all_crates)} crates are already published at {version}. Nothing to do.")
        return

    # Check git tag exists (should run github.py --push first)
    if not tag_exists(tag):
        print(f"\nERROR: Git tag {tag} does not exist.", file=sys.stderr)
        print("Run 'python scripts/releases/github.py --push' first.", file=sys.stderr)
        sys.exit(1)
    print(f"Git tag {tag}:      exists")

    # Check cargo login
    print("Checking cargo auth...", flush=True)
    if not cargo_login_configured():
        print("\nERROR: No crates.io token found.", file=sys.stderr)
        print("Run 'cargo login' first.", file=sys.stderr)
        sys.exit(1)
    print("Cargo auth:        ok")

    # Show publish plan
    print(f"\nPublish plan ({SLEEP_BETWEEN_BATCHES}s sleep between batches):")
    for i, batch in enumerate(PUBLISH_BATCHES, 1):
        print(f"  Batch {i}: {', '.join(batch)}")

    if not publish:
        print("\nDry run: no crates were published.")
        print("Run with --publish to execute.")
        return

    # Publish
    failed: list[str] = []
    for i, batch in enumerate(PUBLISH_BATCHES, 1):
        print(f"\n--- Batch {i}/{len(PUBLISH_BATCHES)} ---", flush=True)
        for crate_name in batch:
            if not publish_crate(crate_name):
                failed.append(crate_name)
                print(f"\nAborting: {crate_name} failed. Fix the issue and re-run.", file=sys.stderr)
                print(f"Already published crates are fine — cargo publish is idempotent for the same version.", file=sys.stderr)
                sys.exit(1)

        if i < len(PUBLISH_BATCHES):
            print(f"  Waiting {SLEEP_BETWEEN_BATCHES}s for crates.io index to update...", flush=True)
            time.sleep(SLEEP_BETWEEN_BATCHES)

    print(f"\nDone. All {len(all_crates)} crates published at version {version}.")
    print(f"  https://crates.io/crates/auths/{version}")


if __name__ == "__main__":
    main()
