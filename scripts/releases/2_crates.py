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

Publish order: see PUBLISH_BATCHES below (topological from cargo metadata).
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

# Topological order computed from `cargo metadata` (a crate may only appear
# after every internal dependency it has). Regenerate when crate deps change:
# each batch contains crates whose internal deps are all in earlier batches.
#
# Every publishable workspace member must be either in a batch here or in
# EXCLUDED_FROM_PUBLISH below — `validate_batches()` enforces that, so a crate
# can no longer silently fall out of the release (which is exactly what happened
# to auths-mcp-core/-gateway: built, wired, and never published because nothing
# checked they were listed).
PUBLISH_BATCHES: list[list[str]] = [
    ["auths", "auths-crypto", "auths-telemetry", "auths-utils"],
    ["auths-keri", "auths-oidc-port"],
    ["auths-jwt", "auths-pairing-protocol", "auths-verifier"],
    ["auths-index", "auths-policy", "auths-rp", "auths-scim", "auths-transparency"],
    ["auths-core"],
    ["auths-infra-http", "auths-infra-rekor", "auths-pairing-daemon"],
    ["auths-id"],
    ["auths-storage"],
    ["auths-sdk"],
    ["auths-infra-git", "auths-mcp-core", "auths-mcp-server", "auths-scim-server"],
    ["auths-cli", "auths-mcp-gateway"],
]

# Publishable workspace members deliberately NOT published to crates.io, each
# with the reason. Keeping this explicit is what makes the coverage check
# meaningful: an omission is a decision recorded here, never an accident.
EXCLUDED_FROM_PUBLISH: dict[str, str] = {
    "auths-api": "org control-plane server binary; not a library anyone depends on from crates.io",
    "murmur-core": "belongs to the Murmur messenger — a separate product with its own release",
    "murmur-relay": "belongs to the Murmur messenger — a separate product with its own release",
}

SLEEP_BETWEEN_BATCHES = 60


def workspace_members() -> list[str]:
    """Crate names of the `[workspace] members` under `crates/`.

    Read from the root Cargo.toml so the coverage check sees exactly what
    `cargo` would build, not whatever happens to sit in the crates/ directory.
    """
    text = CARGO_TOML.read_text()
    members_block = re.search(r"members\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not members_block:
        return []
    paths = re.findall(r'"(crates/[^"]+)"', members_block.group(1))
    names = []
    for p in paths:
        crate_toml = CARGO_TOML.parent / p / "Cargo.toml"
        if not crate_toml.exists():
            continue
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', crate_toml.read_text(), re.MULTILINE)
        if name:
            names.append(name.group(1))
    return names


def is_publishable(crate_name: str) -> bool:
    """Whether a workspace member is publishable (no `publish = false`)."""
    for p in re.findall(r'"(crates/[^"]+)"', CARGO_TOML.read_text()):
        crate_toml = CARGO_TOML.parent / p / "Cargo.toml"
        if not crate_toml.exists():
            continue
        text = crate_toml.read_text()
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if name and name.group(1) == crate_name:
            return not re.search(r"^\s*publish\s*=\s*false", text, re.MULTILINE)
    return False


def validate_batches() -> list[str]:
    """Return coverage errors: publishable members neither batched nor excluded,
    plus batch/exclusion entries that no longer name a publishable member."""
    batched = [c for batch in PUBLISH_BATCHES for c in batch]
    errors: list[str] = []

    dupes = sorted({c for c in batched if batched.count(c) > 1})
    for c in dupes:
        errors.append(f"{c} appears in PUBLISH_BATCHES more than once")

    batched_set = set(batched)
    overlap = batched_set & set(EXCLUDED_FROM_PUBLISH)
    for c in sorted(overlap):
        errors.append(f"{c} is both batched and excluded — pick one")

    for crate in sorted(workspace_members()):
        if not is_publishable(crate):
            if crate in batched_set:
                errors.append(f"{crate} has publish=false but is in a batch")
            continue
        if crate not in batched_set and crate not in EXCLUDED_FROM_PUBLISH:
            errors.append(
                f"{crate} is publishable but is neither in a batch nor in "
                f"EXCLUDED_FROM_PUBLISH — add it to the release or record why not"
            )

    members = set(workspace_members())
    for crate in sorted(batched_set - members):
        errors.append(f"{crate} is batched but is not a workspace member")
    for crate in sorted(set(EXCLUDED_FROM_PUBLISH) - members):
        errors.append(f"{crate} is excluded but is not a workspace member")

    return errors


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
        ["cargo", "publish", "-p", "auths", "--dry-run", "--locked"],
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
        ["cargo", "publish", "-p", crate_name, "--locked"],
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
    # Coverage is checked on every run — a batch that has drifted out of sync
    # with the workspace is a release bug whether or not we are publishing today.
    errors = validate_batches()
    if "--validate" in sys.argv:
        if errors:
            print("PUBLISH_BATCHES coverage FAILED:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            sys.exit(1)
        members = [c for c in workspace_members() if is_publishable(c)]
        print(
            f"PUBLISH_BATCHES coverage OK: {len(members)} publishable members "
            f"({sum(len(b) for b in PUBLISH_BATCHES)} batched, "
            f"{len(EXCLUDED_FROM_PUBLISH)} excluded)"
        )
        return
    if errors:
        print("ERROR: PUBLISH_BATCHES coverage is out of date:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

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
