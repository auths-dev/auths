#!/usr/bin/env python3
"""
Tag and push a GitHub release from the workspace version in Cargo.toml.

Usage:
    python scripts/releases/github.py          # dry-run (shows what would happen)
    python scripts/releases/github.py --push   # create tag and push to trigger release workflow

What it does:
    1. Reads the version from [workspace.package] in Cargo.toml
    2. Checks crates.io to make sure the version has been bumped
    3. Checks that the git tag doesn't already exist
    4. Creates a git tag v{version} and pushes it to origin

Requires:
    - python3 (no external dependencies)
    - git on PATH
    - network access to crates.io
"""

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

CARGO_TOML = Path(__file__).resolve().parents[2] / "Cargo.toml"
CRATES_IO_URL = "https://crates.io/api/v1/crates/auths"


def get_workspace_version() -> str:
    text = CARGO_TOML.read_text()
    match = re.search(r'^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL)
    if not match:
        # Fallback: find version under [workspace.package] by scanning lines
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


def get_crates_io_version() -> str | None:
    req = urllib.request.Request(CRATES_IO_URL, headers={"User-Agent": "auths-release-script/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data["crate"]["max_version"]
    except Exception:
        return None


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=CARGO_TOML.parent,
    )
    if result.returncode != 0:
        print(f"ERROR: git {' '.join(args)} failed:\n{result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def tag_exists(tag: str) -> bool:
    result = subprocess.run(
        ["git", "tag", "-l", tag],
        capture_output=True,
        text=True,
        cwd=CARGO_TOML.parent,
    )
    return bool(result.stdout.strip())


def main() -> None:
    push = "--push" in sys.argv

    version = get_workspace_version()
    tag = f"v{version}"
    print(f"Workspace version: {version}")
    print(f"Git tag:           {tag}")

    # Check crates.io for version bump
    published = get_crates_io_version()
    if published:
        print(f"crates.io version: {published}")
        if published == version:
            print(f"\nERROR: Version {version} is already published on crates.io.", file=sys.stderr)
            print("Bump the version in Cargo.toml before releasing.", file=sys.stderr)
            sys.exit(1)
    else:
        print("crates.io version: (not found or not published yet)")

    # Check git tag doesn't already exist
    if tag_exists(tag):
        print(f"\nERROR: Git tag {tag} already exists.", file=sys.stderr)
        print("Bump the version in Cargo.toml or delete the existing tag.", file=sys.stderr)
        sys.exit(1)

    # Check we're on a clean working tree
    status = git("status", "--porcelain")
    if status:
        print(f"\nERROR: Working tree is not clean:\n{status}", file=sys.stderr)
        print("Commit or stash changes before releasing.", file=sys.stderr)
        sys.exit(1)

    if not push:
        print(f"\nDry run: would create and push tag {tag}")
        print("Run with --push to execute.")
        return

    print(f"\nCreating tag {tag}...")
    git("tag", tag)

    print(f"Pushing tag {tag} to origin (pre-push hooks may run)...")
    sys.stdout.flush()
    result = subprocess.run(
        ["git", "push", "origin", tag],
        cwd=CARGO_TOML.parent,
    )
    if result.returncode != 0:
        print(f"\nERROR: git push failed (exit {result.returncode})", file=sys.stderr)
        sys.exit(1)

    print(f"\nDone. Release workflow will run at:")
    print(f"  https://github.com/auths-dev/auths/actions")


if __name__ == "__main__":
    main()
