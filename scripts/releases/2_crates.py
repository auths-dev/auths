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

Publish order: derived at run time from `cargo metadata` (compute_publish_batches).
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

# Publish order is NO LONGER hand-maintained. It is derived at run time from
# `cargo metadata` (see compute_publish_batches), so a crate can never be
# published before an internal dependency it needs — the exact bug that broke
# the 0.1.4 release, where a stale hand-written list put `auths` (which depends
# on auths-sdk) in the FIRST batch and auths-sdk eight batches later. A list
# that has to be kept in sync by hand will drift; a derived one cannot.
#
# The only human decision left is which publishable members to KEEP OFF
# crates.io — recorded explicitly below so an omission is always a decision,
# never an accident. Everything else that is publishable (publish != false and
# not excluded) is published, in dependency order.
EXCLUDED_FROM_PUBLISH: dict[str, str] = {
    # auths-api is published because auths-mcp-server (a published crate) now
    # normal-depends on it — the release must be dependency-closed. Likewise
    # auths-witness / auths-witness-node had `publish = false` lifted because
    # auths-cli's `witness-node` feature pulls them in. The rule enforced by
    # validate_batches(): nothing published may depend on something unpublished.
    "auths-test-utils": "internal test scaffolding; a dev-dependency only, never a published dependency",
    "murmur-core": "belongs to the Murmur messenger — a separate product with its own release",
    "murmur-relay": "belongs to the Murmur messenger — a separate product with its own release",
}

SLEEP_BETWEEN_BATCHES = 60


def _cargo_metadata() -> dict:
    """`cargo metadata --no-deps` for the root workspace (members only)."""
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        cwd=CARGO_TOML.parent,
    )
    if result.returncode != 0:
        print("ERROR: `cargo metadata` failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def workspace_members(meta: dict) -> set[str]:
    """Every workspace member crate name, per cargo (the build's own view)."""
    return {p["name"] for p in meta["packages"]}


def publishable_members(meta: dict) -> set[str]:
    """Members cargo would let us publish: `publish` is null or a non-empty
    allow-list. `publish = false` serialises to `[]` and is excluded."""
    return {p["name"] for p in meta["packages"] if p.get("publish") != []}


def _internal_release_deps(meta: dict) -> dict[str, set[str]]:
    """crate -> the internal deps that gate its publish (normal + build only).

    Dev-dependencies are deliberately ignored: `cargo publish` strips them, so
    they neither need to be on crates.io first nor should they create ordering
    edges (they are also the usual source of dependency cycles in a workspace).
    """
    members = workspace_members(meta)
    graph: dict[str, set[str]] = {}
    for p in meta["packages"]:
        deps = {
            d["name"]
            for d in p.get("dependencies", [])
            # kind is null for a normal dep, "build" for build, "dev" for dev.
            if d.get("kind") in (None, "build") and d["name"] in members
        }
        deps.discard(p["name"])
        graph[p["name"]] = deps
    return graph


def compute_publish_batches(meta: dict) -> list[list[str]]:
    """Topological batches over the crates we actually publish.

    Nodes are the publishable, non-excluded members; edges are their normal/build
    internal deps. Each batch is the set of crates whose deps are all already
    published, so batch N only depends on batches < N — order can't be wrong.
    Crates within a batch are sorted for a stable, reviewable plan.
    """
    nodes = publishable_members(meta) - set(EXCLUDED_FROM_PUBLISH)
    graph = _internal_release_deps(meta)
    # Restrict edges to the node set — a dep on an excluded/unpublished crate is
    # caught by validate_batches(), not silently used as an ordering edge here.
    remaining = {n: {d for d in graph.get(n, set()) if d in nodes} for n in nodes}

    batches: list[list[str]] = []
    published: set[str] = set()
    while remaining:
        ready = sorted(n for n, deps in remaining.items() if deps <= published)
        if not ready:
            cycle = ", ".join(sorted(remaining))
            print(
                f"ERROR: dependency cycle among publishable crates: {cycle}",
                file=sys.stderr,
            )
            sys.exit(1)
        batches.append(ready)
        published.update(ready)
        for n in ready:
            del remaining[n]
    return batches


def validate_batches(meta: dict) -> list[str]:
    """Correctness checks on the derived plan. Ordering is guaranteed by the
    topological sort; what's left to catch is a bad EXCLUDED set — a stale entry,
    or an exclusion that would make a *published* crate un-publishable because it
    normal-depends on something we refuse to publish."""
    errors: list[str] = []
    members = workspace_members(meta)
    publishable = publishable_members(meta)
    graph = _internal_release_deps(meta)

    for crate in sorted(set(EXCLUDED_FROM_PUBLISH) - members):
        errors.append(f"{crate} is excluded but is not a workspace member")

    to_publish = publishable - set(EXCLUDED_FROM_PUBLISH)
    for crate in sorted(to_publish):
        for dep in sorted(graph.get(crate, set())):
            if dep in to_publish:
                continue
            why = (
                "excluded from publish" if dep in EXCLUDED_FROM_PUBLISH
                else "publish = false" if dep not in publishable
                else "not a workspace member"
            )
            errors.append(
                f"{crate} is published but normal-depends on {dep} ({why}) — "
                f"cargo publish -p {crate} will fail because {dep} won't be on crates.io"
            )

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
    # The plan is derived from `cargo metadata` every run, so ordering is always
    # correct; validate_batches() only has to catch a bad EXCLUDED set.
    meta = _cargo_metadata()
    errors = validate_batches(meta)
    batches = compute_publish_batches(meta)
    if "--validate" in sys.argv:
        if errors:
            print("Release-plan validation FAILED:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            sys.exit(1)
        print(
            f"Release plan OK: {sum(len(b) for b in batches)} crates in "
            f"{len(batches)} dependency-ordered batches, "
            f"{len(EXCLUDED_FROM_PUBLISH)} excluded."
        )
        for i, batch in enumerate(batches, 1):
            print(f"  Batch {i}: {', '.join(batch)}")
        return
    if errors:
        print("ERROR: release plan is invalid:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    publish = "--publish" in sys.argv

    version = get_workspace_version()
    tag = f"v{version}"
    all_crates = [crate for batch in batches for crate in batch]

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
    for i, batch in enumerate(batches, 1):
        print(f"  Batch {i}: {', '.join(batch)}")

    if not publish:
        print("\nDry run: no crates were published.")
        print("Run with --publish to execute.")
        return

    # Publish
    failed: list[str] = []
    for i, batch in enumerate(batches, 1):
        print(f"\n--- Batch {i}/{len(batches)} ---", flush=True)
        for crate_name in batch:
            if not publish_crate(crate_name):
                failed.append(crate_name)
                print(f"\nAborting: {crate_name} failed. Fix the issue and re-run.", file=sys.stderr)
                print(f"Already published crates are fine — cargo publish is idempotent for the same version.", file=sys.stderr)
                sys.exit(1)

        if i < len(batches):
            print(f"  Waiting {SLEEP_BETWEEN_BATCHES}s for crates.io index to update...", flush=True)
            time.sleep(SLEEP_BETWEEN_BATCHES)

    print(f"\nDone. All {len(all_crates)} crates published at version {version}.")
    print(f"  https://crates.io/crates/auths/{version}")


if __name__ == "__main__":
    main()
