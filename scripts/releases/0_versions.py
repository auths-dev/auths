#!/usr/bin/env python3
"""
Sync every package version to the workspace version in Cargo.toml.

Usage:
    python scripts/releases/0_versions.py            # dry-run (shows drift table)
    python scripts/releases/0_versions.py --check    # exit 1 on drift (CI gate)
    python scripts/releases/0_versions.py --write    # stamp all files

Source of truth: [workspace.package] version in the root Cargo.toml.

Targets:
    packages/auths-node/package.json          (semver, as-is)
    packages/auths-verifier-ts/package.json   (semver, as-is)
    packages/auths-express/package.json       (semver, as-is)
    packages/auths-python/pyproject.toml      (PEP 440 normalized, e.g. 0.0.1rc12)
    crates/auths-mobile-ffi/Cargo.toml        (separate workspace, semver as-is)

Requires:
    - python3 (no external dependencies)
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CARGO_TOML = REPO_ROOT / "Cargo.toml"

JSON_VERSION_RE = re.compile(r'("version"\s*:\s*)"[^"]+"')
TOML_VERSION_RE = re.compile(r'^(version\s*=\s*)"[^"]+"', re.MULTILINE)


def get_workspace_version() -> str:
    text = CARGO_TOML.read_text()
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


def pep440_version(semver: str) -> str:
    """Normalize a semver prerelease to PEP 440 (0.0.1-rc.12 -> 0.0.1rc12)."""
    version = re.sub(r"-rc\.?(\d+)", r"rc\1", semver)
    version = re.sub(r"-alpha\.?(\d+)", r"a\1", version)
    version = re.sub(r"-beta\.?(\d+)", r"b\1", version)
    return version


def read_version(path: Path, pattern: re.Pattern) -> str | None:
    match = pattern.search(path.read_text())
    if not match:
        return None
    inner = re.search(r'"([^"]+)"$', match.group(0))
    return inner.group(1) if inner else None


def write_version(path: Path, pattern: re.Pattern, version: str) -> None:
    text = path.read_text()
    updated = pattern.sub(lambda m: f'{m.group(1)}"{version}"', text, count=1)
    path.write_text(updated)


def targets(workspace_version: str) -> list[tuple[Path, re.Pattern, str]]:
    py_version = pep440_version(workspace_version)
    return [
        (REPO_ROOT / "packages/auths-node/package.json", JSON_VERSION_RE, workspace_version),
        (REPO_ROOT / "packages/auths-verifier-ts/package.json", JSON_VERSION_RE, workspace_version),
        (REPO_ROOT / "packages/auths-express/package.json", JSON_VERSION_RE, workspace_version),
        (REPO_ROOT / "packages/auths-python/pyproject.toml", TOML_VERSION_RE, py_version),
        (REPO_ROOT / "crates/auths-mobile-ffi/Cargo.toml", TOML_VERSION_RE, workspace_version),
    ]


# Internal workspace dependencies must carry an explicit `version` matching the
# workspace version: `cargo publish` strips the `path` and requires a version
# requirement on every dependency.
WORKSPACE_DEP_RE = re.compile(
    r'(auths-[a-z0-9-]+ = \{ path = "crates/[^"]+", version = )"([^"]+)"'
)


# Crate-local declarations (`path = "../auths-x", version = "..."`) need the
# same treatment.
CRATE_DEP_RE = re.compile(
    r'(auths-[a-z0-9-]+ = \{ path = "\.\./[^"]+", version = )"([^"]+)"'
)


def dep_files() -> list[Path]:
    return [REPO_ROOT / "Cargo.toml"] + sorted(REPO_ROOT.glob("crates/*/Cargo.toml"))


def workspace_dep_drift(workspace_version: str) -> int:
    count = 0
    for f in dep_files():
        pattern = WORKSPACE_DEP_RE if f.parent == REPO_ROOT else CRATE_DEP_RE
        text = f.read_text()
        count += sum(
            1 for m in pattern.finditer(text) if m.group(2) != workspace_version
        )
    return count


def stamp_workspace_deps(workspace_version: str) -> None:
    for f in dep_files():
        pattern = WORKSPACE_DEP_RE if f.parent == REPO_ROOT else CRATE_DEP_RE
        text = pattern.sub(lambda m: f'{m.group(1)}"{workspace_version}"', f.read_text())
        f.write_text(text)


def main() -> None:
    check = "--check" in sys.argv
    write = "--write" in sys.argv

    workspace_version = get_workspace_version()
    print(f"Workspace version: {workspace_version}")

    drifted: list[tuple[Path, re.Pattern, str]] = []
    for path, pattern, expected in targets(workspace_version):
        current = read_version(path, pattern)
        if current is None:
            print(f"ERROR: no version field found in {path}", file=sys.stderr)
            sys.exit(1)
        status = "ok" if current == expected else f"DRIFT (expected {expected})"
        print(f"  {path.relative_to(REPO_ROOT)}: {current} — {status}")
        if current != expected:
            drifted.append((path, pattern, expected))

    dep_drift = workspace_dep_drift(workspace_version)
    dep_status = "ok" if dep_drift == 0 else f"{dep_drift} DRIFT"
    print(f"  Cargo.toml internal dependency versions: {dep_status}")

    if not drifted and dep_drift == 0:
        print("\nAll package versions are in sync.")
        return

    if write:
        for path, pattern, expected in drifted:
            write_version(path, pattern, expected)
            print(f"Stamped {path.relative_to(REPO_ROOT)} -> {expected}")
        if dep_drift:
            stamp_workspace_deps(workspace_version)
            print(f"Stamped Cargo.toml internal dependency versions -> {workspace_version}")
        return

    print(
        f"\n{len(drifted) + (1 if dep_drift else 0)} file(s) out of sync.",
        file=sys.stderr,
    )
    print("Run with --write to stamp them.", file=sys.stderr)
    if check:
        sys.exit(1)


if __name__ == "__main__":
    main()
