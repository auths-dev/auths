#!/usr/bin/env python3
"""
Sync every package version to the workspace version in Cargo.toml.

Usage:
    python scripts/releases/0_versions.py                  # dry-run (shows drift table)
    python scripts/releases/0_versions.py --check          # exit 1 on drift (CI gate)
    python scripts/releases/0_versions.py --write          # stamp all files
    python scripts/releases/0_versions.py --set 0.1.4      # bump workspace version, then stamp all files

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
        (REPO_ROOT / "packages/auths-fastapi/pyproject.toml", TOML_VERSION_RE, py_version),
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


# uv-managed Python packages carry their own version inside uv.lock. When only
# pyproject.toml is bumped, `uv sync --locked` in the publish workflows refuses
# the now-stale lock — which is exactly what broke the FastAPI and Python-SDK
# publishes on 0.1.5. `uv lock` rewrites just this one line; we stamp it directly
# (anchored to the editable package's own `[[package]]` block, where the version
# is unique) so `--check` catches the drift with no `uv` on PATH — it runs in CI.
UV_LOCKS: list[tuple[str, str]] = [
    ("packages/auths-python/uv.lock", "auths"),
    ("packages/auths-fastapi/uv.lock", "auths-fastapi"),
]


def uv_lock_re(name: str) -> re.Pattern:
    return re.compile(r'(name = "' + re.escape(name) + r'"\nversion = )"([^"]+)"')


# Cargo.lock files that a version bump breaks: (a) committed, (b) read with
# `--locked` by a publish, and (c) NOT the root lock — the root self-heals on any
# `cargo` invocation and is gated again by `cargo publish --locked`, whereas a
# SEPARATE-workspace lock is touched by nothing until its publish reads it stale.
# Today that is exactly the Python SDK's lock: maturin runs `--release --locked`
# against it, and the bump left it at 0.1.3 — the 0.1.5 break. (The Node SDK /
# Swift locks are gitignored and their builds don't pass `--locked`; CI
# regenerates them. mobile-ffi's lock is stale but published nowhere.) Path
# entries carry no checksum and reference each other by bare name (no inline
# version), so stamping each workspace-crate `version` line is exact — no `cargo`
# needed, so `--check` gates this in CI too. Add a lock here the day a new
# separate workspace starts being published `--locked`.
CARGO_LOCKS: list[str] = [
    "packages/auths-python/Cargo.lock",  # maturin: `--release --locked` (broke 0.1.5)
]


def auths_crate_names() -> set[str]:
    """Workspace crate names (crates/*) — the crates that must sit at the
    workspace version in every lockfile. Wrapper packages under packages/
    (auths-python, auths-node, …) keep their own independent versions and are
    excluded by construction: they are not under crates/."""
    names: set[str] = set()
    for toml in sorted((REPO_ROOT / "crates").glob("*/Cargo.toml")):
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', toml.read_text(), re.MULTILINE)
        if m:
            names.add(m.group(1))
    return names


def cargo_lock_entry_re(name: str) -> re.Pattern:
    """The `[[package]]` block for one workspace crate: name then version, adjacent."""
    return re.compile(
        r'(\[\[package\]\]\nname = "' + re.escape(name) + r'"\nversion = )"([^"]+)"'
    )


def cargo_lock_stale(path: Path, crates: set[str], version: str) -> list[str]:
    """Workspace crates in `path` pinned at something other than `version`."""
    if not path.exists():
        return []
    text = path.read_text()
    return [
        name
        for name in sorted(crates)
        if (m := cargo_lock_entry_re(name).search(text)) and m.group(2) != version
    ]


def stamp_cargo_lock(path: Path, crates: set[str], version: str) -> None:
    text = path.read_text()
    for name in crates:
        text = cargo_lock_entry_re(name).sub(lambda m: f'{m.group(1)}"{version}"', text)
    path.write_text(text)


def set_workspace_version(new_version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", new_version):
        print(f"ERROR: '{new_version}' is not a valid semver version", file=sys.stderr)
        sys.exit(1)
    text = CARGO_TOML.read_text()
    section = re.search(
        r'(\[workspace\.package\][^\[]*?version\s*=\s*)"[^"]+"', text
    )
    if not section:
        print("ERROR: no version in [workspace.package] in Cargo.toml", file=sys.stderr)
        sys.exit(1)
    CARGO_TOML.write_text(
        text[: section.start()] + f'{section.group(1)}"{new_version}"' + text[section.end() :]
    )
    print(f"Set workspace version -> {new_version}")


def parse_set_arg() -> str | None:
    if "--set" not in sys.argv:
        return None
    idx = sys.argv.index("--set")
    if idx + 1 >= len(sys.argv):
        print("ERROR: --set requires a version argument", file=sys.stderr)
        sys.exit(1)
    return sys.argv[idx + 1]


def main() -> None:
    check = "--check" in sys.argv
    write = "--write" in sys.argv

    new_version = parse_set_arg()
    if new_version is not None:
        set_workspace_version(new_version)
        write = True

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

    py_version = pep440_version(workspace_version)
    for rel, name in UV_LOCKS:
        path = REPO_ROOT / rel
        if not path.exists():
            continue
        pattern = uv_lock_re(name)
        match = pattern.search(path.read_text())
        current = match.group(2) if match else None
        status = "ok" if current == py_version else f"DRIFT (expected {py_version})"
        print(f"  {path.relative_to(REPO_ROOT)}: {current} — {status}")
        if match and current != py_version:
            drifted.append((path, pattern, py_version))

    crates = auths_crate_names()
    cargo_drift: list[tuple[Path, list[str]]] = []
    for rel in CARGO_LOCKS:
        path = REPO_ROOT / rel
        if not path.exists():
            continue
        stale = cargo_lock_stale(path, crates, workspace_version)
        status = "ok" if not stale else f"{len(stale)} crate(s) DRIFT (expected {workspace_version})"
        print(f"  {path.relative_to(REPO_ROOT)}: {status}")
        if stale:
            cargo_drift.append((path, stale))

    if not drifted and dep_drift == 0 and not cargo_drift:
        print("\nAll package versions are in sync.")
        return

    if write:
        for path, pattern, expected in drifted:
            write_version(path, pattern, expected)
            print(f"Stamped {path.relative_to(REPO_ROOT)} -> {expected}")
        if dep_drift:
            stamp_workspace_deps(workspace_version)
            print(f"Stamped Cargo.toml internal dependency versions -> {workspace_version}")
        for path, stale in cargo_drift:
            stamp_cargo_lock(path, crates, workspace_version)
            print(
                f"Stamped {path.relative_to(REPO_ROOT)} "
                f"({len(stale)} crate(s)) -> {workspace_version}"
            )
        return

    print(
        f"\n{len(drifted) + (1 if dep_drift else 0) + len(cargo_drift)} file(s) out of sync.",
        file=sys.stderr,
    )
    print("Run with --write to stamp them.", file=sys.stderr)
    if check:
        sys.exit(1)


if __name__ == "__main__":
    main()
