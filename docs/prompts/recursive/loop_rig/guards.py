"""The deterministic guardrails — the rig's reason to exist.

Each guard is (close to) a pure function from observed facts to a typed verdict, and every
guard **fails closed**: an unexpected error is a violation, never a pass. The cycle runs the
whole sweep after a build and aborts on the first failure.

Each guard closes one drawback from `../recursive_design.md`:
- control_plane_unchanged → meta-drift (the loop rewriting its own goal/rules)
- ci_mirror             → map/territory desync (trusting "it's green" over the real exit code)
- no_disabled_tests     → spec-gaming (turning a test off to go green — the RT-001 lesson)
- no_process_metadata   → process leakage into the shipped tree
- secrets_scan          → leaking a secret with a moved/relicensed file
"""
from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from . import git
from .config import Config


@dataclass(frozen=True)
class GuardResult:
    """A single guard's verdict. Truthy iff it passed."""

    name: str
    ok: bool
    detail: str

    def __bool__(self) -> bool:
        return self.ok


def iter_added_lines(diff_text: str) -> Iterator[tuple[str, str]]:
    """Yield `(path, added_line)` for every '+' line in a unified diff, attributed to its file."""
    path = "?"
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            yield path, line[1:]


def _is_source(path: str) -> bool:
    """A code file we hold to the tree rules — not docs, plans, or markdown."""
    return not (path.endswith(".md") or path.startswith("docs/"))


def control_plane_unchanged(changed: list[str], prefixes: tuple[str, ...]) -> GuardResult:
    """Refuse a cycle that edited its own constitution (grounding / runbook / prompts / this rig)."""
    hits = [f for f in changed if any(f.startswith(p) for p in prefixes)]
    if hits:
        return GuardResult(
            "control-plane-immutable", False,
            "the loop edited the control plane (only a human may): " + ", ".join(hits),
        )
    return GuardResult("control-plane-immutable", True, "control plane untouched")


def _scan_added(diff_text: str, patterns: tuple[str, ...]) -> list[str]:
    """Added source lines matching any pattern, as `path: line` strings."""
    rx = [re.compile(p) for p in patterns]
    return [
        f"{path}: {line.strip()}"
        for path, line in iter_added_lines(diff_text)
        if _is_source(path) and any(r.search(line) for r in rx)
    ]


def no_disabled_tests(diff_text: str, patterns: tuple[str, ...]) -> GuardResult:
    """Tripwire for a test being commented out / ignored / skipped in this range."""
    hits = _scan_added(diff_text, patterns)
    if hits:
        return GuardResult(
            "no-disabled-tests", False,
            "a test may have been switched off (a disabled security test is a failing test):\n  "
            + "\n  ".join(hits[:10]),
        )
    return GuardResult("no-disabled-tests", True, "no tests disabled")


def no_process_metadata(diff_text: str, patterns: tuple[str, ...]) -> GuardResult:
    """Tripwire for plan/process/AI vocabulary leaking into the shipped tree."""
    hits = _scan_added(diff_text, patterns)
    if hits:
        return GuardResult(
            "no-process-metadata", False,
            "plan/process/AI vocabulary leaked into the tree:\n  " + "\n  ".join(hits[:10]),
        )
    return GuardResult("no-process-metadata", True, "tree is free of process metadata")


def secrets_scan(changed: list[str], repo_root: Path, patterns: tuple[str, ...]) -> GuardResult:
    """First-pass secret scan of changed files. SEAM: swap for gitleaks/trufflehog in production."""
    rx = [re.compile(p) for p in patterns]
    hits: list[str] = []
    for rel in changed:
        f = repo_root / rel
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            return GuardResult("secrets-scan", False, f"could not read {rel} — failing closed")
        hits += [f"{rel}: matched /{r.pattern[:40]}/" for r in rx if r.search(text)]
    if hits:
        return GuardResult("secrets-scan", False, "possible secret in changed files:\n  " + "\n  ".join(hits[:10]))
    return GuardResult("secrets-scan", True, "no secret markers found")


def ci_mirror(commands: tuple[str, ...], repo_root: Path) -> GuardResult:
    """Run the project's full check surface — the REAL gate. First non-zero fails the cycle."""
    for cmd in commands:
        out = subprocess.run(cmd, cwd=repo_root, shell=True, capture_output=True, text=True)
        if out.returncode != 0:
            tail = (out.stdout + out.stderr).strip().splitlines()[-15:]
            return GuardResult("ci-mirror", False, f"`{cmd}` failed:\n  " + "\n  ".join(tail))
    return GuardResult("ci-mirror", True, f"all {len(commands)} checks green")


def enforce(config: Config, base: str, head_sha: str, run_ci: bool = True) -> list[GuardResult]:
    """Run every guard over `base..head_sha`. Fail closed: any exception becomes a violation.

    Args:
    * `config`: the rig configuration (paths, patterns, CI commands).
    * `base`, `head_sha`: the range to inspect (typically the whole cycle).
    * `run_ci`: run the CI-mirror (real subprocesses); set False for fast structural-only checks.

    Usage:
    ```python
    results = enforce(config, base_sha, git.head(repo))
    if not all(results): abort(...)
    ```
    """
    try:
        changed = git.changed_files(base, head_sha, config.repo_root)
        diff = git.diff_text(base, head_sha, config.repo_root)
    except Exception as e:  # fail closed — if we can't read the diff, we can't clear the cycle
        return [GuardResult("diff", False, f"could not read the cycle diff: {e}")]

    results = [
        control_plane_unchanged(changed, config.control_plane_prefixes),
        no_disabled_tests(diff, config.disabled_test_patterns),
        no_process_metadata(diff, config.metadata_patterns),
        secrets_scan(changed, config.repo_root, config.secret_patterns),
    ]
    if run_ci:
        results.append(ci_mirror(config.ci_mirror, config.repo_root))
    return results
