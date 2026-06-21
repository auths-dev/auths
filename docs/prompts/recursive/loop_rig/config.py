"""Configuration: where the control plane lives, and what "green" actually means.

One place to tune the rig. Everything here is data — the guards and the cycle read it;
nothing here does I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# The local check-surface green-gate (runbook.md appendix). The REAL gate — exit codes,
# not an agent's claim that it's green. Mirror your CI exactly.
AUTHS_CI_MIRROR: tuple[str, ...] = (
    "cargo build --workspace",
    "cargo clippy --workspace --all-targets --exclude murmur-ffi -- -D warnings",
    "cargo fmt --all --check",
    "cargo run -q -p xtask -- gen-error-docs --check",
    "cargo deny check",
)

# Plan/process vocabulary + AI attribution that must never reach the tree (runbook directive 9).
METADATA_PATTERNS: tuple[str, ...] = (
    r"\bproof-battery\b",
    r"\bred.?team\b",
    r"\brunbook\b",
    r"\bepic\s+[A-Z0-9]",
    r"\bRT-\d{3}\b",
    r"(?i)\bclaude\b",
    r"(?i)co-authored-by:.*claude",
    r"(?i)generated with .*\bai\b",
)

# Tests being switched off — the RT-001 lesson (a security suite commented out of the build).
DISABLED_TEST_PATTERNS: tuple[str, ...] = (
    r"^\s*//\s*mod\s+\w+\s*;",            # rust: commented-out test module
    r"^\s*//\s*#\[(?:tokio::)?test\]",    # rust: commented-out test attribute
    r"#\[ignore\]",                        # rust: ignored test
    r"(?i)\b(?:it|test|describe)\.skip\b", # js/ts
    r"@(?:pytest\.mark\.skip|unittest\.skip)",  # python
)

# First-pass secret markers. SEAM: in production, shell out to gitleaks/trufflehog instead.
SECRET_PATTERNS: tuple[str, ...] = (
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"(?i)\b(?:password|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
)


@dataclass(frozen=True)
class Prompts:
    """Paths (repo-relative) to the control-plane prompt files the phases follow."""

    grounding: str
    plan: str
    runbook: str
    meta_prompt: str
    architectural_review: str
    red_team: str


@dataclass(frozen=True)
class Config:
    """All the knobs the rig reads. Build one with `Config.for_auths(repo_root)`."""

    repo_root: Path
    plans_root: str
    grounding_doc: str
    prompts: Prompts
    ci_mirror: tuple[str, ...]
    control_plane_prefixes: tuple[str, ...]
    metadata_patterns: tuple[str, ...]
    disabled_test_patterns: tuple[str, ...]
    secret_patterns: tuple[str, ...]

    @classmethod
    def for_auths(cls, repo_root: Path) -> "Config":
        """Default configuration for this repository.

        Args:
        * `repo_root`: absolute path to the `auths/` repository root.

        Usage:
        ```python
        config = Config.for_auths(Path("/path/to/auths"))
        ```
        """
        p = "docs/prompts"
        return cls(
            repo_root=repo_root,
            plans_root="docs/plans",
            grounding_doc=f"{p}/grounding_doc.md",
            prompts=Prompts(
                grounding=f"{p}/grounding_doc.md",
                plan=f"{p}/plan.md",
                runbook=f"{p}/runbook.md",
                meta_prompt=f"{p}/meta_prompt.md",
                architectural_review=f"{p}/architectural_review.md",
                red_team=f"{p}/red_team_general.md",
            ),
            ci_mirror=AUTHS_CI_MIRROR,
            # Protects every prompt AND this rig — the loop cannot edit its own constitution.
            control_plane_prefixes=(f"{p}/",),
            metadata_patterns=METADATA_PATTERNS,
            disabled_test_patterns=DISABLED_TEST_PATTERNS,
            secret_patterns=SECRET_PATTERNS,
        )
