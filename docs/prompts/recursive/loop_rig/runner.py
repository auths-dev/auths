"""The seam between the deterministic rig and the LLM. The rig orchestrates; the runner thinks.

Two implementations:
- `DryRunRunner` (the default): no LLM, no mutation — logs the directive it *would* send so you
  can watch a cycle's shape before it has merge rights.
- `ClaudeCliRunner`: drives Claude Code headless via `claude -p`. SEAM: adapt the invocation and
  token-parsing to your CLI/version.

Swap in any object with a `run(PhaseRequest) -> PhaseResult` method.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol


class Phase(Enum):
    PLAN = "plan"
    BUILD = "build"
    ARCH_REVIEW = "architectural-review"
    RED_TEAM = "red-team"
    REGROUND = "reground"


@dataclass(frozen=True)
class PhaseRequest:
    """One cognitive step. The directive references prompt files the agent reads itself."""

    phase: Phase
    instruction: str
    cwd: Path


@dataclass(frozen=True)
class PhaseResult:
    ok: bool
    output: str
    tokens: int


class PhaseRunner(Protocol):
    def run(self, req: PhaseRequest) -> PhaseResult: ...


class DryRunRunner:
    """Logs the directive and returns success at zero cost. No LLM, no writes, no merges."""

    def run(self, req: PhaseRequest) -> PhaseResult:
        print(f"  [dry-run] {req.phase.value}: {req.instruction.splitlines()[0]}")
        return PhaseResult(ok=True, output="(dry-run)", tokens=0)


@dataclass
class ClaudeCliRunner:
    """Drives Claude Code headless. SEAM: match the command + token shape to your install."""

    command: str = "claude"
    extra_args: tuple[str, ...] = ("-p", "--output-format", "json", "--permission-mode", "acceptEdits")
    timeout_s: int = 60 * 60

    def run(self, req: PhaseRequest) -> PhaseResult:
        argv = [self.command, *self.extra_args, req.instruction]
        try:
            out = subprocess.run(argv, cwd=req.cwd, capture_output=True, text=True, timeout=self.timeout_s)
        except (OSError, subprocess.TimeoutExpired) as e:
            return PhaseResult(False, f"runner failed: {e}", 0)
        if out.returncode != 0:
            return PhaseResult(False, out.stderr.strip() or out.stdout.strip(), 0)
        return PhaseResult(True, out.stdout, _parse_tokens(out.stdout))


def _parse_tokens(stdout: str) -> int:
    """Best-effort token usage from `claude --output-format json`. SEAM: match your output shape."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return 0
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    return int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
