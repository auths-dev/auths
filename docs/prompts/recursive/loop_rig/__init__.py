"""loop_rig — the deterministic control plane for the recursive build system.

The rig owns scheduling, budget, the guard sweep, the stop rule, and provenance, and delegates
every cognitive phase (plan, build, review, reground) to an LLM runner. It is glue + gates, not a
brain. See `README.md` and `../../recursive_design.md`.
"""
from __future__ import annotations

from .config import Config, Prompts
from .cycle import Budget, CycleOutcome, Decision, decide_continue, run_cycle
from .guards import GuardResult, enforce
from .runner import (
    ClaudeCliRunner,
    DryRunRunner,
    Phase,
    PhaseRequest,
    PhaseResult,
    PhaseRunner,
)

__all__ = [
    "Config",
    "Prompts",
    "Budget",
    "CycleOutcome",
    "Decision",
    "run_cycle",
    "decide_continue",
    "GuardResult",
    "enforce",
    "Phase",
    "PhaseRequest",
    "PhaseResult",
    "PhaseRunner",
    "DryRunRunner",
    "ClaudeCliRunner",
]
