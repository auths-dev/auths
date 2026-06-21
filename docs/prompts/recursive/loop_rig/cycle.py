"""The cycle state machine: ground → plan → build → GUARD → review → reground → decide.

The rig owns control flow, budget, the guard sweep, the stop rule, and provenance; every
cognitive step is delegated to the runner. Guards run after the build and the cycle aborts
**fail closed** on the first violation. One cycle = one timestamped folder under `plans/`.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import git, guards
from .config import Config
from .runner import Phase, PhaseRequest, PhaseRunner


@dataclass
class Budget:
    """A hard ceiling on a run. The loop has no natural brake; this is it."""

    token_ceiling: int | None = None
    wall_clock_s: int | None = None
    _start: float = field(default_factory=time.monotonic)
    spent_tokens: int = 0

    def charge(self, tokens: int) -> None:
        self.spent_tokens += max(0, tokens)

    def exhausted(self) -> tuple[bool, str]:
        """Return `(done, reason)`."""
        if self.token_ceiling is not None and self.spent_tokens >= self.token_ceiling:
            return True, f"token ceiling reached ({self.spent_tokens}/{self.token_ceiling})"
        if self.wall_clock_s is not None and (time.monotonic() - self._start) >= self.wall_clock_s:
            return True, "wall-clock budget reached"
        return False, ""


@dataclass
class Decision:
    cont: bool
    reason: str


@dataclass
class CycleOutcome:
    cycle_dir: str
    base_sha: str
    head_sha: str
    aborted: bool
    reason: str
    guards: list[dict]
    decision: Decision | None
    tokens: int


def run_cycle(
    config: Config,
    runner: PhaseRunner,
    budget: Budget,
    area: str,
    now=datetime.now,
    run_ci: bool = True,
) -> CycleOutcome:
    """Run one full build cycle and return its outcome (aborted-fail-closed or complete).

    Args:
    * `config`: rig configuration.
    * `runner`: the LLM seam (dry-run or real).
    * `budget`: the hard ceiling; charged after every phase.
    * `area`: the plans sub-tree this cycle lives in (e.g. "go_to_market").
    * `now`: clock injected for testability.
    * `run_ci`: run the CI-mirror guard (real subprocesses).

    Usage:
    ```python
    outcome = run_cycle(config, DryRunRunner(), Budget(), "go_to_market")
    ```
    """
    repo = config.repo_root
    base = git.head(repo)

    # 0. Ground — the setpoint must exist before anything plans against it.
    if not (repo / config.grounding_doc).is_file():
        return _abort(config, base, base, "grounding doc missing — cannot plan without a setpoint")

    cycle_dir = _make_cycle_dir(config, area, now)
    rel_dir = cycle_dir.relative_to(repo).as_posix()

    # 1. Plan → the next ledger, gated and in-vision.
    res = runner.run(PhaseRequest(Phase.PLAN, _plan_instruction(config, rel_dir), repo))
    budget.charge(res.tokens)
    if not res.ok:
        return _abort(config, base, git.head(repo), f"plan phase failed: {res.output}", cycle_dir)

    # 2. Build → the agent burns the ledger down per the runbook.
    res = runner.run(PhaseRequest(Phase.BUILD, _build_instruction(config, rel_dir), repo))
    budget.charge(res.tokens)
    head_sha = git.head(repo)
    if not res.ok:
        return _abort(config, base, head_sha, f"build phase failed: {res.output}", cycle_dir)

    # 3. Guard sweep — the REAL gate. Fail closed on the first violation.
    results = guards.enforce(config, base, head_sha, run_ci=run_ci)
    if not all(results):
        failed = "\n".join(f"  ✗ {g.name}: {g.detail}" for g in results if not g.ok)
        return _abort(config, base, head_sha, "guard violation:\n" + failed, cycle_dir, results)

    # 4. Review → two adversarial sensors over the cycle's range.
    for phase, prompt in (
        (Phase.ARCH_REVIEW, config.prompts.architectural_review),
        (Phase.RED_TEAM, config.prompts.red_team),
    ):
        res = runner.run(PhaseRequest(phase, _review_instruction(rel_dir, base, head_sha, prompt), repo))
        budget.charge(res.tokens)

    # 5. Reground → the cycle summary + drift check, then the stop rule.
    res = runner.run(PhaseRequest(Phase.REGROUND, _reground_instruction(config, rel_dir), repo))
    budget.charge(res.tokens)

    decision = decide_continue(cycle_dir, budget)
    outcome = CycleOutcome(rel_dir, base, head_sha, False, "", [_as_dict(g) for g in results], decision, budget.spent_tokens)
    _write_record(cycle_dir, outcome)
    return outcome


def decide_continue(cycle_dir: Path, budget: Budget) -> Decision:
    """Stop on exhausted budget or diminishing returns (only LOW/INFO findings); else continue.

    SEAM: severity is read from the red-team report's verdict counts via regex. Wire it to your
    findings register for a stronger signal.
    """
    done, why = budget.exhausted()
    if done:
        return Decision(False, why)
    report = next(iter(sorted(cycle_dir.glob("red_team_*.md"))), None)
    if report is None:
        return Decision(True, "no red-team report found — continue and investigate")
    text = report.read_text(errors="ignore")
    serious = sum(
        int(m.group(1)) for sev in ("CRITICAL", "HIGH", "MEDIUM")
        if (m := re.search(rf"(\d+)\s+{sev}", text))
    )
    if serious == 0:
        return Decision(False, "diminishing returns — only LOW/INFO findings this cycle")
    return Decision(True, f"{serious} CRITICAL/HIGH/MEDIUM finding(s) remain")


# --- phase directives (short; the agent reads the referenced prompt files itself) ---

def _plan_instruction(config: Config, rel_dir: str) -> str:
    return (
        f"Follow {config.prompts.plan}. Read the setpoint {config.prompts.grounding} and the previous "
        f"cycle's review reports, then generate the next ledger at {rel_dir}/progress.md — epics ordered "
        f"by attack, each row gated per {config.prompts.runbook}. Reject at plan-time any row that crosses "
        f"a grounding anti-goal."
    )


def _build_instruction(config: Config, rel_dir: str) -> str:
    return (
        f"Follow {config.prompts.runbook}. Burn down {rel_dir}/progress.md until every row is merged or "
        f"gated. Hold every change to {config.prompts.meta_prompt}. Prove on the wired path; never disable "
        f"a test to go green; keep process metadata and AI attribution out of the tree."
    )


def _review_instruction(rel_dir: str, base: str, head_sha: str, prompt: str) -> str:
    return f"Follow {prompt} over the range {base}..{head_sha}. Write the report into {rel_dir}/."


def _reground_instruction(config: Config, rel_dir: str) -> str:
    return (
        f"Write {rel_dir}/cycle_summary.md: what merged this cycle, a drift check against "
        f"{config.prompts.grounding}, residual risk, and the seed backlog for the next cycle."
    )


# --- provenance + helpers ---

def _make_cycle_dir(config: Config, area: str, now) -> Path:
    d = config.repo_root / config.plans_root / area / now().strftime("%Y%m%d-%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _as_dict(g: guards.GuardResult) -> dict:
    return {"name": g.name, "ok": g.ok, "detail": g.detail}


def _abort(config, base, head_sha, reason, cycle_dir: Path | None = None, results=None) -> CycleOutcome:
    rel = cycle_dir.relative_to(config.repo_root).as_posix() if cycle_dir else ""
    outcome = CycleOutcome(rel, base, head_sha, True, reason, [_as_dict(g) for g in (results or [])], None, 0)
    if cycle_dir:
        _write_record(cycle_dir, outcome)
    return outcome


def _write_record(cycle_dir: Path, outcome: CycleOutcome) -> None:
    """Write the machine-readable cycle record — the audit trail for this cycle."""
    rec = {
        "base_sha": outcome.base_sha,
        "head_sha": outcome.head_sha,
        "aborted": outcome.aborted,
        "reason": outcome.reason,
        "guards": outcome.guards,
        "decision": (
            {"continue": outcome.decision.cont, "reason": outcome.decision.reason}
            if outcome.decision else None
        ),
        "tokens": outcome.tokens,
    }
    (cycle_dir / "cycle_record.json").write_text(json.dumps(rec, indent=2) + "\n")
