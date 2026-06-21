"""CLI: `python -m loop_rig run | guard`.

Safe by default: `run` is a dry-run (no LLM, no writes, no merges) unless you pass `--execute`.
`guard` runs the deterministic guard sweep standalone — useful as a pre-merge hook or CI step.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import git, guards
from .config import Config
from .cycle import Budget, CycleOutcome, run_cycle
from .runner import ClaudeCliRunner, DryRunRunner

# loop_rig/__main__.py → loop_rig → recursive → prompts → docs → <repo root>
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[4]


def _config(args: argparse.Namespace) -> Config:
    return Config.for_auths(Path(args.repo_root).resolve())


def cmd_run(args: argparse.Namespace) -> int:
    config = _config(args)
    runner = DryRunRunner() if args.dry_run else ClaudeCliRunner()
    budget = Budget(token_ceiling=args.budget_tokens, wall_clock_s=args.budget_seconds)
    run_ci = not args.dry_run  # the CI-mirror is real I/O; skip it under dry-run

    for i in range(args.max_cycles):
        mode = "dry-run" if args.dry_run else "EXECUTE"
        print(f"\n=== cycle {i + 1}/{args.max_cycles} ({mode}) ===")
        outcome = run_cycle(config, runner, budget, args.area, run_ci=run_ci)
        _print_outcome(outcome)
        if outcome.aborted:
            print("aborted — stopping the loop (fail-closed).")
            return 1
        if outcome.decision and not outcome.decision.cont:
            print(f"stop: {outcome.decision.reason}")
            return 0
        if args.checkpoint and not _human_go():
            print("paused at cycle boundary.")
            return 0
    return 0


def cmd_guard(args: argparse.Namespace) -> int:
    config = _config(args)
    head_sha = git.head(config.repo_root)
    base = args.base or f"{head_sha}~1"
    results = guards.enforce(config, base, head_sha, run_ci=not args.no_ci)
    for g in results:
        print(f"  {'✓' if g.ok else '✗'} {g.name}: {g.detail.splitlines()[0]}")
    return 0 if all(results) else 1


def _print_outcome(o: CycleOutcome) -> None:
    print(f"  range:  {o.base_sha[:10]}..{o.head_sha[:10]}")
    print(f"  cycle:  {o.cycle_dir or '(none)'}")
    for g in o.guards:
        print(f"    {'✓' if g['ok'] else '✗'} {g['name']}: {g['detail'].splitlines()[0]}")
    if o.aborted:
        print(f"  ABORTED: {o.reason.splitlines()[0]}")
    elif o.decision:
        print(f"  decision: {'continue' if o.decision.cont else 'stop'} — {o.decision.reason}")
    print(f"  tokens: {o.tokens}")


def _human_go() -> bool:
    try:
        return input("  continue to next cycle? [y/N] ").strip().lower() == "y"
    except EOFError:
        return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="loop_rig", description="Deterministic control plane for the recursive build loop.")
    p.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT), help="repository root (default: inferred)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run one or more build cycles")
    r.add_argument("--area", default="go_to_market", help="plans sub-tree for this run")
    r.add_argument("--max-cycles", type=int, default=1)
    r.add_argument("--budget-tokens", type=int, default=None)
    r.add_argument("--budget-seconds", type=int, default=None)
    r.add_argument("--execute", action="store_true", help="actually drive the LLM + run guards (default: dry-run)")
    r.add_argument("--checkpoint", action="store_true", help="pause for a human 'go' between cycles (L1)")
    r.set_defaults(func=cmd_run)

    g = sub.add_parser("guard", help="run the guard sweep standalone (pre-merge hook / CI step)")
    g.add_argument("--base", default=None, help="base sha (default: HEAD~1)")
    g.add_argument("--no-ci", action="store_true", help="skip the CI-mirror (fast structural checks only)")
    g.set_defaults(func=cmd_guard)

    args = p.parse_args(argv)
    args.dry_run = not getattr(args, "execute", False)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
