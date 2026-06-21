# `recursive/` — the loop rig (draft)

The deterministic **control plane** for the recursive build system designed in
[`../recursive_design.md`](../recursive_design.md). It does the part an LLM cannot be trusted to do
to *itself* — enforce the budget, the guardrails, the stop rule, and provenance — and **delegates**
every cognitive phase (plan, build, review, reground) to an LLM runner.

> **It is glue + gates, not a brain (~500 lines, stdlib only).** The prompt files
> (`grounding_doc.md`, `runbook.md`, `meta_prompt.md`, the two review prompts) are the intelligence.
> This rig is what turns them from *"a discipline you hope the agent follows"* into *"a system that
> enforces it."*

---

## The cycle

```
   ground ──▶ plan ──▶ build ──▶  GUARD SWEEP  ──▶ review ──▶ reground ──▶ decide
  (read the   (write   (agent     (the REAL gate;  (arch +    (cycle_       (stop on budget
   setpoint)   the      burns the  fail closed on   red-team   summary.md +  or diminishing
               ledger)  ledger     the 1st          over the   drift check)  returns; else
                        down)      violation)       range)                   loop / checkpoint)
```

Each cycle is one timestamped folder under `docs/plans/<area>/<YYYYMMDD-HHMMSS>/` holding the
ledger, the two review reports, `cycle_summary.md`, and a machine-readable `cycle_record.json`.

## The guards (the reason it exists)

The guard sweep runs after the build and **fails closed** — the cycle aborts on the first
violation. Each guard closes one drawback from `recursive_design.md §5`:

| Guard | Closes |
|---|---|
| **control-plane-immutable** | meta-drift — refuses a cycle that edited `docs/prompts/` (the prompts *and* this rig). The loop may not rewrite its own constitution. |
| **ci-mirror** | map/territory desync — runs the project's real check surface and reads exit codes, not the agent's "it's green." |
| **no-disabled-tests** | spec-gaming — a test commented out / `#[ignore]`'d / `.skip`'d in the range (the RT-001 lesson: a disabled security test is a failing test). |
| **no-process-metadata** | plan/epic/`red-team`/AI vocabulary leaking into the shipped tree (runbook directive 9). |
| **secrets-scan** | a secret riding along with a moved/relicensed file. |

Run them standalone (e.g. as a pre-merge hook or CI step):

```bash
python -m loop_rig guard                 # over HEAD~1..HEAD, full CI-mirror
python -m loop_rig guard --base <sha>     # over a range
python -m loop_rig guard --no-ci          # fast structural checks only
```

## Quickstart

```bash
cd docs/prompts/recursive

# SAFE DEFAULT — dry-run: no LLM, no writes, no merges. Watch a cycle's shape.
python -m loop_rig run --area go_to_market

# For real: drive the agent + run guards, bounded, with a human checkpoint each cycle (L1).
python -m loop_rig run --execute --max-cycles 3 --budget-tokens 2000000 --checkpoint
```

Python 3.10+, standard library only. No install step.

## Safety properties

- **Fail closed.** Any guard error is a violation; any unreadable diff aborts the cycle.
- **Safe default.** `run` is a dry-run unless you pass `--execute`. The CI-mirror (real subprocesses)
  only runs under `--execute`.
- **Control-plane immutability.** The rig refuses a cycle that touched `docs/prompts/` — which
  contains the prompts *and this rig*. It cannot be used to edit itself.
- **The rig never commits or merges.** The agent does that during `build`; the rig only *observes*
  git (read-only) and *audits* the result.
- **Bounded.** A `Budget` (token and/or wall-clock ceiling) is the loop's only natural brake; it is
  charged after every phase and stops the run when hit.

## The seams you adapt before `--execute` on a repo with merge rights

All marked `SEAM` in the code:

- **`runner.ClaudeCliRunner`** — the exact `claude -p` invocation and how token usage is parsed for
  your CLI/version. (The default runner is `DryRunRunner`, so the rig is safe out of the box.)
- **`guards.secrets_scan`** — a regex first pass; swap for `gitleaks`/`trufflehog` in production.
- **`cycle.decide_continue`** — the stop rule reads severity counts from the red-team report via
  regex; wire it to your findings register for a stronger signal.
- **`config.AUTHS_CI_MIRROR`** — the real gate. Keep it identical to your CI.

## File map

| File | Role |
|---|---|
| `config.py` | Paths, the CI-mirror commands, and the guard patterns — the one place to tune. |
| `git.py` | Read-only git helpers. The rig observes; it never writes git. |
| `guards.py` | The five deterministic guardrails. Each fails closed. |
| `runner.py` | The LLM seam — `DryRunRunner` (default) and `ClaudeCliRunner`. |
| `cycle.py` | The state machine + `Budget` + the stop rule + provenance. |
| `__main__.py` | The CLI (`run`, `guard`). |

## Status: DRAFT

- **Real and working today:** the cycle state machine, all five guards, the budget, provenance
  (`cycle_record.json`), the dry-run, and the CLI. `python -m loop_rig run` and `… guard` run as-is.
- **Stubs / seams (clearly marked, wire before real merge rights):** the `claude` invocation + token
  parsing, the secrets-scan depth, and the severity parse in the stop rule.

## How it maps to the prompt files

| Prompt | Role in the loop | Rig touch-point |
|---|---|---|
| `grounding_doc.md` | setpoint (vision, anti-goals, destination) | read in `plan`/`reground`; protected by `control-plane-immutable` |
| `plan.md` | planner → next ledger | the `plan` phase directive |
| `runbook.md` | per-cycle controller | the `build` phase directive |
| `meta_prompt.md` | engineering bar | the `build` phase directive |
| `architectural_review.md` · `red_team_general.md` | sensors | the `review` phase; their findings seed the next cycle |

The rig sequences these and enforces the guardrails that `recursive_design.md` only *described*.
