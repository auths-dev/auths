# Smoke Tests

Golden-path smoke tests for the `auths` CLI: the lifecycle a real developer, CI job, and
agent operator hit, run headlessly against the **locally built binary** (never the PATH
install — stale installed binaries have burned us before).

> The previous version of `end_to_end.py` exercised the Auths + Radicle stack. Radicle is
> deprecated and `auths-radicle` removed; the script was rewritten 2026-06-10 as the CLI
> golden-path test described below.

## Files

| File | What it is |
|------|------------|
| `end_to_end.py` | The harness. 11 scenarios, ~44 steps, ~30 s, fully headless. |
| `last_run.json` | Machine-readable results of the most recent run (per-step rc, duration, full stdout/stderr). |
| `findings_2026_06_10.md` | Analysis of the run as opinionated design decisions (D1–D10): what's broken, what the UX should be, alternatives rejected. |
| `implementation_plan_2026_06_10.md` | Execution companion: verified entry points (`file:line`), resolved micro-decisions, acceptance criteria keyed to smoke-step names, phase ordering. |
| `cli_improvements.md` | Older CLI UX notes. |

## Running

```bash
cargo build -p auths-cli                      # build first — the script does not build
python3 docs/smoketests/end_to_end.py         # full run
python3 docs/smoketests/end_to_end.py --keep  # keep temp HOMEs for inspection
python3 docs/smoketests/end_to_end.py --release   # test target/release/auths
AUTHS_BIN=/path/to/auths python3 docs/smoketests/end_to_end.py  # explicit binary
```

Exit code 0 = no failures. Per-step detail lands in `last_run.json`.

## What it covers

1. Developer first-run (`init` → `status` → `whoami` → key/device list)
2. The 30-second aha (`auths demo` — must be headless and fast)
3. Artifact signing (`sign <file>` → `verify <file>`)
4. Git commit signing (plain `git commit` per the README, then `auths sign HEAD`)
5. Stateless verification (`id export-bundle` → `verify --identity-bundle`)
6. Trust pinning (pin → list → show → remove)
7. Agent delegation (`id agent add`, the supported agent path)
8. Key rotation (`id rotate` → sign + verify again)
9. CI profile (3 fresh HOMEs — flakiness probe — then signing via the printed env block)
10. Retired-path UX (`init --profile agent` must fail with actionable guidance)
11. Hygiene (doctor, config, error lookup, completions, `--json`, help surfaces)

## Harness invariants (keep these when editing)

- **Test the local build.** Resolve the binary from `target/{debug,release}/auths` or
  `AUTHS_BIN`; never bare `auths` from PATH.
- **Isolated HOME per scenario** — never touch the real `~/.auths`.
- **Headless always**: `AUTHS_KEYCHAIN_BACKEND=file`, `stdin=DEVNULL`, timeouts on every
  step, `--non-interactive` everywhere. Nothing may reach the Secure Enclave / Touch ID.
- **The passphrase fixture must satisfy the policy** (≥12 chars, ≥3 of 4 character
  classes — `crates/auths-core/src/crypto/encryption.rs`). A weak fixture fails init and
  cascades. Current fixture: `Smoke-Test-Pass1!`.
- **Parse stdout *and* stderr** — human output goes to stderr by convention.
- A failing step never aborts the suite; dependent steps skip with a reason.

---

## Prompt: recreate this analysis from scratch

Paste the following into a fresh Claude Code session at the repo root to reproduce the
whole exercise (smoke run → findings → implementation plan) against the current state of
the codebase:

```
Run a golden-path audit of the auths CLI and write up the results. Work from evidence,
not docs or memory — the deliverable is what the tool ACTUALLY does today.

1. BUILD & BASELINE
   - Build the CLI from source: `cargo build -p auths-cli`. Never test the PATH-installed
     binary; resolve `target/debug/auths` explicitly (stale installs have caused false
     bug reports before).
   - Discover the real command tree from `--help-all` and `crates/auths-cli/src/cli.rs`,
     and the real flags from the command modules — do not trust README/docs examples.

2. SMOKE RUN
   - Read `docs/smoketests/end_to_end.py`. Update it if the command tree drifted; keep
     its invariants (listed in docs/smoketests/README.md: local binary, isolated HOMEs,
     headless file keychain, policy-compliant passphrase fixture, stdout+stderr parsing,
     skip-with-reason on dependent failures).
   - Run it. For EVERY failure, trace the root cause in source before classifying it —
     cite file:line. A failure whose root cause is the harness (e.g. weak passphrase
     fixture) is a fix to the harness AND a UX finding about the error message that
     misled you. Re-run until results are stable and every failure is explained.

3. COMPARE PROMISES TO REALITY
   - Walk the golden path as documented in README.md ("Sign your first commit") and
     docs/getting-started/signing-commits.md. Any step where the documented command fails
     live is a P0 finding. Count user-visible steps; every step beyond
     `auths init` + normal git usage is a friction finding.

4. WRITE THE FINDINGS DOC (docs/smoketests/findings_<date>.md)
   - Opinionated, not neutral. Open with the bar: after `auths init`, the product is
     ZERO new verbs — `git commit` then `auths verify HEAD`, nothing else.
   - Each finding = evidence (terse, with file:line) → THE DECISION (one prescribed
     design) → rejected alternatives, named, with why. No "options to consider".
   - Include: a before/after table of the golden path in steps; a "what already meets
     the bar" section (protect what works); a punch list ordered by leverage, not
     severity.
   - Judge UX, not just correctness: contradictions between adjacent outputs, errors
     that recommend unrunnable commands, data printed to stderr, dead-end menu options,
     inconsistent exit codes, jargon leaks.

5. WRITE THE IMPLEMENTATION PLAN (docs/smoketests/implementation_plan_<date>.md)
   - Written so one session could execute it cold: verified file:line entry points for
     every change (grep them — don't guess); resolve every micro-decision the findings
     doc left open (e.g. WHICH git hook mechanism, what happens on --amend, where a
     transaction's commit point is); acceptance criteria keyed to smoke-test step names
     ("step X flips to PASS"); collateral list (README, docs, doctor, harness updates);
     phase ordering with dependencies.
   - Respect the architecture rules in CLAUDE.md: business logic in SDK/core, never in
     CLI handlers; clock injection; typed errors.

6. Leave the smoke harness committed and the results file (last_run.json) refreshed.
```
