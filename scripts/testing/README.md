# Workspace test runner

Small shim around `cargo nextest` that writes the full run to a temp file so you
can `grep` it precisely instead of piping megabytes of compile output through
chat. Intended for both humans and LLM agents.

## Why not just `cargo nextest` directly?

- A full `--workspace --all-features` run produces thousands of lines of
  compile + test output. Streaming that into a transcript is wasteful and
  makes it easy to miss a single failing test among a wall of green.
- A second cargo process can hold the `target/` lock and make a fresh run
  block silently. The runner detects that and warns on first sighting.
- A stable, timestamped log path plus a `/tmp/auths-tests.log` "latest"
  symlink lets a follow-up agent grep results without having to know which
  run produced them.

## Usage

```bash
# Full workspace, all features
python3 scripts/testing/run_nextest.py

# One crate only
python3 scripts/testing/run_nextest.py -p auths-keri

# Filter to specific tests (nextest expression)
python3 scripts/testing/run_nextest.py -p auths-keri --extra '-E test(replay_)'

# Mirror output to stdout in addition to the log
python3 scripts/testing/run_nextest.py --tee
```

The script prints the log path on exit and refreshes
`/tmp/auths-tests.log` as a symlink to the most recent run.

## Grep cheat-sheet (for LLMs and humans)

The runner exits 0 regardless of test outcome by default — the caller is
expected to grep the log. One combined expression catches every failure
shape you care about:

```bash
grep -E '^error\[|^error:|^\s*FAIL \[|^\s*TIMEOUT \[|^failures:|Summary \[' /tmp/auths-tests.log
```

Breakdown:

| Pattern | What it catches |
|---|---|
| `^error\[E\d+\]:` | rustc compile error with a code (e.g. `error[E0308]`) |
| `^error:` | cargo / clippy errors without a code |
| `^\s*FAIL \[` | a single failed test (`        FAIL [  0.004s] crate::test`) |
| `^\s*TIMEOUT \[` | a hung test nextest killed |
| `^\s*LEAK \[` | nextest leak-sanitizer report |
| `^failures:` | start of nextest's "failures:" block (one per failed test) |
| `Summary \[` | final summary line (counts passed / failed / skipped) |
| `thread '.*' panicked at` | Rust panic backtrace anchor |
| `Canceling due to test failure` | run canceled before completion (with fail-fast) |

### Typical incident workflow

1. Run the script:
   ```bash
   python3 scripts/testing/run_nextest.py
   ```
2. Find compile errors first — they mask test failures:
   ```bash
   grep -nE '^error\[|^error:' /tmp/auths-tests.log | head -40
   ```
3. If none, find failed tests:
   ```bash
   grep -nE '^\s*FAIL \[|^\s*TIMEOUT \[' /tmp/auths-tests.log
   ```
4. For each failure, pull the surrounding assertion:
   ```bash
   grep -nA 20 '^failures:' /tmp/auths-tests.log
   ```
5. Check the final count:
   ```bash
   grep 'Summary \[' /tmp/auths-tests.log
   ```

### Multi-line context

Some rustc errors span many lines (`error[E0308]: ... = note: ...`). Widen
the context window when inspecting:

```bash
grep -nE -A 12 '^error\[' /tmp/auths-tests.log
```

### When the run was interrupted

If the Summary line is absent, the run either is still in progress, was
killed (OOM, ctrl-C), or hit a compile error that prevented any tests from
executing. In that order:

```bash
# still running?
pgrep -f 'cargo-nextest' && echo 'still running'

# killed?
grep -E 'SIGKILL|Killed' /tmp/auths-tests.log

# compile-only failure? (no tests ever ran)
grep -c '^\s*FAIL \[' /tmp/auths-tests.log   # → 0
grep -c '^error\[\|^error:' /tmp/auths-tests.log   # → > 0
```

## Options

| Flag | Default | Purpose |
|---|---|---|
| `-p CRATE` / `--package` | none | Test a single crate instead of the full workspace |
| `--no-all-features` | off | Drop `--all-features` — useful when two features are mutually exclusive |
| `--extra 'STR'` | "" | Free-form args appended to the nextest invocation |
| `--tee` | off | Mirror output to stdout in addition to the log file |
| `--fail-on-error` | off | Exit non-zero when tests fail (default is exit 0 so the caller can grep) |

## Files

```
scripts/testing/
  README.md         this file
  run_nextest.py    the runner
```

Log files land in `/tmp/` with names `auths-tests-<tag>-<timestamp>.log`,
plus a `/tmp/auths-tests.log` symlink to the most recent run.
