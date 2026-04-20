#!/usr/bin/env python3
"""Run `cargo nextest` and stream output to a predictable temp file.

Why: the workspace is large enough that a full test run produces megabytes
of output. Keeping it in a file rather than a chat transcript lets the
caller (human or LLM) `grep` precisely for compile errors, failed tests,
or summary stats without re-running anything.

Usage:

    python3 scripts/testing/run_nextest.py                   # full workspace
    python3 scripts/testing/run_nextest.py -p auths-keri     # single crate
    python3 scripts/testing/run_nextest.py --no-all-features # default features
    python3 scripts/testing/run_nextest.py --extra 'cases::replay_rejected::'

The script prints the log path on exit. See `README.md` in this
directory for the grep recipes.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = Path("/tmp")
LATEST_SYMLINK = LOG_DIR / "auths-tests.log"


def build_command(args: argparse.Namespace) -> list[str]:
    cmd = ["cargo", "nextest", "run", "--no-fail-fast"]
    if args.package:
        cmd += ["-p", args.package]
    else:
        cmd += ["--workspace"]
    if not args.no_all_features:
        cmd += ["--all-features"]
    if args.extra:
        # Accept a free-form filter string passed through to nextest.
        cmd += shlex.split(args.extra)
    return cmd


def detect_lock_contention(line: str) -> bool:
    return "Blocking waiting for file lock" in line


def run(args: argparse.Namespace) -> int:
    cmd = build_command(args)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    tag = args.package or "workspace"
    log_path = LOG_DIR / f"auths-tests-{tag}-{timestamp}.log"

    print(f"[run_nextest] cwd: {REPO_ROOT}")
    print(f"[run_nextest] cmd: {' '.join(cmd)}")
    print(f"[run_nextest] log: {log_path}")
    print()

    start = time.time()
    with log_path.open("w") as f:
        proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        lock_warned = False
        for line in proc.stdout:
            f.write(line)
            f.flush()
            if not lock_warned and detect_lock_contention(line):
                print(
                    "[run_nextest] WARN: target dir is locked by another cargo "
                    "invocation. Waiting for it to release…",
                    file=sys.stderr,
                )
                lock_warned = True
            if args.tee:
                sys.stdout.write(line)
                sys.stdout.flush()
        rc = proc.wait()

    elapsed = time.time() - start

    # Refresh the "latest" symlink. The caller who doesn't know the
    # timestamped name can always `grep /tmp/auths-tests.log`.
    try:
        if LATEST_SYMLINK.exists() or LATEST_SYMLINK.is_symlink():
            LATEST_SYMLINK.unlink()
        LATEST_SYMLINK.symlink_to(log_path)
    except OSError as e:
        print(f"[run_nextest] could not update {LATEST_SYMLINK}: {e}", file=sys.stderr)

    print()
    print(f"[run_nextest] exit code: {rc}")
    print(f"[run_nextest] elapsed:   {elapsed:.1f}s")
    print(f"[run_nextest] log:       {log_path}")
    print(f"[run_nextest] latest:    {LATEST_SYMLINK}")
    print()
    # Pre-canned summary hint so the caller doesn't have to remember the patterns.
    print("[run_nextest] next steps:")
    print(f"  grep -E '^error\\[|^error:|^\\s*FAIL \\[|^\\s*TIMEOUT \\[|^failures:|Summary \\[' {LATEST_SYMLINK}")
    print(f"  # see scripts/testing/README.md for the full grep cheat-sheet")
    return 0 if args.success_regardless else rc


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "-p", "--package",
        help="Cargo package to test (e.g. auths-keri). Defaults to --workspace.",
    )
    p.add_argument(
        "--no-all-features",
        action="store_true",
        help="Skip --all-features. Useful when a mutually-exclusive feature "
             "combination rejects the blanket.",
    )
    p.add_argument(
        "--extra",
        default="",
        help="Extra args appended to the nextest invocation "
             "(e.g. --extra '-E test(my_pattern)').",
    )
    p.add_argument(
        "--tee",
        action="store_true",
        help="Mirror nextest output to stdout in addition to the log file.",
    )
    p.add_argument(
        "--fail-on-error",
        dest="success_regardless",
        action="store_false",
        default=True,
        help="Propagate nextest's non-zero exit. Default is to exit 0 so the "
             "caller can grep the log regardless.",
    )
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
