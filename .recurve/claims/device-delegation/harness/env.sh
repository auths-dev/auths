#!/usr/bin/env bash
# harness/env.sh — paths + sandbox for the device-delegation suite. Source me.
#
# The suite drives the REAL lean `auths` binary (staged at bin/auths by the suite
# rebuild, content-hashed against target/release/auths) over a THROWAWAY --repo /
# sandboxed HOME — it never touches ~/.auths or the user's git config. Probes
# behaviorally test that device #0 is a delegated identifier distinct from the
# root, that a commit signs+verifies under it, and that it is independently
# revocable — end to end against the CLI.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                  # .../claims/device-delegation
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
AUTHS_SRC="$(cd "$RECURVE_DIR/.." && pwd)"             # the auths platform workspace

# The binary under test: the suite-staged `auths` (content-hash'd against
# target/release/auths). A probe is BROKEN until the suite rebuild stages it;
# falls back to target/release/auths for a direct run.
AUTHS_BIN="${AUTHS_BIN:-$SUITE_DIR/bin/auths}"
[ -x "$AUTHS_BIN" ] || AUTHS_BIN="$AUTHS_SRC/target/release/auths"
export AUTHS_BIN
