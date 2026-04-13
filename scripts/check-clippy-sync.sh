#!/usr/bin/env bash
# check-clippy-sync.sh — verify fn-114 curve deny-list is in sync across all 7 clippy.toml files.
#
# Clippy does NOT merge per-crate clippy.toml with the workspace config — each crate
# with its own clippy.toml replaces the workspace rules entirely. This script ensures
# that the curve-agnostic deny-list lines (all lines matching 'fn-114:') are identical
# across the workspace root and all 6 per-crate clippy.toml files that currently exist.
#
# Run in CI (before fn-114.40 removes the deny-list block) to catch accidental drift
# where one file is updated without the others.
#
# Exit 0: in sync.  Exit 1: drift detected; prints diff.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FILES=(
  "clippy.toml"
  "crates/auths-crypto/clippy.toml"
  "crates/auths-core/clippy.toml"
  "crates/auths-id/clippy.toml"
  "crates/auths-sdk/clippy.toml"
  "crates/auths-cli/clippy.toml"
  "crates/auths-transparency/clippy.toml"
)

for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: missing clippy.toml: $f" >&2
    exit 1
  fi
done

extract_curve_entries() {
  grep 'fn-114:' "$1" | sort
}

REFERENCE_FILE="${FILES[0]}"
REFERENCE=$(extract_curve_entries "$REFERENCE_FILE")

STATUS=0
for f in "${FILES[@]:1}"; do
  CURRENT=$(extract_curve_entries "$f")
  if [[ "$CURRENT" != "$REFERENCE" ]]; then
    echo "DRIFT: $f differs from $REFERENCE_FILE"
    diff <(echo "$REFERENCE") <(echo "$CURRENT") || true
    STATUS=1
  fi
done

if [[ $STATUS -eq 0 ]]; then
  EXPECTED=10
  ACTUAL=$(echo "$REFERENCE" | wc -l | tr -d ' ')
  if [[ "$ACTUAL" -ne "$EXPECTED" ]]; then
    echo "WARNING: expected $EXPECTED fn-114 entries, found $ACTUAL in $REFERENCE_FILE"
    echo "If fn-114.40 has removed entries, update EXPECTED in this script."
    STATUS=1
  else
    echo "OK: all ${#FILES[@]} clippy.toml files carry identical $ACTUAL fn-114 entries."
  fi
fi

exit $STATUS
