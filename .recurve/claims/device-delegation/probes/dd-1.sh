#!/usr/bin/env bash
# DD-1: after `auths init`, identity_did != device_did (the primary device is a
# delegated identifier with its own AID, not the root).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_contract.sh"

if [ -n "${TRAP_FIXTURE:-}" ]; then
  # Known-bad: the collapse itself (equal DIDs) — must RED.
  id="$(cat "$TRAP_FIXTURE/identity_did" 2>/dev/null)"
  dev="$(cat "$TRAP_FIXTURE/device_did" 2>/dev/null)"
else
  dd_fresh_identity || broken "auths init failed or binary missing ($AUTHS_BIN)"
  out="$("$AUTHS_BIN" whoami --json --repo "$AUTHS_HOME" 2>/dev/null)" || broken "whoami failed"
  id="$(printf '%s' "$out" | dd_json_field identity_did)"
  dev="$(printf '%s' "$out" | dd_json_field device_did)"
fi

[ -n "$id" ] && [ -n "$dev" ] || broken "could not read identity_did/device_did from whoami --json"
[ "$id" != "$dev" ] || red "ours=identity_did==device_did ($id) oracle=distinct (device #0 must be a delegated AID)"
green "identity_did ($id) != device_did ($dev)"
