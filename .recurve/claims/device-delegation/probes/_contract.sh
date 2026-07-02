#!/usr/bin/env bash
# The probe contract (frozen — see recurve schema/gap.schema.json):
#   exit 0  GREEN   the desired behavior is present
#   exit 1  RED     the desired behavior is absent (print ONE detail line a
#                   builder can treat as the spec: "ours=X oracle=Y")
#   exit 2  BROKEN  could not measure (missing binary/fixture/build)
#   anything else (crash, timeout) coerces to BROKEN — never to a verdict.
#
# Traps: when $TRAP_FIXTURE is set, the runner is feeding you a KNOWN-BAD
# counterexample; you MUST exit 1. A probe never seen RED is not yet evidence.
#
# Probes are hermetic: build nothing, finish in seconds against the already-built
# release binary ($AUTHS_BIN or target/release/auths).
green() { echo "${1:-behavior present}"; exit 0; }
red()   { echo "${1:?print the one RED line of truth}"; exit 1; }
broken(){ echo "${1:-could not measure}"; exit 2; }

# Resolve the auths repo root (probes live at .recurve/claims/device-delegation/probes/).
DD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
AUTHS_BIN="${AUTHS_BIN:-$DD_ROOT/target/release/auths}"

# Spin up a throwaway developer identity in an isolated HOME. Exports the keychain
# env into the CURRENT shell (call directly, NOT in $(...), or the exports are lost to
# a subshell) and sets $AUTHS_HOME. Returns non-zero (→ caller BROKEN) if init fails.
dd_fresh_identity() {
  [ -x "$AUTHS_BIN" ] || return 2
  local home; home="$(mktemp -d)"
  export HOME="$home" AUTHS_HOME="$home/.auths" \
    AUTHS_KEYCHAIN_BACKEND=file AUTHS_KEYCHAIN_FILE="$home/keys.enc" \
    AUTHS_PASSPHRASE='Recurve-DeviceDelegation-Probe-2026!' GIT_CONFIG_NOSYSTEM=1
  mkdir -p "$AUTHS_HOME"
  "$AUTHS_BIN" init --non-interactive --profile developer --repo "$AUTHS_HOME" >/dev/null 2>&1 || return 2
}

# jq-free JSON field read via python3. auths --json wraps payloads in
# {success,command,data:{...}}, so look inside `.data` first, then top level.
dd_json_field() {
  python3 -c '
import sys, json
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
if isinstance(d, dict) and isinstance(d.get("data"), dict): d = d["data"]
print(d.get(sys.argv[1], "") if isinstance(d, dict) else "")' "$1"
}
