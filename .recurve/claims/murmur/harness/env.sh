#!/usr/bin/env bash
# harness/env.sh — paths, sandbox, and the relay-driving helpers for the Murmur
# messenger suite. Source me.
#
# Layout mirrors the auths-mcp suite's harness/env.sh: Layer 1 (constants +
# helpers) is always safe to source. The suite drives the REAL `murmur-relay`
# binary (staged at bin/murmur-relay by the suite rebuild) and the murmur-core
# seam — both honest skeletons today, so every probe is RED. It never touches
# ~/.auths or the user's git config. Nothing here is product code; it is the
# fixture that lets a probe behaviorally test a claim end to end.
#
# GREENFIELD: the engine is a skeleton today (seal/open/trust/relay all fail
# closed "feature absent"), so every probe is RED. That is correct — the burndown
# builds it green.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                  # .../claims/murmur
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
AUTHS_SRC="$(cd "$RECURVE_DIR/.." && pwd)"             # the auths platform workspace

# The binary under test: the suite-staged relay (content-hash'd against
# target/release/murmur-relay). A relay-reading probe is BROKEN until the suite
# rebuild stages it.
RELAY_BIN="${RELAY_BIN:-$SUITE_DIR/bin/murmur-relay}"

# The native app repo (the sculpt tree) — where the iOS + macOS shells live, for
# probes that assert app-side facts (APP-1). Resolved beside the auths repo.
MURMUR_APP="${MURMUR_APP:-$(cd "$AUTHS_SRC/../murmur" 2>/dev/null && pwd || true)}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_DIM="$(printf '\033[2m')"; C_GREEN="$(printf '\033[32m')"
    C_RED="$(printf '\033[31m')"; C_RESET="$(printf '\033[0m')"
else
    C_DIM=""; C_GREEN=""; C_RED=""; C_RESET=""
fi
say()  { printf '%s▸ %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die()  { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
pass() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }

# relay_ready — 0 if the suite-staged relay runs and reports its version;
# non-zero otherwise. --version is the liveness check (it exits 0 in the
# skeleton); `serve` fails closed (the wire is unbuilt), which is the point.
relay_ready() {
    [ -x "$RELAY_BIN" ] || return 1
    "$RELAY_BIN" --version >/dev/null 2>&1 || return 1
    return 0
}

# relay_version — echo the staged relay's reported version line.
relay_version() {
    "$RELAY_BIN" --version 2>/dev/null
}

# relay_serve — drive `murmur-relay serve` and echo its combined output; returns
# the exit code so a fail-closed (RED) relay is observable to the caller. In the
# skeleton this fails closed with "store-and-forward wire not built yet".
relay_serve() {
    "$RELAY_BIN" serve 2>&1
}

# ── The sandbox: a throwaway HOME the relay/engine drive in ───────────────────
# Every value is set explicitly so a probe can never reach the user's real
# ~/.auths, ~/.gitconfig, or global git.
sandbox_env() {
    local lab="$1"
    export LAB_DIR="$lab"
    export HOME="$lab/home"
    export AUTHS_HOME="$lab/registry"
    export AUTHS_REPO="$lab/registry"
    export GIT_CONFIG_GLOBAL="$lab/home/.gitconfig"
    export GIT_CONFIG_NOSYSTEM=1
    mkdir -p "$HOME" "$AUTHS_HOME"
}
