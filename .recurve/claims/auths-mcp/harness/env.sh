#!/usr/bin/env bash
# harness/env.sh — paths, sandbox, and the gateway-driving helpers for the
# bounded-agent MCP gateway suite. Source me.
#
# Layout mirrors the-intern-that-couldnt/harness/env.sh: Layer 1 (constants +
# helpers) is always safe to source. The suite drives the REAL `auths-mcp-gateway`
# binary (staged at bin/auths-mcp-gateway by the suite rebuild) in REPLAY mode over
# a frozen transcript and a THROWAWAY sandbox — it never touches ~/.auths or the
# user's git config. Every probe drives the gateway to a verdict for one FR's
# accept + adversarial path and reads it. Nothing here is product code; it is the
# fixture that lets a probe behaviorally test a containment claim end to end.
#
# GREENFIELD: the gateway is a stub today, so every probe is RED. That is correct —
# the burndown builds it green.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                  # .../claims/auths-mcp
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
AUTHS_SRC="$(cd "$RECURVE_DIR/.." && pwd)"             # the auths platform workspace

# The binary under test: the suite-staged gateway (content-hash'd against
# target/release/auths-mcp-gateway). A probe is BROKEN until the suite rebuild
# stages it. The companion lean `auths` CLI (for minting delegations / verifying
# receipts) sits beside the release binary.
GATEWAY_BIN="${GATEWAY_BIN:-$SUITE_DIR/bin/auths-mcp-gateway}"
# The gateway shells the proven `auths` CLI + `auths-sign` to build the throwaway
# delegation chain and sign each per-call proof (the security boundary — the verify —
# is native in-process). Export them so the gateway subprocess inherits them.
AUTHS_BIN="${AUTHS_BIN:-$AUTHS_SRC/target/release/auths}"
AUTHS_SIGN="${AUTHS_SIGN:-$AUTHS_SRC/target/release/auths-sign}"
export AUTHS_BIN AUTHS_SIGN

# A fixed, obviously-test-only passphrase (12+ chars, 3 character classes).
SANDBOX_PASSPHRASE="Mcp-Gat3way-Bound!"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_DIM="$(printf '\033[2m')"; C_GREEN="$(printf '\033[32m')"
    C_RED="$(printf '\033[31m')"; C_RESET="$(printf '\033[0m')"
else
    C_DIM=""; C_GREEN=""; C_RED=""; C_RESET=""
fi
say()  { printf '%s▸ %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die()  { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
pass() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }

# bin_ready — 0 if the suite-staged gateway runs as the gateway; non-zero otherwise.
bin_ready() {
    [ -x "$GATEWAY_BIN" ] || return 1
    "$GATEWAY_BIN" --version >/dev/null 2>&1 || return 1
    return 0
}

# ── The sandbox: a throwaway HOME + registry the chain is built in ────────────
# Every value is set explicitly so a probe can never reach the user's real
# ~/.auths, ~/.gitconfig, or global git.
sandbox_env() {
    local lab="$1"
    export LAB_DIR="$lab"
    export PARENT_REPO="$lab/registry"
    export HOME="$lab/home"
    export AUTHS_HOME="$PARENT_REPO"
    export AUTHS_REPO="$PARENT_REPO"
    export AUTHS_KEYCHAIN_BACKEND="file"
    export AUTHS_KEYCHAIN_FILE="$PARENT_REPO/keys.enc"
    export AUTHS_PASSPHRASE="$SANDBOX_PASSPHRASE"
    export GIT_CONFIG_GLOBAL="$lab/home/.gitconfig"
    export GIT_CONFIG_NOSYSTEM=1
    export GIT_AUTHOR_NAME="Parent Root"; export GIT_AUTHOR_EMAIL="root@auths.demo"
    export GIT_COMMITTER_NAME="Parent Root"; export GIT_COMMITTER_EMAIL="root@auths.demo"
    export PATH="$(dirname "$GATEWAY_BIN"):$PATH"
    mkdir -p "$HOME" "$PARENT_REPO"
}

# ── Driving the gateway in replay mode (the hermetic probe entrypoint) ─────────
# A probe writes a frozen transcript of a tools/call sequence under the sandbox,
# drives the gateway over it, and reads the per-call verdict.

# transcript_path <fixture-name> — the suite-frozen replay transcript for a probe.
# Probes drive the gateway from a committed transcript so verdicts are byte-stable
# with no model/network (PRD §7). The named fixtures live under each probe's dir.
transcript_path() {
    local name="$1"
    printf '%s/probes/transcripts/%s.json' "$SUITE_DIR" "$name"
}

# gateway_replay <transcript> — drive the gateway in replay mode over the frozen
# transcript and echo its stdout (the per-call verdict stream). Returns the exit
# code so a fail-closed (RED) gateway is observable to the caller.
gateway_replay() {
    local transcript="$1"
    "$GATEWAY_BIN" replay --transcript "$transcript" 2>&1
}

# verdict_for <transcript> <call-index> — drive the gateway and extract the
# machine-readable verdict for the Nth call (0-based). Echoes e.g. allowed,
# outside-agent-scope, usage-cap-exceeded, revoked. Empty if the gateway produced
# no verdict (the greenfield RED state).
verdict_for() {
    local transcript="$1" idx="$2"
    gateway_replay "$transcript" 2>/dev/null \
        | grep -oE '(allowed|outside-agent-scope|usage-cap-exceeded|agent-expired|revoked)' \
        | sed -n "$((idx + 1))p"
}
