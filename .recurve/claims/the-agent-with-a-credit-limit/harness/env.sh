#!/usr/bin/env bash
# harness/env.sh — paths, sandbox, and the cap-credential helpers for the
# quantitative-cap suite. Source me.
#
# Layout mirrors the-intern-that-couldnt/harness/env.sh: Layer 1 (constants +
# helpers) is always safe to source. The suite drives the REAL lean `auths`
# binary (staged at bin/auths by the suite rebuild) over a THROWAWAY --repo /
# sandboxed HOME — it never touches ~/.auths or the user's git config. Every
# probe builds a finance-org -> procurement-agent chain, issues the agent a
# credential carrying a quantitative cap (`calls:<N>`), then presents observed
# usage counts and reads `credential verify`'s verdict. Nothing here is product
# code; it is the fixture that lets a probe behaviorally test the cap claim end
# to end against the verifier's own monotonic usage ledger.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                  # .../claims/the-agent-with-a-credit-limit
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
AUTHS_SRC="$(cd "$RECURVE_DIR/.." && pwd)"             # the auths platform workspace

# The binary under test: the suite-staged lean default `auths` (content-hash'd
# against target/release/auths). A probe is BROKEN until the suite rebuild
# stages it.
AUTHS_BIN="${AUTHS_BIN:-$SUITE_DIR/bin/auths}"

# A fixed, obviously-test-only passphrase (12+ chars, 3 character classes — meets
# keychain policy). Not a secret: a local test fixture.
SANDBOX_PASSPHRASE="Credit-L1mit-Demo!"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_DIM="$(printf '\033[2m')"; C_GREEN="$(printf '\033[32m')"
    C_RED="$(printf '\033[31m')"; C_RESET="$(printf '\033[0m')"
else
    C_DIM=""; C_GREEN=""; C_RED=""; C_RESET=""
fi
say()  { printf '%s▸ %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die()  { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
pass() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }

# bin_ready — 0 if the suite-staged binary runs as auths; non-zero otherwise.
bin_ready() {
    [ -x "$AUTHS_BIN" ] || return 1
    "$AUTHS_BIN" --version >/dev/null 2>&1 || return 1
    command -v jq >/dev/null 2>&1 || return 1
    return 0
}

# ── The sandbox: a throwaway HOME + registry the chain is built in ────────────
# Every value is set explicitly so the probe can never reach the user's real
# ~/.auths, ~/.gitconfig, or global git. Call `sandbox_env <root>` to point the
# auths CLI + git at a throwaway dir. The verifier's monotonic usage ledger lives
# under the SAME registry (usage-ledger/<said>.json), so each probe's ledger is
# its own throwaway too — re-running a probe is always pristine.
sandbox_env() {
    local lab="$1"
    export LAB_DIR="$lab"
    export ORG_REPO="$lab/registry"
    export HOME="$lab/home"
    export AUTHS_HOME="$ORG_REPO"
    export AUTHS_REPO="$ORG_REPO"
    export AUTHS_KEYCHAIN_BACKEND="file"
    export AUTHS_KEYCHAIN_FILE="$ORG_REPO/keys.enc"
    export AUTHS_PASSPHRASE="$SANDBOX_PASSPHRASE"
    export GIT_CONFIG_GLOBAL="$lab/home/.gitconfig"
    export GIT_CONFIG_NOSYSTEM=1
    export GIT_AUTHOR_NAME="Finance Org"; export GIT_AUTHOR_EMAIL="finance@auths.demo"
    export GIT_COMMITTER_NAME="Finance Org"; export GIT_COMMITTER_EMAIL="finance@auths.demo"
    export PATH="$(dirname "$AUTHS_BIN"):$PATH"
    mkdir -p "$HOME" "$ORG_REPO"
}

# ── Chain construction (finance-org -> procurement-agent), all real CLI calls ──

# bootstrap_org <key-alias> — create the finance org root identity. Echoes its
# did:keri. The org is the credential ISSUER and the VERIFIER (its registry holds
# the monotonic usage ledger).
bootstrap_org() {
    local alias="${1:-finance}"
    cat > "$LAB_DIR/org-meta.json" <<EOF
{"name":"Finance Org","purpose":"quantitative cap demo"}
EOF
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id create \
        --metadata-file "$LAB_DIR/org-meta.json" --local-key-alias "$alias" \
        >"$LAB_DIR/org-create.out" 2>&1
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id show 2>/dev/null \
        | grep -oE 'did:keri:[A-Za-z0-9_-]+' | head -1
}

# delegate_agent <label> <delegator-alias> <scope...> — delegate a procurement
# agent scoped to the given capabilities. Echoes the agent's did:keri.
delegate_agent() {
    local label="$1" delegator="$2"; shift 2
    local scope_args=()
    local cap
    for cap in "$@"; do scope_args+=(--scope "$cap"); done
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id agent add \
        --label "$label" --key "$delegator" --curve ed25519 "${scope_args[@]}" \
        >"$LAB_DIR/agent-add-$label.out" 2>&1
    grep -oE 'did:keri:[A-Za-z0-9_-]+' "$LAB_DIR/agent-add-$label.out" | head -1
}

# issue_capped <issuer-alias> <agent-did> <cap...> — issue a credential carrying
# the given capabilities (e.g. `calls:3 sign_commit`). Echoes the credential SAID.
# Because it is meant to be called in a command substitution, the CLI exit code
# and raw output cannot ride back on shell variables (a subshell cannot export to
# its parent); instead it writes them to STABLE files the caller reads directly:
#   $LAB_DIR/last-issue.code   the `credential issue` exit code
#   $LAB_DIR/last-issue.out    the raw JSON/stderr of that issuance
# A probe reads ISSUE_RC via `issue_rc` and ISSUE_OUT via "$LAB_DIR/last-issue.out".
issue_capped() {
    local issuer="$1" agent="$2"; shift 2
    local cap_args=() cap
    for cap in "$@"; do cap_args+=(--cap "$cap"); done
    "$AUTHS_BIN" --repo "$ORG_REPO" --json credential issue \
        --issuer "$issuer" --to "$agent" "${cap_args[@]}" \
        >"$LAB_DIR/last-issue.out" 2>&1
    printf '%s' "$?" > "$LAB_DIR/last-issue.code"
    jq -r '.data.credential_said // empty' "$LAB_DIR/last-issue.out" 2>/dev/null
}

# issue_rc — the exit code of the most recent issue_capped call (read from the
# file issue_capped wrote, so it survives the command-substitution boundary).
issue_rc() { cat "$LAB_DIR/last-issue.code" 2>/dev/null || echo 127; }

# write_observation <file> <said> <calls_used> — write the untrusted observed
# usage count the verifier checks against its monotonic ledger.
write_observation() {
    local file="$1" said="$2" used="$3"
    printf '{"said":"%s","calls_used":%s}' "$said" "$used" > "$file"
}

# verify_status <issuer-alias> <said> [observation-file] — run `credential
# verify` against the org registry (resolves the issuer KEL/TEL + enforces the
# usage cap, when an observation is given, against the registry's monotonic
# usage ledger) and echo the machine-readable status code (valid, cap_exceeded,
# usage_counter_rolled_back, schema_invalid, …).
verify_status() {
    local issuer="$1" said="$2" obs="${3:-}"
    local args=(--repo "$ORG_REPO" --json credential verify --issuer "$issuer" "$said")
    [ -n "$obs" ] && args+=(--usage-counter "$obs")
    "$AUTHS_BIN" "${args[@]}" 2>/dev/null \
        | jq -r '.data.status // empty' 2>/dev/null
}

# cred_caps <issuer-alias> <said> — echo the credential's stored capability claim
# (comma-joined as the verifier reads it). Lets a probe inspect what was actually
# persisted for a given issuance (e.g. to show a malformed cap was stored opaque).
cred_caps() {
    local issuer="$1" said="$2"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json credential list --issuer "$issuer" 2>/dev/null \
        | jq -r --arg s "$said" \
            '.data.credentials[]? | select(.credential_said==$s) | .capabilities | join(",")' \
        2>/dev/null
}
