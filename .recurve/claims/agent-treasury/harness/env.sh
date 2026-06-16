#!/usr/bin/env bash
# harness/env.sh — paths, sandbox, and the treasury helpers for the fund-of-agents
# suite. Source me.
#
# Mirrors the-agent-with-a-credit-limit/harness/env.sh: Layer 1 (constants +
# helpers) is always safe to source. The suite drives the REAL lean `auths` binary
# (staged at bin/auths by the suite rebuild) over a THROWAWAY --repo / sandboxed
# HOME — it never touches ~/.auths or the user's git config. Every probe builds a
# treasury chain (human -> manager -> {flip,x402,yield,arb} sub-agents), each
# sub-agent handed a per-slice quantitative cap (`calls:<N>`, narrated as a dollar
# slice), and exercises either the proven per-slice machinery (AGT-4) or the
# NET-NEW aggregate-cap surface (Σ slices ≤ parent_cap + reallocate), reading the
# verifier's own verdicts. Nothing here is product code; it is the fixture that
# lets a probe behaviorally test the treasury claims end to end.
#
# UNITS: the enforced unit is the call-count cap (`calls:N`) — the proven AGT-4
# quantitative cap. The fund's $-amounts are narration: a `calls:10` treasury is
# "$10,000", a `calls:4` slice is "$4,000". The property under test — Σ slices ≤
# parent, reallocatable, distinct verdict — is unit-agnostic.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                  # .../claims/agent-treasury
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
AUTHS_SRC="$(cd "$RECURVE_DIR/.." && pwd)"             # the auths platform workspace

# The binary under test: the suite-staged lean default `auths` (content-hash'd
# against target/release/auths). A probe is BROKEN until the suite rebuild stages it.
AUTHS_BIN="${AUTHS_BIN:-$SUITE_DIR/bin/auths}"

# A fixed, obviously-test-only passphrase (12+ chars, 3 classes — meets keychain policy).
SANDBOX_PASSPHRASE="Treasury-Fund-Demo1!"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_DIM="$(printf '\033[2m')"; C_GREEN="$(printf '\033[32m')"
    C_RED="$(printf '\033[31m')"; C_RESET="$(printf '\033[0m')"
else
    C_DIM=""; C_GREEN=""; C_RED=""; C_RESET=""
fi
say()  { printf '%s▸ %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die()  { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
pass() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }

# bin_ready — 0 if the suite-staged binary runs as auths (and jq is present).
bin_ready() {
    [ -x "$AUTHS_BIN" ] || return 1
    "$AUTHS_BIN" --version >/dev/null 2>&1 || return 1
    command -v jq >/dev/null 2>&1 || return 1
    return 0
}

# has_subcommand <args...> — 0 if `auths <args> --help` is recognized (the surface
# exists), non-zero otherwise. Lets a probe tell "the aggregate surface is absent"
# (a RED missing-surface, the gap) apart from "the harness broke" (BROKEN).
has_subcommand() {
    "$AUTHS_BIN" "$@" --help >/dev/null 2>&1
}

# ── The sandbox: a throwaway HOME + registry the treasury is built in ──────────
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
    export GIT_AUTHOR_NAME="Treasury"; export GIT_AUTHOR_EMAIL="treasury@auths.demo"
    export GIT_COMMITTER_NAME="Treasury"; export GIT_COMMITTER_EMAIL="treasury@auths.demo"
    export PATH="$(dirname "$AUTHS_BIN"):$PATH"
    mkdir -p "$HOME" "$ORG_REPO"
}

did_of() { grep -oE 'did:keri:[A-Za-z0-9_-]+' "$1" | head -1; }

# bootstrap_manager <alias> — create the treasury MANAGER root identity (the human
# delegates the manager; here the manager root is the issuer + verifier whose KEL
# anchors the slices and the aggregate cap). Echoes its did:keri.
bootstrap_manager() {
    local alias="${1:-manager}"
    cat > "$LAB_DIR/manager-meta.json" <<EOF
{"name":"Treasury Manager","purpose":"fund-of-agents aggregate cap demo"}
EOF
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id create \
        --metadata-file "$LAB_DIR/manager-meta.json" --local-key-alias "$alias" \
        >"$LAB_DIR/manager-create.out" 2>&1
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id show 2>/dev/null \
        | grep -oE 'did:keri:[A-Za-z0-9_-]+' | head -1
}

# delegate_subagent <label> <delegator-alias> — delegate a sub-agent scoped to act.
# Echoes the sub-agent's did:keri.
delegate_subagent() {
    local label="$1" delegator="$2"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id agent add \
        --label "$label" --key "$delegator" --curve ed25519 --scope sign_commit \
        >"$LAB_DIR/agent-add-$label.out" 2>&1
    grep -oE 'did:keri:[A-Za-z0-9_-]+' "$LAB_DIR/agent-add-$label.out" | head -1
}

# issue_slice <issuer-alias> <agent-did> <calls:N> — issue a sub-agent its per-slice
# quantitative cap credential. Echoes the credential SAID. Exit code + raw output
# survive the command-substitution boundary via stable files:
#   $LAB_DIR/last-issue.code   the issue exit code
#   $LAB_DIR/last-issue.out    the raw JSON/stderr
issue_slice() {
    local issuer="$1" agent="$2" cap="$3"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json credential issue \
        --issuer "$issuer" --to "$agent" --cap "$cap" --cap sign_commit \
        >"$LAB_DIR/last-issue.out" 2>&1
    printf '%s' "$?" > "$LAB_DIR/last-issue.code"
    jq -r '.data.credential_said // empty' "$LAB_DIR/last-issue.out" 2>/dev/null
}
issue_rc() { cat "$LAB_DIR/last-issue.code" 2>/dev/null || echo 127; }

# write_observation <file> <said> <calls_used>
write_observation() {
    printf '{"said":"%s","calls_used":%s}' "$2" "$3" > "$1"
}

# verify_status <issuer-alias> <said> [observation-file] — per-slice verify against
# the manager registry; echoes the machine status (valid, cap_exceeded,
# usage_counter_rolled_back, …). This is the PROVEN AGT-4 surface.
verify_status() {
    local issuer="$1" said="$2" obs="${3:-}"
    local args=(--repo "$ORG_REPO" --json credential verify --issuer "$issuer" "$said")
    [ -n "$obs" ] && args+=(--usage-counter "$obs")
    "$AUTHS_BIN" "${args[@]}" 2>/dev/null | jq -r '.data.status // empty' 2>/dev/null
}

# ── NET-NEW surface (AGENT-TREASURY-1): the aggregate cap + reallocation ───────
# These drive the to-be-built engine primitive. Until it lands they fail closed
# (empty status / nonzero), which a probe reads as a RED missing-surface — the gap.

# treasury_open <manager-alias> <cap> — establish the aggregate cap (calls:N or N).
# Echoes the machine status (opened).
treasury_open() {
    local mgr="$1" cap="$2"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury open --manager "$mgr" --cap "$cap" \
        2>/dev/null | jq -r '.data.status // empty' 2>/dev/null
}

# treasury_allot <manager-alias> <agent-did> <amount> — commit a slice. Echoes the
# machine status (allotted | aggregate_cap_exceeded).
treasury_allot() {
    local mgr="$1" to="$2" amt="$3"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury allot --manager "$mgr" --to "$to" --amount "$amt" \
        2>/dev/null | jq -r '.data.status // empty' 2>/dev/null
}

# treasury_slice <manager-alias> <agent-did> — echo a sub-agent's current slice amount.
treasury_slice() {
    local mgr="$1" did="$2"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury status --manager "$mgr" 2>/dev/null \
        | jq -r --arg d "$did" '.data.slices[]? | select(.agent_did==$d) | .amount' 2>/dev/null
}

# reallocate <manager-alias> <from-did> <to-did> <amount> — move <amount> of slice
# budget from one sub-agent to another. Echoes the machine status
# (reallocated | aggregate_cap_exceeded). Writes exit code to $LAB_DIR/realloc.code.
reallocate() {
    local mgr="$1" from="$2" to="$3" amt="$4"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury reallocate \
        --manager "$mgr" --from "$from" --to "$to" --amount "$amt" \
        >"$LAB_DIR/realloc.out" 2>&1
    printf '%s' "$?" > "$LAB_DIR/realloc.code"
    jq -r '.data.status // empty' "$LAB_DIR/realloc.out" 2>/dev/null
}
realloc_rc() { cat "$LAB_DIR/realloc.code" 2>/dev/null || echo 127; }

# treasury_status <manager-alias> — echo the aggregate invariant status
# (valid | aggregate_cap_exceeded) from the manager's KEL: Σ live slices ≤ parent_cap.
treasury_status() {
    local mgr="$1"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury status --manager "$mgr" \
        2>/dev/null | jq -r '.data.status // empty' 2>/dev/null
}

# treasury_field <manager-alias> <jq-path> — read one field of `treasury status`
# (e.g. .data.parent_cap, .data.committed, .data.free_pool).
treasury_field() {
    local mgr="$1" path="$2"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json treasury status --manager "$mgr" \
        2>/dev/null | jq -r "$path // empty" 2>/dev/null
}

# revoke_subagent <manager-alias> <agent-did> — revoke a sub-agent (OPS-1). Echoes
# exit code to $LAB_DIR/revoke.code; status via stdout if surfaced.
revoke_subagent() {
    local mgr="$1" agent="$2"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id agent revoke \
        --key "$mgr" --agent "$agent" >"$LAB_DIR/revoke.out" 2>&1
    printf '%s' "$?" > "$LAB_DIR/revoke.code"
    jq -r '.data.status // empty' "$LAB_DIR/revoke.out" 2>/dev/null
}
revoke_rc() { cat "$LAB_DIR/revoke.code" 2>/dev/null || echo 127; }
