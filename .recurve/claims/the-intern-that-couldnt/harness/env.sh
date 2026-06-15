#!/usr/bin/env bash
# harness/env.sh — paths, sandbox, and the chain-building helpers for the
# over-permissioned sub-agent suite. Source me.
#
# Layout mirrors network/harness/env.sh: Layer 1 (constants + helpers) is always
# safe to source. The suite drives the REAL lean `auths` binary (staged at
# bin/auths by the suite rebuild) over a THROWAWAY --repo / sandboxed HOME — it
# never touches ~/.auths or the user's git config. Every probe builds an
# org -> worker-agent delegation chain, has the worker sign a commit, and reads
# `auths verify`'s verdict. Nothing here is product code; it is the fixture that
# lets a probe behaviorally test a containment claim end to end.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                  # .../claims/the-intern-that-couldnt
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
AUTHS_SRC="$(cd "$RECURVE_DIR/.." && pwd)"             # the auths platform workspace

# The binary under test: the suite-staged lean default `auths` (content-hash'd
# against target/release/auths). A probe is BROKEN until the suite rebuild
# stages it. The companion `auths-sign` (git's SSH signing program) sits beside
# the release binary; the worker signs through it.
AUTHS_BIN="${AUTHS_BIN:-$SUITE_DIR/bin/auths}"
AUTHS_SIGN="${AUTHS_SIGN:-$AUTHS_SRC/target/release/auths-sign}"

# A fixed, obviously-test-only passphrase (12+ chars, 3 character classes — meets
# keychain policy). Not a secret: a local test fixture.
SANDBOX_PASSPHRASE="Intern-Th4t-Couldnt!"

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
    [ -x "$AUTHS_SIGN" ] || return 1
    return 0
}

# ── The sandbox: a throwaway HOME + registry the chain is built in ────────────
# Every value is set explicitly so the probe can never reach the user's real
# ~/.auths, ~/.gitconfig, or global git. Call `sandbox_env <root>` to point the
# auths CLI + git at a throwaway dir; call `worker_env <root>` to flip the same
# sandbox onto the worker's delegate-machine registry + keychain.

# sandbox_env <lab-dir> — org-side env: HOME, registry, keychain, git identity
# all under <lab-dir>. The auths CLI reads its registry from AUTHS_REPO/AUTHS_HOME
# (co-located with the keychain file — they must agree or the CLI cannot find the
# repo). --repo is also passed on every call as the throwaway override.
sandbox_env() {
    local lab="$1"
    export LAB_DIR="$lab"
    export ORG_REPO="$lab/registry"
    export WORKER_REPO="$lab/registry-worker"
    export HOME="$lab/home"
    export AUTHS_HOME="$ORG_REPO"
    export AUTHS_REPO="$ORG_REPO"
    export AUTHS_KEYCHAIN_BACKEND="file"
    export AUTHS_KEYCHAIN_FILE="$ORG_REPO/keys.enc"
    export AUTHS_PASSPHRASE="$SANDBOX_PASSPHRASE"
    export GIT_CONFIG_GLOBAL="$lab/home/.gitconfig"
    export GIT_CONFIG_NOSYSTEM=1
    export GIT_AUTHOR_NAME="Org Root"; export GIT_AUTHOR_EMAIL="root@auths.demo"
    export GIT_COMMITTER_NAME="Org Root"; export GIT_COMMITTER_EMAIL="root@auths.demo"
    export PATH="$(dirname "$AUTHS_BIN"):$PATH"
    mkdir -p "$HOME" "$ORG_REPO"
}

# worker_env <alias> — flip the sandbox onto the WORKER's delegate-machine
# registry and its own git config (signingkey = the worker alias). Call after
# sandbox_env + materialize_worker_machine. The worker signs as a dip-rooted
# delegate here. The alias is passed explicitly (a command-substituted
# delegate_worker cannot export it back to the caller).
worker_env() {
    local alias="${1:-${WORKER_ALIAS:-committer}}"
    export AUTHS_HOME="$WORKER_REPO"
    export AUTHS_REPO="$WORKER_REPO"
    export AUTHS_KEYCHAIN_FILE="$WORKER_REPO/keys.enc"
    export GIT_CONFIG_GLOBAL="$LAB_DIR/home/.gitconfig-worker"
    git config --global gpg.format ssh
    git config --global gpg.ssh.program "$AUTHS_SIGN"
    git config --global user.signingkey "auths:$alias"
    git config --global commit.gpgsign true
    git config --global user.name "$alias"
    git config --global user.email "$alias@auths.demo"
}

# org_env — flip back to the org/verify registry (org icp + scope seal + worker
# dip all resolvable, the registry the verifier replays both KELs from).
org_env() {
    export AUTHS_HOME="$ORG_REPO"
    export AUTHS_REPO="$ORG_REPO"
    export AUTHS_KEYCHAIN_FILE="$ORG_REPO/keys.enc"
    export GIT_CONFIG_GLOBAL="$LAB_DIR/home/.gitconfig"
}

# ── Chain construction (org -> worker agent), all real CLI calls ──────────────

# bootstrap_org <key-alias> — create the org root identity. Echoes its did:keri.
bootstrap_org() {
    local alias="${1:-org}"
    cat > "$LAB_DIR/org-meta.json" <<EOF
{"name":"Org Root","purpose":"over-permissioned sub-agent demo"}
EOF
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id create \
        --metadata-file "$LAB_DIR/org-meta.json" --local-key-alias "$alias" \
        >"$LAB_DIR/org-create.out" 2>&1
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id show 2>/dev/null \
        | grep -oE 'did:keri:[A-Za-z0-9_-]+' | head -1
}

# delegate_worker <label> <delegator-alias> <scope...> — delegate a worker agent
# scoped to the given capabilities. Echoes the worker's did:keri; sets
# WORKER_ALIAS for worker_env. Returns the CLI exit code (so an issuance refusal
# is observable to the caller).
delegate_worker() {
    local label="$1" delegator="$2"; shift 2
    local scope_args=()
    local cap
    for cap in "$@"; do scope_args+=(--scope "$cap"); done
    WORKER_ALIAS="$label"
    "$AUTHS_BIN" --repo "$ORG_REPO" --json id agent add \
        --label "$label" --key "$delegator" --curve ed25519 "${scope_args[@]}" \
        >"$LAB_DIR/agent-add-$label.out" 2>&1
    local rc=$?
    grep -oE 'did:keri:[A-Za-z0-9_-]+' "$LAB_DIR/agent-add-$label.out" | head -1
    return $rc
}

# materialize_worker_machine <root-prefix> — produce the delegate-machine
# registry: copy the org registry, then rewrite refs/auths/registry to DROP the
# org icp root's identity subtree, leaving only the worker dip. This is the
# scriptable equivalent of pairing a second device — `resolve_local_signer` then
# skips the (now-absent) icp root and signs as the worker dip. Tree surgery only;
# no key material is forged or moved.
materialize_worker_machine() {
    local root_pfx="$1"
    cp -R "$ORG_REPO" "$WORKER_REPO"
    local gd="$WORKER_REPO/.git"
    local idx="$gd/tmp-index"
    GIT_INDEX_FILE="$idx" git --git-dir="$gd" read-tree refs/auths/registry
    GIT_INDEX_FILE="$idx" git --git-dir="$gd" ls-files \
        | grep "identities/${root_pfx:0:2}/${root_pfx:2:2}/$root_pfx/" \
        | while read -r p; do
            GIT_INDEX_FILE="$idx" git --git-dir="$gd" rm --cached -q -- "$p"
          done
    local t p c
    t="$(GIT_INDEX_FILE="$idx" git --git-dir="$gd" write-tree)"
    p="$(git --git-dir="$gd" rev-parse refs/auths/registry)"
    c="$(git --git-dir="$gd" commit-tree "$t" -p "$p" -m worker-only)"
    git --git-dir="$gd" update-ref refs/auths/registry "$c"
    rm -f "$idx"
}

# worker_signs_commit <work-repo> <message> <scope-csv> — in a fresh git repo,
# the worker (delegate-machine signer) signs a commit claiming the given scope.
# Echoes the commit SHA. Call inside worker_env.
worker_signs_commit() {
    local work="$1" msg="$2" scope="$3"
    mkdir -p "$work"
    ( cd "$work"
      git init -q
      printf '%s\n' "$msg" > file.txt
      git add file.txt
      git commit -qm "$msg" --no-gpg-sign
      "$AUTHS_BIN" --repo "$WORKER_REPO" sign HEAD --scope "$scope" >/dev/null 2>&1
      git rev-parse HEAD )
}

# verify_commit_status <work-repo> <sha> — run `auths verify` against the ORG
# registry (resolves both KELs + the delegator-anchored scope seal) and echo the
# machine-readable status code (e.g. valid, outside-agent-scope, agent-expired).
# Call inside org_env.
verify_commit_status() {
    local work="$1" sha="$2"
    ( cd "$work"
      "$AUTHS_BIN" --repo "$ORG_REPO" --json verify "$sha" 2>/dev/null ) \
        | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
        | sed -E 's/.*"status"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/'
}
