#!/usr/bin/env bash
# harness/env.sh — paths, constants, and helpers for the witness-network
# conformance suite. Source me.
#
# Layout mirrors interop/harness/env.sh: Layer 1 (constants + helpers) is always
# safe to source. The suite drives building the platform witness node in
# ../../../../auths (the shared tree) and boots a LOCAL 3-node fixture (Docker
# Compose) the probes check against. No product code lives here — only the
# fixture that lets a probe behaviorally test a claim end to end.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUITE_DIR="$(dirname "$HARNESS_DIR")"                 # .../claims/network
RECURVE_DIR="$(cd "$SUITE_DIR/../.." && pwd)"          # .../.recurve
NET_ROOT="$(cd "$RECURVE_DIR/.." && pwd)"              # .../auths-network
AUTHS_SRC="$(cd "$NET_ROOT/../auths" && pwd)"          # the platform workspace (shared tree)

HARNESS_COMPOSE="$HARNESS_DIR/compose"
HARNESS_STATE="$HARNESS_DIR/.state"                    # gitignored runtime scratch
VERSIONS_LOCK="$HARNESS_DIR/versions.lock"

# The local fixture: three witness nodes with DISTINCT identities. The seeds are
# fixed (not secrets — a local test fixture), so each node's advertised AID is
# stable and reproducible across bring-ups. Distinct seeds => distinct AIDs =>
# the diversity the threshold story rests on, present from the fixture up.
COMPOSE_PROJECT="auths-witness-net"
NODE_NAMES=(wit1 wit2 wit3)
NODE_PORTS=(3331 3332 3333)
# The local tag the suite makes the RELEASED witness node image present under.
# Standup runs this image (`auths witness up --image "$WITNESS_IMAGE"`); the
# harness (ensure-image.sh) builds it ONCE from the platform's canonical
# deployment Dockerfile. One tag, one source of truth — env.sh, ensure-image.sh,
# up.sh, and the WIT-N1 probe all read it from here.
WITNESS_IMAGE="${WITNESS_IMAGE:-auths-witness:net-fixture}"
# 32-byte hex seeds, one per node — distinct, fixed, obviously test-only.
NODE_SEEDS=(
  "1111111111111111111111111111111111111111111111111111111111111111"
  "2222222222222222222222222222222222222222222222222222222222222222"
  "3333333333333333333333333333333333333333333333333333333333333333"
)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_DIM="$(printf '\033[2m')"; C_GREEN="$(printf '\033[32m')"
    C_RED="$(printf '\033[31m')"; C_RESET="$(printf '\033[0m')"
else
    C_DIM=""; C_GREEN=""; C_RED=""; C_RESET=""
fi
say()  { printf '%s▸ %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die()  { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
pass() { printf '%s✓ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }

# node_health <port> — print the /health JSON of a running node, or fail.
node_health() {
    local port="$1"
    curl -fsS --max-time 3 "http://127.0.0.1:${port}/health" 2>/dev/null
}

# node_aid <port> — the advertised witness identity (AID) of a running node.
node_aid() {
    node_health "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["witness_did"])' 2>/dev/null
}

# all_nodes_healthy — 0 if every node in NODE_PORTS answers /health, else 1.
all_nodes_healthy() {
    local port
    for port in "${NODE_PORTS[@]}"; do
        node_health "$port" >/dev/null 2>&1 || return 1
    done
    return 0
}

# oracle_version — the keripy version pinned in versions.lock (single source).
oracle_version() {
    awk '/^  keripy:/{f=1} f&&/version:/{gsub(/[" ]/,"",$2); print $2; exit}' "$VERSIONS_LOCK"
}
