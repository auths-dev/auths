#!/usr/bin/env bash
# harness/up.sh — bring the local 3-witness fixture up idempotently.
#
# Builds the platform witness image (musl-static auths-witness, from the shared
# tree's canonical deployment Dockerfile) and boots three nodes with distinct
# identities. Idempotent: if the three are already healthy this returns fast.
# Mirrors interop/peers/up.sh — bring-up is the harness's job, never a probe's
# (probes are hermetic and only READ the running fixture).
set -euo pipefail
. "$(dirname "$0")/env.sh"

if ! command -v docker >/dev/null 2>&1; then
    echo "BROKEN: docker CLI absent — the 3-witness fixture needs Docker." >&2
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    echo "BROKEN: Docker daemon down — start Docker Desktop (open -a Docker)." >&2
    exit 2
fi

export AUTHS_SRC

if all_nodes_healthy; then
    pass "3-witness fixture already healthy on ports ${NODE_PORTS[*]}"
    exit 0
fi

# One image build, shared by all three nodes — never three concurrent workspace
# compiles. ensure-image.sh owns the build (one source of truth, reused by the
# WIT-N1 standup probe); the compose file pins the same tag ($WITNESS_IMAGE).
bash "$HARNESS_DIR/ensure-image.sh"

say "booting the three nodes from the shared image"
docker compose -p "$COMPOSE_PROJECT" -f "$HARNESS_COMPOSE/docker-compose.yml" up -d

say "waiting for all three nodes to answer /health (≤120s)"
deadline=$(( $(date +%s) + 120 ))
until all_nodes_healthy; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        die "fixture did not become healthy within 120s — see: docker compose -p $COMPOSE_PROJECT logs"
    fi
    sleep 2
done

# Distinct identities are the whole point — surface them so bring-up is auditable.
for i in "${!NODE_NAMES[@]}"; do
    aid="$(node_aid "${NODE_PORTS[$i]}")"
    pass "${NODE_NAMES[$i]} healthy on :${NODE_PORTS[$i]} — identity ${aid}"
done
