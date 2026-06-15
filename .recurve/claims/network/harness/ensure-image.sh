#!/usr/bin/env bash
# harness/ensure-image.sh — make the released witness node image PRESENT locally.
#
# Standup runs a RELEASED image (`image:`, never `build:`) — obtaining that image
# is the harness's job, never the probe's or `up`'s. On a real VPS the operator
# pulls the published image; on a dev/CI box where it is not published, the
# harness builds it ONCE from the platform's canonical deployment Dockerfile and
# tags it, so `auths witness up --image "$WITNESS_IMAGE"` finds it present and
# stands a real node up. This keeps the source build OUT of the standup path
# (WIT-B4) — the binary the node runs is still what the platform ships, built
# from the canonical image definition, just made present here.
#
# Idempotent: if the tag already exists this returns fast.
set -euo pipefail
. "$(dirname "$0")/env.sh"

# The local tag standup is pointed at by the suite. One tag, one source of truth,
# shared by ensure-image, up.sh, and the WIT-N1 probe.
WITNESS_IMAGE="${WITNESS_IMAGE:-auths-witness:net-fixture}"

if ! command -v docker >/dev/null 2>&1; then
    die "docker CLI absent — the witness image needs a container engine"
fi
if ! docker info >/dev/null 2>&1; then
    die "Docker daemon down — start Docker Desktop (open -a Docker)"
fi

if docker image inspect "$WITNESS_IMAGE" >/dev/null 2>&1; then
    pass "witness image already present: $WITNESS_IMAGE"
    exit 0
fi

say "building the witness node image ONCE from the canonical deployment Dockerfile (musl static; first build is slow, cached after)"
# One build, tagged for the whole suite. The .dockerignore in $AUTHS_SRC keeps the
# context to source only.
docker build \
    -f "$AUTHS_SRC/docs/deployment/witness/Dockerfile" \
    -t "$WITNESS_IMAGE" \
    "$AUTHS_SRC"

docker image inspect "$WITNESS_IMAGE" >/dev/null 2>&1 \
    || die "image build reported success but $WITNESS_IMAGE is not present"
pass "witness image built and tagged: $WITNESS_IMAGE"
