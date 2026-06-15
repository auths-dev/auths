#!/usr/bin/env bash
# harness/down.sh — tear the local 3-witness fixture down. Removes containers and
# the fixture network; leaves the built image cached for the next bring-up.
set -euo pipefail
. "$(dirname "$0")/env.sh"

if ! docker info >/dev/null 2>&1; then
    say "Docker daemon down — nothing to tear down"
    exit 0
fi
docker compose -p "$COMPOSE_PROJECT" -f "$HARNESS_COMPOSE/docker-compose.yml" down --remove-orphans
pass "3-witness fixture down"
