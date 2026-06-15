#!/usr/bin/env bash
# harness/kill-node.sh — failure injection. Stop one witness node by index
# (1..3) so a probe can assert how the network degrades: kill one and a 2-of-3
# threshold still holds; kill two and ordering-sensitive verdicts fail closed.
#
#   kill-node.sh <N>        stop node N (1-based)
#   kill-node.sh <N> start  restore node N
#
# Stop, not remove — the node's identity and receipts survive so a restart is a
# real recovery, not a fresh node. This is the FR-13 "kill 1 node" lever.
set -euo pipefail
. "$(dirname "$0")/env.sh"

idx="${1:-}"
action="${2:-stop}"
case "$idx" in
  1|2|3) ;;
  *) die "usage: kill-node.sh <1|2|3> [stop|start]" ;;
esac
name="${NODE_NAMES[$((idx-1))]}"

case "$action" in
  stop)
    docker compose -p "$COMPOSE_PROJECT" -f "$HARNESS_COMPOSE/docker-compose.yml" stop "$name" >/dev/null
    pass "node $idx ($name) stopped — port ${NODE_PORTS[$((idx-1))]} now dark"
    ;;
  start)
    docker compose -p "$COMPOSE_PROJECT" -f "$HARNESS_COMPOSE/docker-compose.yml" start "$name" >/dev/null
    pass "node $idx ($name) restarted"
    ;;
  *) die "unknown action '$action' — expected stop|start" ;;
esac
