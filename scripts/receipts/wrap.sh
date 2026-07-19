#!/usr/bin/env bash
# RC-E5.1 — the local test/seeding harness: wrap both first-party servers on
# x402 test-mode. The MARKET LISTING never includes these wrap lines — the
# submitted endpointValue is the BARE server command (`auths-receipts-server` /
# `auths-escrow-server`); the market and every buyer run their own wrap.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

BIN_DIR="${BIN_DIR:-$root/target/release}"
RECEIPTS_BUDGET="${RECEIPTS_BUDGET:-\$5}"
ESCROW_BUDGET="${ESCROW_BUDGET:-\$50}"

if [[ ! -x "$BIN_DIR/auths-receipts-server" ]]; then
  echo "building release binaries…" >&2
  (cd "$root" && cargo build --release -p auths-receipts -p auths-mcp-gateway)
fi

case "${1:-receipts}" in
  receipts)
    exec "$BIN_DIR/auths-mcp-gateway" wrap \
      --scope receipts.build --scope receipts.verify --scope dispute.evidence \
      --budget "$RECEIPTS_BUDGET" --rail x402 --test-mode \
      ${DISPUTE_REF:+--dispute-ref "$DISPUTE_REF"} \
      -- "$BIN_DIR/auths-receipts-server"
    ;;
  escrow)
    exec "$BIN_DIR/auths-mcp-gateway" wrap \
      --scope escrow.open --scope escrow.release --scope escrow.arbitrate \
      --budget "$ESCROW_BUDGET" --rail x402 --test-mode \
      -- "$BIN_DIR/auths-escrow-server"
    ;;
  *)
    echo "usage: wrap.sh [receipts|escrow]" >&2
    exit 2
    ;;
esac
