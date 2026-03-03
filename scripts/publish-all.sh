#!/usr/bin/env bash
set -euo pipefail

# Publish all workspace crates to crates.io in dependency order.
# Waits 160 seconds between each publish for crates.io indexing.

WAIT_SECS=160

# Dependency-ordered list (foundations first, leaves last).
# Skipped: auths-test-utils, xtask (publish = false)
# Skipped: auths-radicle (depends on unpublished radicle-core/radicle-crypto)
# Skipped: auths-mobile-ffi (UniFFI mobile bindings, not a library crate)
CRATES=(
  auths
  auths-crypto
  auths-index
  auths-policy
  auths-telemetry
  auths-verifier
  auths-core
  auths-infra-http
  auths-id
  auths-sdk
  auths-storage
  auths-infra-git
  auths-cli
)

TOTAL=${#CRATES[@]}

for i in "${!CRATES[@]}"; do
  crate="${CRATES[$i]}"
  num=$((i + 1))

  echo ""
  echo "[$num/$TOTAL] Publishing $crate..."
  echo ""

  cargo publish -p "$crate"

  if [ "$num" -lt "$TOTAL" ]; then
    echo ""
    echo "Waiting ${WAIT_SECS}s for crates.io to index $crate..."
    sleep "$WAIT_SECS"
  fi
done

echo ""
echo "All $TOTAL crates published."
