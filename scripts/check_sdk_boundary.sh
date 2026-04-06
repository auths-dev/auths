#!/bin/bash
set -euo pipefail

# Hard ban: CLI must not reference core/id/storage directly.
# Zero exceptions. Pre-launch, zero users, no reason to bypass.
# Covers ALL of auths-cli/src/, including test code.

# Check both `use` imports AND inline qualified paths
VIOLATIONS=$(grep -rn "auths_core::\|auths_id::\|auths_storage::" \
  crates/auths-cli/src/ \
  --include='*.rs' || true)

if [ -n "$VIOLATIONS" ]; then
  echo "BLOCKED: CLI referencing core/id/storage directly."
  echo "Route all imports through auths-sdk modules."
  echo ""
  echo "$VIOLATIONS"
  exit 1
fi

echo "OK: No direct core/id/storage references in CLI."
