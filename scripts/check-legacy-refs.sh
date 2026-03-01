#!/bin/bash
# CI check to prevent new refs/auths/* or refs/keri/* usage
#
# This script tracks the count of legacy ref patterns in the codebase.
# As migration progresses, the expected count should decrease.
#
# Usage: ./scripts/check-legacy-refs.sh

set -euo pipefail

cd "$(dirname "$0")/.."

echo "Checking for legacy ref patterns..."
echo ""

# Count refs/auths/* usages (excluding comments/docs based on context)
# Use grep with || true to handle no matches
AUTHS_MATCHES=$(grep -rn "refs/auths" crates/ --include="*.rs" 2>/dev/null || true)
if [ -z "$AUTHS_MATCHES" ]; then
    AUTHS_COUNT=0
else
    AUTHS_COUNT=$(echo "$AUTHS_MATCHES" | wc -l | tr -d ' ')
fi
echo "refs/auths/* usages: $AUTHS_COUNT"

# Count refs/keri/* usages (the old pattern, not refs/did/keri/*)
KERI_MATCHES=$(grep -rn "refs/keri" crates/ --include="*.rs" 2>/dev/null || true)
if [ -z "$KERI_MATCHES" ]; then
    KERI_COUNT=0
else
    # Filter out refs/did/keri which is the current pattern
    KERI_FILTERED=$(echo "$KERI_MATCHES" | grep -v "refs/did/keri" || true)
    if [ -z "$KERI_FILTERED" ]; then
        KERI_COUNT=0
    else
        KERI_COUNT=$(echo "$KERI_FILTERED" | wc -l | tr -d ' ')
    fi
fi
echo "refs/keri/* usages: $KERI_COUNT"

# Check refs/auths/registry (the new pattern - should exist)
REGISTRY_MATCHES=$(grep -rn "refs/authly" crates/ --include="*.rs" 2>/dev/null || true)
if [ -z "$REGISTRY_MATCHES" ]; then
    REGISTRY_COUNT=0
else
    REGISTRY_COUNT=$(echo "$REGISTRY_MATCHES" | wc -l | tr -d ' ')
fi
echo "refs/auths/* usages: $REGISTRY_COUNT"

echo ""

# Expected counts as of 2026-02-08
# These should decrease as migration progresses
EXPECTED_AUTHS=51
EXPECTED_KERI=0

# Fail if refs/keri count increased
if [ "$KERI_COUNT" -gt "$EXPECTED_KERI" ]; then
    echo "ERROR: refs/keri/* usage increased from $EXPECTED_KERI to $KERI_COUNT"
    echo "This pattern is deprecated. Use refs/auths/registry instead."
    exit 1
fi

# Fail if refs/auths count increased
if [ "$AUTHS_COUNT" -gt "$EXPECTED_AUTHS" ]; then
    echo "ERROR: refs/auths/* usage increased from $EXPECTED_AUTHS to $AUTHS_COUNT"
    echo "This pattern is deprecated. Use PackedRegistryBackend with refs/auths/registry instead."
    exit 1
fi

# Success message
if [ "$AUTHS_COUNT" -lt "$EXPECTED_AUTHS" ]; then
    echo "PROGRESS: refs/auths/* decreased from $EXPECTED_AUTHS to $AUTHS_COUNT"
    echo "Consider updating EXPECTED_AUTHS in this script."
fi

echo ""
echo "Legacy ref check passed."
echo ""
echo "Migration status:"
echo "  - refs/keri/*: $KERI_COUNT (target: 0) - DONE"
echo "  - refs/auths/*: $AUTHS_COUNT (target: 0) - IN PROGRESS"
echo "  - refs/auths/*: $REGISTRY_COUNT (should increase as migration progresses)"
