#!/usr/bin/env bash
# Architectural boundary guard: detects violations in auths-sdk source.
# Excludes test directories, comment lines, and doc strings to prevent false positives.
# Run in CI before cargo test.
set -e

SDK_SRC="crates/auths-sdk/src"
VIOLATIONS=0

# Filter from grep -rn "filepath:linenum:content" output:
#   - lines where content part starts with // or /// (comments)
#   - lines where content part starts with whitespace then // (indented comments)
not_comment() {
    grep -Ev ':[0-9]+:[[:space:]]*//'
}

check_pattern() {
    local pattern=$1
    local msg=$2
    local matches
    matches=$(grep -r --include="*.rs" \
        --exclude-dir=tests \
        -n \
        "$pattern" $SDK_SRC 2>/dev/null \
        | not_comment || true)
    if [ -n "$matches" ]; then
        echo "ARCHITECTURE VIOLATION: $msg"
        echo "$matches"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
}

check_pattern "Utc::now()" "Use injected ClockProvider instead of Utc::now()"
check_pattern "std::fs::" "Filesystem I/O in SDK layer — use storage port traits"
check_pattern "git2::" "git2 in auths-sdk — inject RegistryBackend instead"
check_pattern "GitRegistryBackend\|RegistryIdentityStorage" "Concrete storage types in auths-sdk — inject abstractions"

if [ "$VIOLATIONS" -gt 0 ]; then
    echo ""
    echo "$VIOLATIONS architecture violation(s) found in $SDK_SRC."
    exit "$VIOLATIONS"
fi

echo "Architecture boundary check passed."
