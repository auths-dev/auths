#!/usr/bin/env bash
# Architectural boundary guard: detects violations in auths-sdk source.
# Excludes test directories, `#[cfg(test)]` modules, comment lines, and doc
# strings to prevent false positives. Run in CI before cargo test.
set -e

SDK_SRC="crates/auths-sdk/src"
VIOLATIONS=0

# Print "file:line:content" for the production region of a file — everything
# before the first `#[cfg(test)]` marker. Test modules sit at the bottom of
# files by convention (enforced by rustfmt ordering in this repo), and test
# code is exempt from the clock/fs/storage rules (mirrors clippy.toml's
# allow-unwrap-in-tests).
production_lines() {
    local file=$1
    awk -v f="$file" '/#\[cfg\(test\)\]/{exit} {print f":"NR":"$0}' "$file"
}

check_pattern() {
    local pattern=$1
    local msg=$2
    local exclude_file=${3:-}
    local matches=""
    local file hits
    while IFS= read -r file; do
        if [ -n "$exclude_file" ] && [ "$file" = "$exclude_file" ]; then
            continue
        fi
        hits=$(production_lines "$file" \
            | grep "$pattern" \
            | grep -Ev ':[0-9]+:[[:space:]]*//' || true)
        if [ -n "$hits" ]; then
            matches+="$hits"$'\n'
        fi
    done < <(find "$SDK_SRC" -name '*.rs' -not -path '*/tests/*')
    if [ -n "$matches" ]; then
        echo "ARCHITECTURE VIOLATION: $msg"
        printf '%s' "$matches"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
}

check_pattern "Utc::now()" "Use injected ClockProvider instead of Utc::now()"
# workflows/commit_hooks.rs is the sanctioned host-filesystem boundary for git
# hook wiring: git itself must execute the hook from a real path with a real
# executable bit, so abstracting these writes behind a storage port would be a
# seam with exactly one implementation. Same precedent as the storage.rs facade.
check_pattern "std::fs::" "Filesystem I/O in SDK layer — use storage port traits" "$SDK_SRC/workflows/commit_hooks.rs"
check_pattern "git2::" "git2 in auths-sdk — inject RegistryBackend instead"
# src/storage.rs is the sanctioned facade: a feature-gated re-export module so
# presentation layers (CLI, servers) can compose concrete Git backends without
# depending on auths-storage directly. SDK *logic* must still never name
# concrete storage types — only the facade may.
check_pattern "GitRegistryBackend\|RegistryIdentityStorage" "Concrete storage types in auths-sdk logic — inject abstractions (only src/storage.rs may re-export them)" "$SDK_SRC/storage.rs"

if [ "$VIOLATIONS" -gt 0 ]; then
    echo ""
    echo "$VIOLATIONS architecture violation(s) found in $SDK_SRC."
    exit "$VIOLATIONS"
fi

echo "Architecture boundary check passed."
