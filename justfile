# Auths project recipes

# Run all tests (nextest + doc tests).
test:
    cargo nextest run --workspace --all-features
    cargo test --workspace --doc

# Run only integration tests (tests/ directories across all crates).
intest:
    cargo nextest run --workspace -E 'kind(test)'

# Run all build targets in parallel and report pass/fail cleanly.
# Optional targets (wasm-pack, cross/aarch64) are skipped if the tool is not installed.
# Install optional tools:
#   cargo install wasm-pack --version "=0.12.1" --locked
#   cargo install cross --locked   (also needs Docker running)
build:
    #!/usr/bin/env bash
    set -uo pipefail

    GREEN='\033[0;32m'
    RED='\033[0;31m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'

    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT

    pids=()
    names=()
    logs=()

    _run() {
        local label="$1"; shift
        local log="$TMP/${#pids[@]}.log"
        names+=("$label")
        logs+=("$log")
        "$@" >"$log" 2>&1 &
        pids+=($!)
    }

    # --- Always-run builds ---
    _run "native (auths-cli)"        cargo build --release --package auths-cli
    # Run from inside the crate to avoid workspace resolver v3 feature-scoping
    # issues. From the workspace root, `--features wasm` (with or without the
    # pkg/feature qualifier) triggers "cannot specify features for packages
    # outside of workspace" under resolver = "3". cd-ing in sidesteps this.
    _run "wasm32 check"              bash -c 'rustup target add wasm32-unknown-unknown 2>/dev/null; cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --features wasm'
    _run "python bindings"           cargo check --manifest-path packages/auths-verifier-python/Cargo.toml

    # --- Optional: wasm-pack (full wasm-pack pipeline, not just cargo check) ---
    if command -v wasm-pack >/dev/null 2>&1; then
        _run "wasm-pack build"       bash -c 'cd crates/auths-verifier && wasm-pack build --target bundler --features wasm'
    fi

    # --- Optional: aarch64 cross build (requires cross + Docker) ---
    if command -v cross >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        _run "aarch64 cross build"   cross build --release --package auths-cli --target aarch64-unknown-linux-gnu
    fi

    echo ""
    echo -e "${BOLD}Running ${#pids[@]} builds in parallel...${NC}"
    echo ""

    failed=0
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}"
        rc=$?
        label="${names[$i]}"
        log="${logs[$i]}"

        if [ "$rc" -eq 0 ]; then
            printf "  ${GREEN}✓${NC}  %-32s built\n" "$label"
        else
            printf "  ${RED}✗${NC}  %-32s failed\n" "$label"
            # Show error lines and their file locations; skip Compiling/Checking noise
            errors=$(grep -E "^error" "$log" 2>/dev/null | head -8 || true)
            locs=$(grep -E "^ +--> " "$log" 2>/dev/null | head -4 || true)
            if [ -n "$errors" ]; then
                echo "$errors" | sed 's/^/       /'
                [ -n "$locs" ] && echo "$locs" | sed 's/^/       /'
            else
                # Fallback: last few non-blank lines if no ^error lines found
                tail -6 "$log" | grep -v '^\s*$' | sed 's/^/       /'
            fi
            failed=1
        fi
    done

    echo ""
    if [ "$failed" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}All builds passed${NC}"
    else
        echo -e "${RED}${BOLD}One or more builds failed — see above${NC}"
        exit 1
    fi

# Run the Radicle multi-device e2e demo (requires rad CLI).
e2e-radicle:
    bash scripts/radicle-e2e.sh

# Install auths-cli from local source into ~/.cargo/bin
install:
    cargo install --path crates/auths-cli

# Create and push a GitHub release (tag + binaries).
release-github:
    python scripts/releases/1_github.py --push

# Publish all workspace crates to crates.io in dependency order.
release-crates:
    python scripts/releases/2_crates.py --publish

# One-time setup: create a CI release-signing device and export secrets for GitHub
# Run this once locally, then add the printed values as GitHub secrets
# Delegates to the xtask crate for cross-platform correctness.
ci-setup:
    cargo xt ci-setup
