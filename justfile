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

# Private server recipes (e2e, sitedemo, logindemo, chatdemo) have been moved to auths-cloud.


# Private server recipes (e2e, sitedemo, logindemo, chatdemo) have been moved to auths-cloud.

# Bump the workspace version, commit, tag, and push to trigger the release workflow.
# Usage: just release 0.0.1-rc.10
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    # Colors
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    RED='\033[0;31m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'

    VERSION="{{VERSION}}"
    TAG="v${VERSION}"

    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}                    Release Publisher                       ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Version:${NC} ${CYAN}${TAG}${NC}"

    # Check if on main/master branch
    CURRENT_BRANCH=$(git branch --show-current)
    if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
        echo -e "${YELLOW}⚠ Warning:${NC} You're on branch ${CYAN}${CURRENT_BRANCH}${NC}, not ${CYAN}main${NC}"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}✗${NC} Release cancelled"
            exit 1
        fi
    fi

    # Check for uncommitted changes (before we make our own)
    if ! git diff-index --quiet HEAD --; then
        echo -e "${RED}✗ Error:${NC} Uncommitted changes detected"
        echo ""
        git status --short
        echo ""
        echo -e "${DIM}Commit or stash your changes before releasing${NC}"
        exit 1
    fi

    # Bump version in root Cargo.toml (single source of truth via workspace.package)
    CURRENT=$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
    echo -e "${BOLD}Bumping:${NC} ${DIM}${CURRENT}${NC} → ${CYAN}${VERSION}${NC}"
    sed -i '' "s/^version = \"${CURRENT}\"/version = \"${VERSION}\"/" Cargo.toml
    # Refresh Cargo.lock
    cargo metadata --no-deps --format-version 1 -q > /dev/null
    git add Cargo.toml Cargo.lock
    git diff --cached --quiet || git commit -m "chore: release ${TAG}"

    # Check if tag already exists
    if git rev-parse "$TAG" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Warning:${NC} Tag ${CYAN}${TAG}${NC} already exists"
        read -p "Delete and recreate? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${DIM}Deleting local and remote tag...${NC}"
            git tag -d "$TAG" 2>/dev/null || true
            git push origin ":refs/tags/$TAG" 2>/dev/null || true
            echo -e "${GREEN}✓${NC} Deleted existing tag"
        else
            echo -e "${RED}✗${NC} Release cancelled"
            exit 1
        fi
    fi

    # Pre-flight checks
    echo ""
    echo -e "${BOLD}Pre-flight Checks:${NC}"

    # Check if release workflow exists
    if [ ! -f ".github/workflows/release.yml" ]; then
        echo -e "  ${RED}✗${NC} Release workflow not found at .github/workflows/release.yml"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Release workflow exists"

    # Check if we can push
    if ! git ls-remote --exit-code origin >/dev/null 2>&1; then
        echo -e "  ${RED}✗${NC} Cannot reach remote origin"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Remote accessible"

    # Sync with remote
    echo -e "  ${DIM}Fetching latest from origin...${NC}"
    git fetch origin --quiet

    # Check if local is behind remote
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")
    if [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
        BASE=$(git merge-base @ @{u} 2>/dev/null || echo "")
        if [ "$LOCAL" = "$BASE" ]; then
            echo -e "  ${RED}✗${NC} Your branch is behind origin. Run: git pull"
            exit 1
        elif [ "$REMOTE" = "$BASE" ]; then
            echo -e "  ${YELLOW}⚠${NC} Your branch is ahead of origin (unpushed commits)"
        else
            echo -e "  ${RED}✗${NC} Your branch has diverged from origin"
            exit 1
        fi
    fi
    echo -e "  ${GREEN}✓${NC} Branch is up to date"

    echo ""

    # Confirmation
    echo -e "${BOLD}Release Summary:${NC}"
    echo -e "  Tag:          ${CYAN}${TAG}${NC}"
    echo -e "  Branch:       ${CYAN}${CURRENT_BRANCH}${NC}"
    echo -e "  Commit:       ${DIM}$(git rev-parse --short HEAD)${NC}"
    echo -e "  Remote:       ${DIM}$(git remote get-url origin)${NC}"
    echo ""
    echo -e "${BOLD}This will:${NC}"
    echo -e "  1. Create tag ${CYAN}${TAG}${NC}"
    echo -e "  2. Push tag to origin"
    echo -e "  3. Trigger GitHub Actions release workflow"
    echo -e "  4. Build binaries for all platforms"
    echo -e "  5. Create GitHub release with artifacts"
    echo -e "  6. Trigger Homebrew formula update"
    echo ""

    read -p "$(echo -e ${BOLD}Proceed with release?${NC}) [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}✗${NC} Release cancelled"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}Creating Release...${NC}"

    # Create tag
    echo -e "  ${DIM}Creating tag ${TAG}...${NC}"
    git tag -a "$TAG" -m "Release ${VERSION}"
    echo -e "  ${GREEN}✓${NC} Tag created"

    # Push tag
    echo -e "  ${DIM}Pushing tag to origin...${NC}"
    git push origin "$TAG"
    echo -e "  ${GREEN}✓${NC} Tag pushed"

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Release ${TAG} Initiated!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Get repo info
    REPO_URL=$(git remote get-url origin | sed 's/\.git$//' | sed 's|git@github.com:|https://github.com/|')

    echo -e "${BOLD}Monitor Progress:${NC}"
    echo -e "  Workflow:  ${CYAN}${REPO_URL}/actions/workflows/release.yml${NC}"
    echo -e "  Release:   ${CYAN}${REPO_URL}/releases/tag/${TAG}${NC}"
    echo ""

    # Try to open browser
    if command -v gh &> /dev/null; then
        echo -e "${DIM}Waiting for workflow to start...${NC}"
        sleep 3

        # Try to get workflow run
        WORKFLOW_URL=$(gh run list --workflow=release.yml --limit 1 --json databaseId,url --jq '.[0].url' 2>/dev/null || echo "")

        if [ -n "$WORKFLOW_URL" ]; then
            echo -e "${BOLD}Opening workflow run...${NC}"
            if command -v open &> /dev/null; then
                open "$WORKFLOW_URL"
            elif command -v xdg-open &> /dev/null; then
                xdg-open "$WORKFLOW_URL"
            fi
        fi
    else
        echo -e "${DIM}Install 'gh' CLI to auto-open workflow runs${NC}"
    fi

    echo ""
    echo -e "${BOLD}What Happens Next:${NC}"
    echo -e "  1. ${DIM}GitHub Actions builds binaries (5-10 min)${NC}"
    echo -e "  2. ${DIM}Creates GitHub release with artifacts${NC}"
    echo -e "  3. ${DIM}Triggers Homebrew formula update (automated)${NC}"
    echo -e "  4. ${DIM}Review & merge Homebrew PR${NC}"
    echo ""
    echo -e "${BOLD}If Workflow Fails:${NC}"
    echo -e "  • Check Actions tab for error logs"
    echo -e "  • Fix the issue and re-run: ${CYAN}just release ${VERSION}${NC}"
    echo -e "  • Delete failed release if needed: ${CYAN}gh release delete ${TAG}${NC}"
    echo ""
    echo -e "${BOLD}After Successful Release:${NC}"
    echo -e "  • Verify binaries uploaded: ${CYAN}${REPO_URL}/releases/tag/${TAG}${NC}"
    echo -e "  • Check Homebrew PR: ${CYAN}https://github.com/bordumb/homebrew-auths-cli/pulls${NC}"
    echo -e "  • Test installation: ${CYAN}brew upgrade auths && auths --version${NC}"
    echo ""
    echo -e "${DIM}Happy releasing! 🚀${NC}"
    echo ""

# Check release workflow status
release-status:
    #!/usr/bin/env bash
    set -euo pipefail

    if ! command -v gh &> /dev/null; then
        echo "Error: 'gh' CLI not installed"
        echo "Install: brew install gh"
        exit 1
    fi

    echo ""
    echo "Recent release workflow runs:"
    echo ""
    gh run list --workflow=release.yml --limit 5
    echo ""

# Delete a release tag (local and remote)
release-delete TAG:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "Deleting release tag: {{TAG}}"
    git tag -d "{{TAG}}" 2>/dev/null || echo "Local tag not found"
    git push origin ":refs/tags/{{TAG}}" 2>/dev/null || echo "Remote tag not found"

    if command -v gh &> /dev/null; then
        gh release delete "{{TAG}}" --yes 2>/dev/null || echo "GitHub release not found"
    fi

    echo "✓ Deleted {{TAG}}"

# Install auths-cli from local source into ~/.cargo/bin
install:
    cargo install --path crates/auths-cli

# One-time setup: create a CI release-signing device and export secrets for GitHub
# Run this once locally, then add the printed values as GitHub secrets
# Delegates to the xtask crate for cross-platform correctness.
ci-setup:
    cargo xt ci-setup
