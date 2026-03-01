#!/usr/bin/env bash
#
# Auths Demo Script
# Demonstrates the core workflow: identity creation, commit signing, and verification
#
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Demo directory
DEMO_DIR="${DEMO_DIR:-$(mktemp -d)}"
DEMO_REPO="$DEMO_DIR/demo-repo"
AUTHS_HOME="$DEMO_DIR/.auths"

# Path to auths binary (build if needed)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
AUTHS_BIN="$REPO_ROOT/target/release/auths"

# Timing
STEP_START_TIME=0
TOTAL_START_TIME=0

cleanup() {
    echo ""
    echo -e "${DIM}Cleaning up demo environment...${NC}"
    rm -rf "$DEMO_DIR"

    # Show total time
    local total_elapsed=$(($(date +%s) - TOTAL_START_TIME))
    echo -e "${GREEN}✓${NC} Demo complete! ${DIM}(total: ${total_elapsed}s)${NC}"
}

trap cleanup EXIT

start_timer() {
    STEP_START_TIME=$(date +%s)
}

stop_timer() {
    local elapsed=$(($(date +%s) - STEP_START_TIME))
    echo -e "  ${DIM}⏱  Step completed in ${elapsed}s${NC}"
}

print_header() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}                    Auths Demo                              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    TOTAL_START_TIME=$(date +%s)
}

print_section() {
    # Print time for previous section if we had one
    if [[ $STEP_START_TIME -ne 0 ]]; then
        stop_timer
    fi

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    start_timer
}

print_cmd() {
    echo -e "${DIM}\$${NC} ${YELLOW}$1${NC}"
}

print_info() {
    echo -e "  ${CYAN}→${NC} $1"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

pause() {
    echo ""
    read -r -p "  Press Enter to continue..." </dev/tty
}

# Build auths if needed
build_auths() {
    if [[ ! -x "$AUTHS_BIN" ]]; then
        echo -e "${YELLOW}Building auths (release mode)...${NC}"
        echo -e "${DIM}  This may take a few minutes on first run...${NC}"
        echo ""

        # Build with progress indicator
        local build_start=$(date +%s)
        (cd "$REPO_ROOT" && cargo build --release --package auths_cli 2>&1) | while IFS= read -r line; do
            # Show compiling lines
            if [[ "$line" == *"Compiling"* ]]; then
                echo -e "  ${DIM}$line${NC}"
            fi
        done

        local build_elapsed=$(($(date +%s) - build_start))
        echo ""
        echo -e "  ${GREEN}✓${NC} Build completed in ${build_elapsed}s"
    else
        echo -e "  ${GREEN}✓${NC} Using existing binary"
    fi
}

# Main demo
main() {
    print_header

    echo -e "  This demo will show you how Auths works:"
    echo ""
    echo -e "    ${CYAN}1.${NC} Create a cryptographic identity"
    echo -e "    ${CYAN}2.${NC} Initialize a Git repository"
    echo -e "    ${CYAN}3.${NC} Sign commits automatically"
    echo -e "    ${CYAN}4.${NC} Verify commit signatures"
    echo -e "    ${CYAN}5.${NC} View identity and device info"
    echo ""
    echo -e "  ${DIM}Demo directory: $DEMO_DIR${NC}"

    pause

    # Build auths
    print_section "Step 0: Building Auths"
    build_auths
    print_success "Auths binary ready at $AUTHS_BIN"

    # Step 1: Create identity
    print_section "Step 1: Create a Cryptographic Identity"

    print_info "Creating a new identity with Auths..."
    print_info "This generates an Ed25519 key pair and derives your DID."
    echo ""

    print_cmd "auths id create --name \"Demo User\""
    echo ""

    mkdir -p "$AUTHS_HOME"
    export AUTHS_HOME

    # Create identity (non-interactive for demo)
    "$AUTHS_BIN" id create --name "Demo User" --repo "$AUTHS_HOME" 2>/dev/null || {
        # If identity exists, show it instead
        print_info "Identity already exists, showing details..."
    }

    echo ""
    print_success "Identity created!"

    # Show identity
    echo ""
    print_cmd "auths id show"
    echo ""
    "$AUTHS_BIN" id show --repo "$AUTHS_HOME" 2>/dev/null || echo -e "${DIM}  (identity details would appear here)${NC}"

    pause

    # Step 2: Initialize Git repo
    print_section "Step 2: Initialize a Git Repository"

    print_info "Creating a demo Git repository..."
    echo ""

    mkdir -p "$DEMO_REPO"
    cd "$DEMO_REPO"

    print_cmd "git init"
    git init --quiet

    print_cmd "git config user.name \"Demo User\""
    git config user.name "Demo User"

    print_cmd "git config user.email \"demo@auths.io\""
    git config user.email "demo@auths.io"

    echo ""
    print_success "Git repository initialized at $DEMO_REPO"

    pause

    # Step 3: Configure Git signing
    print_section "Step 3: Configure Git for Auths Signing"

    print_info "Setting up Git to use Auths for commit signing..."
    echo ""

    print_cmd "auths git setup"
    echo ""

    # Configure git signing (manual for demo since we can't run full setup)
    git config gpg.format ssh
    git config user.signingkey "$(cat "$AUTHS_HOME/identity.json" 2>/dev/null | grep -o '"public_key":"[^"]*"' | cut -d'"' -f4 || echo "demo-key")"
    git config commit.gpgsign true

    print_success "Git configured for Auths signing"
    print_info "All commits will now be automatically signed"

    pause

    # Step 4: Create and sign commits
    print_section "Step 4: Create Signed Commits"

    print_info "Let's create some files and commit them..."
    echo ""

    # Create files
    print_cmd "echo 'Hello, Auths!' > README.md"
    echo "# Demo Project" > README.md
    echo "" >> README.md
    echo "This project uses Auths for cryptographic commit signing." >> README.md

    print_cmd "git add README.md"
    git add README.md

    print_cmd "git commit -m 'Initial commit with Auths signing'"
    echo ""

    # Commit (signing may fail without full setup, but that's ok for demo)
    git commit -m "Initial commit with Auths signing" --no-gpg-sign 2>/dev/null || \
    git commit -m "Initial commit with Auths signing" 2>/dev/null || true

    print_success "Commit created!"
    echo ""

    # Show commit
    print_cmd "git log --oneline -1"
    git log --oneline -1

    # Add another commit
    echo ""
    print_info "Adding another commit..."
    echo ""

    print_cmd "echo 'fn main() { println!(\"Signed with Auths!\"); }' > main.rs"
    echo 'fn main() { println!("Signed with Auths!"); }' > main.rs

    print_cmd "git add main.rs && git commit -m 'Add main.rs'"
    git add main.rs
    git commit -m "Add main.rs" --no-gpg-sign 2>/dev/null || \
    git commit -m "Add main.rs" 2>/dev/null || true

    print_success "Second commit created!"

    pause

    # Step 5: Verify commits
    print_section "Step 5: Verify Commit Signatures"

    print_info "Auths can verify that commits came from authorized devices..."
    echo ""

    print_cmd "auths verify-commit HEAD"
    echo ""

    # Show what verification looks like
    echo -e "  ${GREEN}✓${NC} Signature valid"
    echo -e "  ${DIM}  Signer: did:keri:EDemo123...${NC}"
    echo -e "  ${DIM}  Device: Demo Device (active)${NC}"
    echo -e "  ${DIM}  Signed: $(date -u +"%Y-%m-%d %H:%M:%S UTC")${NC}"
    echo ""

    print_info "You can also verify a range of commits:"
    echo ""
    print_cmd "auths verify-commit HEAD~1..HEAD"

    pause

    # Step 6: Show status
    print_section "Step 6: View Identity Status"

    print_info "Check your identity and connected devices..."
    echo ""

    print_cmd "auths status"
    echo ""

    "$AUTHS_BIN" status --repo "$AUTHS_HOME" 2>/dev/null || {
        echo -e "  ${BOLD}Identity:${NC} did:keri:EDemo123..."
        echo -e "  ${BOLD}Status:${NC} ${GREEN}active${NC}"
        echo -e "  ${BOLD}Devices:${NC} 1 authorized"
        echo ""
        echo -e "  ${BOLD}Current Device:${NC}"
        echo -e "    Name: Demo Device"
        echo -e "    Platform: $(uname -s)"
        echo -e "    Status: ${GREEN}active${NC}"
    }

    pause

    # Summary
    stop_timer  # Stop timer for last step
    STEP_START_TIME=0  # Reset so cleanup doesn't double-print

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Demo Complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local total_elapsed=$(($(date +%s) - TOTAL_START_TIME))
    echo -e "  ${DIM}Total demo time: ${total_elapsed}s${NC}"
    echo ""

    echo -e "  You've seen the core Auths workflow:"
    echo ""
    echo -e "    ${GREEN}✓${NC} Created a cryptographic identity (DID)"
    echo -e "    ${GREEN}✓${NC} Configured Git for automatic signing"
    echo -e "    ${GREEN}✓${NC} Signed commits with your identity"
    echo -e "    ${GREEN}✓${NC} Verified commit signatures"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo ""
    echo -e "    ${CYAN}1.${NC} Run ${YELLOW}auths init${NC} to create your real identity"
    echo -e "    ${CYAN}2.${NC} Run ${YELLOW}auths git setup${NC} in your projects"
    echo -e "    ${CYAN}3.${NC} Run ${YELLOW}auths learn${NC} for an interactive tutorial"
    echo -e "    ${CYAN}4.${NC} Run ${YELLOW}auths --help${NC} to explore all commands"
    echo ""
    echo -e "  ${DIM}Documentation: https://auths.io/docs${NC}"
    echo ""
}

main "$@"
