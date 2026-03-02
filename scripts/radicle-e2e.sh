#!/usr/bin/env bash
#
# Radicle Multi-Device E2E Demo
#
# Automated (non-interactive) test that exercises the real rad + auths CLIs
# together: sets up two Radicle nodes, creates an Auths identity, links both
# nodes as devices, creates a project, verifies authorizations, and revokes
# a device.
#
# Prerequisites: rad CLI installed (https://radicle.xyz)
# Usage:        just e2e-radicle   OR   bash scripts/radicle-e2e.sh
#
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
AUTHS_BIN="$REPO_ROOT/target/release/auths"
DEMO_DIR="$(mktemp -d)"

# Auths storage
AUTHS_HOME="$DEMO_DIR/.auths"

# Two simulated Radicle nodes
RAD_NODE1_HOME="$DEMO_DIR/rad-node-1"
RAD_NODE2_HOME="$DEMO_DIR/rad-node-2"

# ── Headless environment ──────────────────────────────────────────────────────
export AUTHS_KEYCHAIN_BACKEND=file
export AUTHS_KEYCHAIN_FILE="$DEMO_DIR/keys.enc"
export AUTHS_PASSPHRASE=test-e2e-passphrase
export RAD_PASSPHRASE="e2e-rad"
export GIT_AUTHOR_NAME="E2E Tester"
export GIT_AUTHOR_EMAIL="e2e@test.local"
export GIT_COMMITTER_NAME="E2E Tester"
export GIT_COMMITTER_EMAIL="e2e@test.local"

# ── Phase tracking ────────────────────────────────────────────────────────────
PHASE_RESULTS=()
CURRENT_PHASE=""

phase_start() {
    CURRENT_PHASE="$1"
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

phase_pass() {
    echo ""
    echo -e "  ${GREEN}✓ PASS${NC}: $CURRENT_PHASE"
    PHASE_RESULTS+=("PASS: $CURRENT_PHASE")
}

phase_fail() {
    local msg="${1:-assertion failed}"
    echo ""
    echo -e "  ${RED}✗ FAIL${NC}: $CURRENT_PHASE — $msg"
    PHASE_RESULTS+=("FAIL: $CURRENT_PHASE — $msg")
}

assert_ok() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $desc"
    else
        echo -e "  ${RED}✗${NC} $desc"
        phase_fail "$desc"
        exit 1
    fi
}

assert_contains() {
    local desc="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo -e "  ${GREEN}✓${NC} $desc"
    else
        echo -e "  ${RED}✗${NC} $desc (expected to find: $needle)"
        phase_fail "$desc"
        exit 1
    fi
}

assert_not_contains() {
    local desc="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo -e "  ${RED}✗${NC} $desc (unexpectedly found: $needle)"
        phase_fail "$desc"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} $desc"
    fi
}

info() {
    echo -e "  ${CYAN}→${NC} $1"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${DIM}Stopping any running Radicle nodes...${NC}"
    RAD_HOME="$RAD_NODE1_HOME" rad node stop 2>/dev/null || true
    RAD_HOME="$RAD_NODE2_HOME" rad node stop 2>/dev/null || true
    echo -e "${DIM}Cleaning up $DEMO_DIR ...${NC}"
    rm -rf "$DEMO_DIR"
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 0 — Prerequisites & Build
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 0: Prerequisites & Build"

if ! command -v rad >/dev/null 2>&1; then
    echo -e "  ${RED}✗${NC} 'rad' CLI not found."
    echo -e "    Install Radicle: ${CYAN}https://radicle.xyz${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} rad CLI found: $(command -v rad)"

if [[ ! -x "$AUTHS_BIN" ]]; then
    info "Building auths (release mode)..."
    (cd "$REPO_ROOT" && cargo build --release --package auths_cli 2>&1) \
        | grep -E "Compiling|Finished" \
        | sed 's/^/    /' || true
fi
assert_ok "auths binary is executable" test -x "$AUTHS_BIN"

info "Demo directory: $DEMO_DIR"
mkdir -p "$AUTHS_HOME" "$RAD_NODE1_HOME" "$RAD_NODE2_HOME"

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 1 — Set up two Radicle nodes
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 1: Set up two Radicle nodes"

# Pre-generate deterministic 32-byte seeds.  RAD_KEYGEN_SEED lets us control
# the Ed25519 seed that `rad auth` uses, so we know the raw bytes without
# having to parse the OpenSSH private-key file that Radicle writes to disk.
NODE1_SEED_HEX=$(openssl rand -hex 32)
NODE2_SEED_HEX=$(openssl rand -hex 32)

# TEST-ONLY: Write seed bytes to disk so `auths key import --seed-file` can
# read them. In production, `rad auth` will pass the seed directly to the
# auths SDK without touching the filesystem. This is the only place where
# seed material hits disk, and the temp directory is cleaned up on exit.
NODE1_SEED="$DEMO_DIR/node1.seed"
NODE2_SEED="$DEMO_DIR/node2.seed"
echo -n "$NODE1_SEED_HEX" | xxd -r -p > "$NODE1_SEED"
echo -n "$NODE2_SEED_HEX" | xxd -r -p > "$NODE2_SEED"

info "Initializing Radicle node 1..."
RAD_HOME="$RAD_NODE1_HOME" RAD_KEYGEN_SEED="$NODE1_SEED_HEX" rad auth --alias node1 2>&1 | sed 's/^/    /' || true

info "Initializing Radicle node 2..."
RAD_HOME="$RAD_NODE2_HOME" RAD_KEYGEN_SEED="$NODE2_SEED_HEX" rad auth --alias node2 2>&1 | sed 's/^/    /' || true

# Extract DIDs — rad self --did outputs did:key:z6Mk... on stdout
NODE1_DID=$(RAD_HOME="$RAD_NODE1_HOME" rad self --did 2>/dev/null | tr -d '[:space:]')
NODE2_DID=$(RAD_HOME="$RAD_NODE2_HOME" rad self --did 2>/dev/null | tr -d '[:space:]')

assert_ok "node 1 DID is not empty" test -n "$NODE1_DID"
assert_ok "node 2 DID is not empty" test -n "$NODE2_DID"

# Derive NIDs (z6Mk...) from DIDs for rad node connect
NODE1_NID="${NODE1_DID#did:key:}"
NODE2_NID="${NODE2_DID#did:key:}"

info "Node 1 DID: $NODE1_DID"
info "Node 2 DID: $NODE2_DID"

assert_ok "node 1 seed is 32 bytes" test "$(wc -c < "$NODE1_SEED" | tr -d ' ')" -eq 32
assert_ok "node 2 seed is 32 bytes" test "$(wc -c < "$NODE2_SEED" | tr -d ' ')" -eq 32

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 2 — Create Auths identity
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 2: Create Auths identity"

# Metadata file for the identity
cat > "$DEMO_DIR/metadata.json" <<'METAJSON'
{
  "xyz.radicle.project": {
    "name": "e2e-radicle-demo"
  },
  "profile": {
    "name": "Radicle E2E Tester"
  }
}
METAJSON

info "Creating identity (RIP-X layout is the default)..."
CREATE_OUTPUT=$("$AUTHS_BIN" --repo "$AUTHS_HOME" id create \
    --metadata-file "$DEMO_DIR/metadata.json" \
    --local-key-alias identity-key \
    2>&1) || true
echo "$CREATE_OUTPUT" | sed 's/^/    /'

# Extract Controller DID from create output, fall back to id show
CONTROLLER_DID=$(echo "$CREATE_OUTPUT" | grep 'Controller DID:' | head -1 | awk -F': ' '{print $NF}' | tr -d '[:space:]')
if [ -z "$CONTROLLER_DID" ]; then
    ID_SHOW_OUTPUT=$("$AUTHS_BIN" --repo "$AUTHS_HOME" id show 2>&1 || true)
    CONTROLLER_DID=$(echo "$ID_SHOW_OUTPUT" | grep 'Controller DID' | head -1 | awk -F': ' '{print $NF}' | tr -d '[:space:]')
fi

assert_ok "controller DID is not empty" test -n "$CONTROLLER_DID"
info "Controller DID: $CONTROLLER_DID"

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 3 — Link device 1 (Radicle node 1)
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 3: Link device 1 (Radicle node 1)"

info "Importing node 1 seed into auths keychain..."
IMPORT1_OUTPUT=$("$AUTHS_BIN" key import \
    --alias node1-key \
    --seed-file "$NODE1_SEED" \
    --controller-did "$CONTROLLER_DID" \
    2>&1) || { echo "$IMPORT1_OUTPUT" | sed 's/^/    /'; phase_fail "key import node1"; exit 1; }
echo "$IMPORT1_OUTPUT" | sed 's/^/    /'

info "Linking node 1 as a device..."
LINK1_OUTPUT=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device link \
    --identity-key-alias identity-key \
    --device-key-alias node1-key \
    --device-did "$NODE1_DID" \
    --note "Radicle Node 1" \
    2>&1) || { echo "$LINK1_OUTPUT" | sed 's/^/    /'; phase_fail "device link node1"; exit 1; }
echo "$LINK1_OUTPUT" | sed 's/^/    /'

# Verify device 1 appears in the list
DEVICE_LIST=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device list 2>/dev/null || true)
assert_contains "device list contains node 1 DID" "$DEVICE_LIST" "$NODE1_DID"

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 4 — Link device 2 (Radicle node 2)
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 4: Link device 2 (Radicle node 2)"

info "Importing node 2 seed into auths keychain..."
IMPORT2_OUTPUT=$("$AUTHS_BIN" key import \
    --alias node2-key \
    --seed-file "$NODE2_SEED" \
    --controller-did "$CONTROLLER_DID" \
    2>&1) || { echo "$IMPORT2_OUTPUT" | sed 's/^/    /'; phase_fail "key import node2"; exit 1; }
echo "$IMPORT2_OUTPUT" | sed 's/^/    /'

info "Linking node 2 as a device..."
LINK2_OUTPUT=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device link \
    --identity-key-alias identity-key \
    --device-key-alias node2-key \
    --device-did "$NODE2_DID" \
    --note "Radicle Node 2" \
    --capabilities sign_commit \
    2>&1) || { echo "$LINK2_OUTPUT" | sed 's/^/    /'; phase_fail "device link node2"; exit 1; }
echo "$LINK2_OUTPUT" | sed 's/^/    /'

# Verify both devices appear
DEVICE_LIST=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device list 2>/dev/null || true)
assert_contains "device list contains node 1" "$DEVICE_LIST" "$NODE1_DID"
assert_contains "device list contains node 2" "$DEVICE_LIST" "$NODE2_DID"

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 5 — Create a Radicle project (from node 1)
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 5: Create a Radicle project"

PROJECT_DIR="$DEMO_DIR/e2e-project"
mkdir -p "$PROJECT_DIR"

info "Initializing git repo and Radicle project..."
(
    cd "$PROJECT_DIR"
    git init --quiet
    git config user.name "E2E Tester"
    git config user.email "e2e@test.local"
    git config commit.gpgsign false
    echo "# Radicle E2E Test Project" > README.md
    git add README.md
    git commit -m "init" --quiet
    RAD_HOME="$RAD_NODE1_HOME" rad init --name e2e-test-project --description "E2E test" --default-branch main --public --no-confirm 2>&1 | sed 's/^/    /' || true
)

assert_ok "project directory exists" test -d "$PROJECT_DIR/.git"

# Extract the Repository ID (RID) for later use
PROJECT_RID=$(cd "$PROJECT_DIR" && RAD_HOME="$RAD_NODE1_HOME" rad inspect --rid 2>/dev/null | tr -d '[:space:]') || true
if [ -n "$PROJECT_RID" ]; then
    info "Radicle project RID: $PROJECT_RID"
else
    info "Could not extract RID (rad init may have partially failed)"
fi
echo -e "  ${GREEN}✓${NC} Radicle project created"

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 6 — Verify both devices are authorized
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 6: Verify both devices are authorized"

DEVICE_LIST=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device list 2>/dev/null || true)

info "Device list output:"
echo "$DEVICE_LIST" | sed 's/^/    /'

assert_contains "node 1 is active" "$DEVICE_LIST" "$NODE1_DID"
assert_contains "node 2 is active" "$DEVICE_LIST" "$NODE2_DID"

# Count active devices (each DID line = 1 device)
DEVICE_COUNT=$(echo "$DEVICE_LIST" | grep -c "did:key:" || true)
assert_ok "exactly 2 devices listed" test "$DEVICE_COUNT" -eq 2

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 6b — Verify storage layout
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 6b: Verify storage layout"

# The CLI stores all state under a single packed ref: refs/auths/registry
# Identity, attestations, and KEL events are tree paths within that ref.
info "Checking packed registry ref..."
REGISTRY_REF_EXISTS=$(git -C "$AUTHS_HOME" show-ref refs/auths/registry 2>/dev/null || true)
assert_ok "refs/auths/registry exists" test -n "$REGISTRY_REF_EXISTS"

info "Checking device attestation entries in registry tree..."
# Sanitized DID format: did_key_z6Mk... (non-alphanumeric replaced with underscores)
NODE1_SANITIZED=$(echo "$NODE1_DID" | sed 's/[^a-zA-Z0-9]/_/g')
NODE2_SANITIZED=$(echo "$NODE2_DID" | sed 's/[^a-zA-Z0-9]/_/g')

# List the full registry tree to find device entries
REGISTRY_TREE=$(git -C "$AUTHS_HOME" ls-tree -r --name-only refs/auths/registry 2>/dev/null || true)

assert_contains "node 1 device entry in registry" "$REGISTRY_TREE" "$NODE1_SANITIZED"
assert_contains "node 2 device entry in registry" "$REGISTRY_TREE" "$NODE2_SANITIZED"

info "Resolving device 1 DID to controller..."
RESOLVED_DID_1=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device resolve --device-did "$NODE1_DID" 2>/dev/null | tr -d '[:space:]')
if [ "$RESOLVED_DID_1" = "$CONTROLLER_DID" ]; then
    echo -e "  ${GREEN}✓${NC} Device 1 resolves to controller DID"
else
    echo -e "  ${RED}✗${NC} Device 1 resolved to '$RESOLVED_DID_1', expected '$CONTROLLER_DID'"
    phase_fail "device 1 resolution mismatch"
    exit 1
fi

info "Resolving device 2 DID to controller..."
RESOLVED_DID_2=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device resolve --device-did "$NODE2_DID" 2>/dev/null | tr -d '[:space:]')
if [ "$RESOLVED_DID_2" = "$CONTROLLER_DID" ]; then
    echo -e "  ${GREEN}✓${NC} Device 2 resolves to controller DID"
else
    echo -e "  ${RED}✗${NC} Device 2 resolved to '$RESOLVED_DID_2', expected '$CONTROLLER_DID'"
    phase_fail "device 2 resolution mismatch"
    exit 1
fi

if [ "$RESOLVED_DID_1" = "$RESOLVED_DID_2" ]; then
    echo -e "  ${GREEN}✓${NC} Both devices resolve to the same controller identity"
else
    echo -e "  ${RED}✗${NC} Devices resolved to different identities"
    phase_fail "identity mismatch between devices"
    exit 1
fi

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 7 — Push patches from both devices
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 7: Push patches from both devices"

PHASE7_OK=true

if [ -z "$PROJECT_RID" ]; then
    info "Skipping — no RID (rad init did not complete in Phase 5)"
    phase_fail "no RID available"
    PHASE7_OK=false
else
    # Use high ports to avoid conflicts with a running personal Radicle node (default 8776)
    E2E_PORT1=19876
    E2E_PORT2=19877

    # Start node 1
    info "Starting Radicle node 1 (port $E2E_PORT1)..."
    RAD_HOME="$RAD_NODE1_HOME" rad node start -- --listen 0.0.0.0:$E2E_PORT1 2>&1 | sed 's/^/    /' || true
    sleep 2

    # Start node 2
    info "Starting Radicle node 2 (port $E2E_PORT2)..."
    RAD_HOME="$RAD_NODE2_HOME" rad node start -- --listen 0.0.0.0:$E2E_PORT2 2>&1 | sed 's/^/    /' || true
    sleep 2

    # Connect node 2 to node 1
    info "Connecting node 2 to node 1..."
    RAD_HOME="$RAD_NODE2_HOME" rad node connect "$NODE1_NID@127.0.0.1:$E2E_PORT1" --timeout 10 2>&1 | sed 's/^/    /' || true
    sleep 1

    # Connect both nodes to permissive public seeds (rosa & iris)
    # seed.radicle.xyz is SELECTIVE (Radicle team repos only) — will not host our project.
    # rosa.radicle.xyz and iris.radicle.xyz are PERMISSIVE (seed all public repos).
    ROSA_NID="z6Mkmqogy2qEM2ummccUthFEaaHvyYmYBYh3dbe9W4ebScxo"
    info "Connecting both nodes to permissive public seeds..."
    RAD_HOME="$RAD_NODE1_HOME" rad node connect "${ROSA_NID}@rosa.radicle.xyz:8776" --timeout 10 2>&1 | sed 's/^/    /' || true
    RAD_HOME="$RAD_NODE2_HOME" rad node connect "${ROSA_NID}@rosa.radicle.xyz:8776" --timeout 10 2>&1 | sed 's/^/    /' || true

    # Seed the project on node 1 (should already be seeded from rad init)
    RAD_HOME="$RAD_NODE1_HOME" rad seed "$PROJECT_RID" 2>/dev/null || true

    # ── Device 1: push a patch ────────────────────────────────────────────
    info "Device 1: creating a feature branch and pushing a patch..."
    PUSH1_OUTPUT=$(
        cd "$PROJECT_DIR"
        export RAD_HOME="$RAD_NODE1_HOME"
        git checkout -b feature-device1 2>/dev/null
        echo "Change from device 1" >> README.md
        git add README.md
        git commit -m "Feature from device 1" --quiet
        git push rad HEAD:refs/patches 2>&1
    ) || true
    echo "$PUSH1_OUTPUT" | sed 's/^/    /'

    # Extract patch ID from push output ("Patch <hex> opened")
    PATCH1_ID=$(echo "$PUSH1_OUTPUT" | grep -oE 'Patch [0-9a-f]{40} opened' | awk '{print $2}') || true

    if [ -n "$PATCH1_ID" ]; then
        PATCH1_URL="https://app.radicle.xyz/nodes/rosa.radicle.xyz/${PROJECT_RID}/patches/${PATCH1_ID}"
        echo -e "  ${GREEN}✓${NC} Device 1 patch created: ${CYAN}${PATCH1_ID}${NC}"
        echo -e "    ${DIM}URL: ${PATCH1_URL}${NC}"
    else
        echo -e "  ${YELLOW}⚠${NC} Could not extract device 1 patch ID"
    fi

    # ── Device 2: clone and push a patch ──────────────────────────────────
    info "Device 2: cloning project and pushing a patch..."
    NODE2_PROJECT="$DEMO_DIR/e2e-project-node2"

    RAD_HOME="$RAD_NODE2_HOME" rad clone "$PROJECT_RID" "$NODE2_PROJECT" --seed "$NODE1_NID" --timeout 15 2>&1 | sed 's/^/    /' || true

    if [ -d "$NODE2_PROJECT" ]; then
        PUSH2_OUTPUT=$(
            cd "$NODE2_PROJECT"
            export RAD_HOME="$RAD_NODE2_HOME"
            git config user.name "E2E Tester Node2"
            git config user.email "e2e-node2@test.local"
            git config commit.gpgsign false
            git checkout -b feature-device2 2>/dev/null
            echo "Change from device 2" >> README.md
            git add README.md
            git commit -m "Feature from device 2" --quiet
            git push rad HEAD:refs/patches 2>&1
        ) || true
        echo "$PUSH2_OUTPUT" | sed 's/^/    /'

        # Extract patch ID from push output
        PATCH2_ID=$(echo "$PUSH2_OUTPUT" | grep -oE 'Patch [0-9a-f]{40} opened' | awk '{print $2}') || true

        if [ -n "$PATCH2_ID" ]; then
            PATCH2_URL="https://app.radicle.xyz/nodes/rosa.radicle.xyz/${PROJECT_RID}/patches/${PATCH2_ID}"
            echo -e "  ${GREEN}✓${NC} Device 2 patch created: ${CYAN}${PATCH2_ID}${NC}"
            echo -e "    ${DIM}URL: ${PATCH2_URL}${NC}"
        else
            echo -e "  ${YELLOW}⚠${NC} Could not extract device 2 patch ID"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} Node 2 clone failed — skipping device 2 patch"
    fi

    # ── Sync to permissive public seeds (best effort) ───────────────────
    # rosa.radicle.xyz and iris.radicle.xyz are permissive — they seed all public repos.
    # seed.radicle.xyz is selective (Radicle team only) and will NOT host our project.
    info "Syncing to rosa.radicle.xyz (best effort)..."
    RAD_HOME="$RAD_NODE1_HOME" rad sync --announce "$PROJECT_RID" --seed "$ROSA_NID" --timeout 15 2>&1 | sed 's/^/    /' || true
    RAD_HOME="$RAD_NODE2_HOME" rad sync --announce "$PROJECT_RID" --seed "$ROSA_NID" --timeout 15 2>&1 | sed 's/^/    /' || true

    # Print summary of patch URLs
    echo ""
    echo -e "  ${BOLD}Patch URLs (rosa.radicle.xyz — permissive public seed):${NC}"
    [ -n "${PATCH1_URL:-}" ] && echo -e "    Device 1: ${CYAN}${PATCH1_URL}${NC}"
    [ -n "${PATCH2_URL:-}" ] && echo -e "    Device 2: ${CYAN}${PATCH2_URL}${NC}"
    echo -e "  ${DIM}Note: URLs require successful sync. If behind NAT, the seed may not be able to fetch from you.${NC}"

    # Verify at least device 1 pushed a patch
    if [ -n "$PATCH1_ID" ]; then
        echo -e "  ${GREEN}✓${NC} At least one patch pushed successfully"
    else
        phase_fail "no patches created"
        PHASE7_OK=false
    fi

    # Stop nodes for subsequent phases
    info "Stopping Radicle nodes..."
    RAD_HOME="$RAD_NODE1_HOME" rad node stop 2>/dev/null || true
    RAD_HOME="$RAD_NODE2_HOME" rad node stop 2>/dev/null || true
fi

if $PHASE7_OK; then
    phase_pass
fi

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 8 — Revoke device 2
# ══════════════════════════════════════════════════════════════════════════════
phase_start "Phase 8: Revoke device 2"

info "Revoking node 2..."
REVOKE_OUTPUT=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device revoke \
    --device-did "$NODE2_DID" \
    --identity-key-alias identity-key \
    --note "E2E revocation test" \
    2>&1) || { echo "$REVOKE_OUTPUT" | sed 's/^/    /'; phase_fail "device revoke node2"; exit 1; }
echo "$REVOKE_OUTPUT" | sed 's/^/    /'

# Without --include-revoked, node 2 should not appear
ACTIVE_DEVICES=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device list 2>/dev/null || true)
assert_contains     "node 1 still active"            "$ACTIVE_DEVICES" "$NODE1_DID"
assert_not_contains "node 2 not in active list"      "$ACTIVE_DEVICES" "$NODE2_DID"

# With --include-revoked, node 2 should appear as revoked
ALL_DEVICES=$("$AUTHS_BIN" --repo "$AUTHS_HOME" device list --include-revoked 2>/dev/null || true)
assert_contains "node 2 shows as revoked" "$ALL_DEVICES" "$NODE2_DID"

info "All-devices list (including revoked):"
echo "$ALL_DEVICES" | sed 's/^/    /'

phase_pass

# ══════════════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}${BOLD}           Radicle Multi-Device E2E — Summary              ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

FAILURES=0
for result in "${PHASE_RESULTS[@]}"; do
    if [[ "$result" == PASS:* ]]; then
        echo -e "  ${GREEN}✓${NC} ${result#PASS: }"
    else
        echo -e "  ${RED}✗${NC} ${result#FAIL: }"
        FAILURES=$((FAILURES + 1))
    fi
done

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All ${#PHASE_RESULTS[@]} phases passed.${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}$FAILURES of ${#PHASE_RESULTS[@]} phases failed.${NC}"
    exit 1
fi
