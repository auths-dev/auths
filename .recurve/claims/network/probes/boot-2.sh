#!/usr/bin/env bash
# BOOT-2 — the skeleton builds: the suite's rebuild produces the artifacts the
# probes read, and that build is the FEATURE-ENABLED `auths` (the `auths witness`
# operator verbs with their real node handlers compiled in via the witness-node
# feature), additive over the lean default.
#
# Behavioral, end to end. GREEN means: bin/auths exists and is a real auths
# binary whose `witness` surface carries the operator verbs (up/down/status/
# register/logs); that surface compiles into the DEFAULT build too (thin clap),
# but the node dependency is feature-gated so the default `cargo tree` pulls NO
# auths-witness-node (WIT-B2 additive); and the node crate COMPOSES the platform
# crates rather than reimplementing protocol (WIT-B1).
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The suite's rebuild (recurve [suites.
# network] rebuild → harness/rebuild.sh) produces bin/auths; this probe is
# hermetic and only READS it. `reads: cli` makes recurve refuse to run this
# probe on a stale bin/auths.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh

RECURVE_TOML="$RECURVE_DIR/recurve.toml"
WITNESS_NODE_CRATE="$AUTHS_SRC/crates/auths-witness-node"

# ── Trap mode ────────────────────────────────────────────────────────────────
# A trap fixture supplies a KNOWN-BAD `cargo tree` of the DEFAULT auths-cli build
# at probes/boot-2.trap/<fixture>/default-tree.txt. If that tree pulls
# auths-witness-node, the feature is NOT additive (the node's heavy deps leaked
# into the lean default install) — the additivity check below MUST reject it
# (exit RED). A default build that drags the node crate in is the lean install
# stopped being lean: exactly the regression WIT-B2 exists to catch.
DEFAULT_TREE_SOURCE="live"
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/default-tree.txt" ] \
        || broken "trap fixture has no default-tree.txt: ${TRAP_FIXTURE}"
    DEFAULT_TREE_SOURCE="${TRAP_FIXTURE}/default-tree.txt"
fi

# ── 1. The suite rebuild + freshness rule are wired ──────────────────────────
grep -q 'rebuild = "bash claims/network/harness/rebuild.sh"' "$RECURVE_TOML" \
    || red "recurve.toml [suites.network] rebuild is not wired to harness/rebuild.sh — nothing produces the artifacts probes read"
grep -q '^\[reads.cli\]' "$RECURVE_TOML" \
    || red "recurve.toml has no [reads.cli] freshness rule — a cli probe could run stale"
grep -q 'source = "target/witness-node/release/auths"' "$RECURVE_TOML" \
    || red "[reads.cli] does not source the FEATURE-ENABLED build (target/witness-node/release/auths)"
[ -x ./harness/rebuild.sh ] || red "harness/rebuild.sh missing or not executable — the rebuild command cannot run"

# ── 2. The rebuild produced bin/auths ────────────────────────────────────────
AUTHS_BIN="./bin/auths"
[ -x "$AUTHS_BIN" ] \
    || red "no bin/auths — the suite rebuild has not run (recurve rebuild network → harness/rebuild.sh)"

# ── 3. bin/auths is a real auths binary with the operator verb surface ───────
"$AUTHS_BIN" --version >/dev/null 2>&1 \
    || broken "bin/auths does not run as an auths binary"
help="$("$AUTHS_BIN" witness --help 2>&1 || true)"
for verb in up down status register logs; do
    printf '%s\n' "$help" | grep -qiw "$verb" \
        || red "bin/auths 'witness' surface is missing the operator verb '$verb' — the skeleton CLI is incomplete: ${help}"
done

# ── 4. The witness-node crate exists and COMPOSES the platform crates (WIT-B1) ─
[ -f "$WITNESS_NODE_CRATE/Cargo.toml" ] \
    || red "auths-witness-node crate absent — the feature-gated node crate is the skeleton's core"
for dep in auths-witness auths-keri auths-verifier; do
    grep -q "$dep" "$WITNESS_NODE_CRATE/Cargo.toml" \
        || red "auths-witness-node does not depend on $dep — it must COMPOSE the platform crates, not reimplement them"
done

# ── 5. The feature is ADDITIVE — default cargo tree pulls NO node crate (WIT-B2)
# Live: ask cargo for the DEFAULT auths-cli dependency tree. Trap: read the
# supplied counterexample tree instead.
if [ "$DEFAULT_TREE_SOURCE" = "live" ]; then
    command -v cargo >/dev/null 2>&1 || broken "cargo absent — cannot measure default-build additivity"
    default_tree="$( ( cd "$AUTHS_SRC" && cargo tree -p auths-cli 2>/dev/null ) || true )"
    [ -n "$default_tree" ] || broken "cargo tree -p auths-cli produced nothing — cannot measure additivity"
    feature_tree="$( ( cd "$AUTHS_SRC" && cargo tree -p auths-cli --features witness-node 2>/dev/null ) || true )"
else
    default_tree="$(cat "$DEFAULT_TREE_SOURCE")"
    feature_tree="auths-witness-node"   # the trap only constrains the DEFAULT tree
fi

if printf '%s\n' "$default_tree" | grep -q 'auths-witness-node'; then
    red "default auths-cli build pulls auths-witness-node — the witness-node feature is NOT additive; the lean install stopped being lean (WIT-B2)"
fi
printf '%s\n' "$feature_tree" | grep -q 'auths-witness-node' \
    || red "--features witness-node does NOT pull auths-witness-node — the feature is wired wrong"

green "skeleton builds: bin/auths is the feature-enabled build (witness up/down/status/register/logs present); auths-witness-node composes auths-witness/auths-keri/auths-verifier and is additive (absent from the default cargo tree, present under --features witness-node)"
