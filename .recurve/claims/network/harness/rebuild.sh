#!/usr/bin/env bash
# harness/rebuild.sh — produce the artifacts this suite's probes read.
#
# The probes here read the FEATURE-ENABLED `auths` build: the `auths witness`
# operator verbs with their real handlers compiled in (`--features
# witness-node`). That build is DISTINCT from the lean default `auths` the demos
# read, so it is built into its OWN target dir and copied into the suite's
# bin/auths — the lean `target/release/auths` the demos content-hash against is
# never clobbered by this suite's rebuild.
#
# Mirrors interop/demos: bring-up/build is the harness's job; probes are hermetic
# and only READ the copied artifact. recurve's [reads.cli] content-hash refuses
# to run a probe whose bin/auths drifts from this build output.
set -euo pipefail
. "$(dirname "$0")/env.sh"

SUITE_BIN="$SUITE_DIR/bin"
# The feature-enabled build's own target dir — keeps the lean default build
# (target/release/auths, read by the demos) untouched.
WITNESS_TARGET="$AUTHS_SRC/target/witness-node"

command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust via rustup (https://rustup.rs)"

say "building the feature-enabled auths (--features witness-node) into target/witness-node"
( cd "$AUTHS_SRC" && cargo build --release -p auths-cli --features witness-node \
    --target-dir "$WITNESS_TARGET" )

built="$WITNESS_TARGET/release/auths"
[ -x "$built" ] || die "build produced no auths binary at $built"

mkdir -p "$SUITE_BIN"
cp -f "$built" "$SUITE_BIN/auths"
pass "bin/auths is the feature-enabled build ($(cd "$AUTHS_SRC" && git rev-parse --short HEAD 2>/dev/null || echo local))"
