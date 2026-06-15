#!/usr/bin/env bash
# WIT-N4 — the node proves which binary it runs. An operator vouches for the
# network; the operator must in turn be vouchable. This probe checks that a
# running node exposes a SIGNED version+digest build attestation and that
# `auths witness status` verifies it — and rejects a forged one.
#
# Behavioral, end to end. GREEN means: a live node serves a build proof pairing
# its own self-measurement of the binary it runs with the signed attestation the
# operator produced over the released binary (dogfooding `auths artifact sign
# --ci`); `auths witness status` confirms the signature holds AND attests the
# digest the node measured of itself (exit 0); AND a FORGED attestation — one
# whose signature is valid but attests a DIFFERENT binary — is rejected by the
# SAME `status` command (non-zero, distinct reason). RED means either the
# genuine build did not verify, or the forged one was accepted — both break the
# claim. BROKEN means we could not even attempt (no bin/auths, no engine,
# fixture/standup prerequisite unmet).
#
# The load-bearing distinction: a valid signature is NOT enough. The attestation
# must attest the digest of the binary actually running. A forger who attaches a
# perfectly-signed attestation for a different binary is caught because the node
# measures /proc/self/exe and `status` checks attested == self-measured. That
# digest check is what converts "signed something" into "proves THIS binary".
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The probe stands up its OWN throwaway
# node (free port + throwaway data dir) with a build attestation the harness
# produced over the released image's binary, then tears that node down on exit
# (hermetic — leaves the shared fixture untouched).
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh
set +e   # we inspect exit codes of commands expected to fail; errexit would abort

AUTHS_BIN="./bin/auths"

# ── Trap mode ────────────────────────────────────────────────────────────────
# A trap fixture supplies a KNOWN-BAD build attestation at
# probes/wit-n4.trap/<fixture>/forged.auths.json: a genuinely-signed attestation
# whose attested digest is NOT the digest of the binary the node runs (it was
# signed over a different artifact). The runner stands a node up with THIS
# attestation injected where the GREEN path injects the genuine one — and the
# probe MUST turn RED, because `status` must reject a node whose attestation is
# for a different binary. A probe that called this "verified" would be one whose
# digest check is cosmetic. The trap stays RED forever.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -x "$AUTHS_BIN" ] \
        || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
    [ -f "${TRAP_FIXTURE}/forged.auths.json" ] \
        || broken "trap fixture missing forged.auths.json: ${TRAP_FIXTURE}"
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
        || broken "no container engine — the trap stands a node up with a forged attestation; without a live node there is nothing to reject"
    bash ./harness/ensure-image.sh >/dev/null 2>&1 \
        || broken "the witness node image could not be made present — cannot stand the trap node up"

    PORT="${WIT_N4_TRAP_PORT:-3347}"
    DATA="$(mktemp -d "${TMPDIR:-/tmp}/wit-n4-trap.XXXXXX")"
    trap_cleanup() {
        "$AUTHS_BIN" witness down --port "$PORT" --data-dir "$DATA" >/dev/null 2>&1
        rm -rf "$DATA" 2>/dev/null
    }
    trap trap_cleanup EXIT
    "$AUTHS_BIN" witness up --port "$PORT" --data-dir "$DATA" \
        --image "$WITNESS_IMAGE" --build-attestation "${TRAP_FIXTURE}/forged.auths.json" \
        >/dev/null 2>&1 \
        || broken "could not stand a node up with the forged attestation injected — cannot exercise the trap"
    out="$("$AUTHS_BIN" witness status --port "$PORT" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ] && printf '%s\n' "$out" | grep -qi 'build verified'; then
        red "ours=verified-forged DANGER — \`status\` accepted a node whose build attestation is for a DIFFERENT binary; the digest check is cosmetic and a node can lie about what it runs: ${out}"
    fi
    red "ours=forged-attestation expected=RED — an attestation over a different binary is the known-bad counterexample; \`status\` correctly refused to verify it (exit $code), so this trap stays RED: $(printf '%s' "$out" | tail -1)"
fi

[ -x "$AUTHS_BIN" ] \
    || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
"$AUTHS_BIN" --version >/dev/null 2>&1 \
    || broken "bin/auths does not run as an auths binary — cannot attempt the build-attestation check"

# The claim is about a RUNNING node serving a build proof; without an engine
# there is no node to serve one. Fixture prerequisite, not a verdict.
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
    || broken "no container engine — the build-attestation claim is about a RUNNING node; without a live node there is nothing to verify (fixture prerequisite, not a verdict)"

# The released image must be present (the node runs it). Acquisition is the
# harness's job, never the probe's or `up`'s (WIT-B4).
bash ./harness/ensure-image.sh >/dev/null 2>&1 \
    || broken "the witness node image could not be made present (harness/ensure-image.sh) — cannot stand a node up to check its build proof"

# The operator-side dogfood: the harness signs the released image's binary with
# `auths artifact sign --ci` and pins the attestation. Producing it is the
# operator's job (the harness here), exactly as image acquisition is.
ATTESTATION="$(bash ./harness/ensure-build-attestation.sh 2>/dev/null)"
[ -n "$ATTESTATION" ] && [ -f "$ATTESTATION" ] \
    || broken "could not produce the signed build attestation for the image binary (harness/ensure-build-attestation.sh) — cannot stand a node up that proves its binary"

# ── Stand up this probe's own node, with the genuine attestation injected ─────
PORT="${WIT_N4_PORT:-3346}"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wit-n4.XXXXXX")"
cleanup() {
    "$AUTHS_BIN" witness down --port "$PORT" --data-dir "$DATA_DIR" >/dev/null 2>&1
    rm -rf "$DATA_DIR" 2>/dev/null
}
trap cleanup EXIT

"$AUTHS_BIN" witness up --port "$PORT" --data-dir "$DATA_DIR" \
    --image "$WITNESS_IMAGE" --build-attestation "$ATTESTATION" >/dev/null 2>&1 \
    || broken "the node did not stand up with the genuine build attestation injected — standup prerequisite, not a verdict on the claim"

# ── 1. The node serves a build proof at a stable endpoint ────────────────────
build_json="$(curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/build")"
build_code=$?
[ "$build_code" -eq 0 ] && [ -n "$build_json" ] \
    || red "ours=no-build-endpoint expected=served-proof — the node did not serve a build attestation at /build (curl exit $build_code); a node that cannot say which binary it runs cannot be vouched for"

# The proof must pair the node's OWN self-measurement with a signed attestation —
# the two fields the digest check needs.
printf '%s' "$build_json" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["running_digest"] and d["attestation"]["payload"]["digest"]["hex"]' 2>/dev/null \
    || red "ours=malformed-build expected=self-measure+attestation — the build proof did not carry both a self-measured running digest and a signed attestation; the digest check has nothing to compare"

# ── 2. `status` verifies the genuine build (signature holds AND digest matches) ─
status_out="$("$AUTHS_BIN" witness status --port "$PORT" 2>&1)"
status_code=$?
[ "$status_code" -eq 0 ] \
    || red "ours=exit${status_code} expected=verified — \`witness status\` did not verify the node's genuine build attestation; a node running exactly what it attests must verify: $(printf '%s' "$status_out" | tail -1)"
printf '%s\n' "$status_out" | grep -qi 'build verified' \
    || red "ours=no-build-verified-line expected=verified — \`status\` exited 0 but did not report the build verified: ${status_out}"

# ── 3. A FORGED attestation (valid signature, WRONG binary) is REJECTED ───────
# Sign a DIFFERENT artifact: a perfectly-valid attestation whose attested digest
# is not the digest of the running binary. Stand a second node up with it and
# confirm `status` refuses — the forgery the whole claim exists to catch.
FORGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wit-n4-forge.XXXXXX")"
FORGE_PORT="${WIT_N4_FORGE_PORT:-3348}"
forge_cleanup() {
    "$AUTHS_BIN" witness down --port "$FORGE_PORT" --data-dir "$FORGE_DIR" >/dev/null 2>&1
    rm -rf "$FORGE_DIR" 2>/dev/null
}
printf 'a binary this node is NOT running' > "$FORGE_DIR/other.bin"
"$AUTHS_BIN" artifact sign "$FORGE_DIR/other.bin" --ci \
    --commit 0000000000000000000000000000000000000000 --ci-platform local \
    --allow-unlogged --sig-output "$FORGE_DIR/forged.auths.json" >/dev/null 2>&1 \
    || { forge_cleanup; broken "could not synthesize a forged (different-binary) attestation to test rejection"; }

"$AUTHS_BIN" witness up --port "$FORGE_PORT" --data-dir "$FORGE_DIR" \
    --image "$WITNESS_IMAGE" --build-attestation "$FORGE_DIR/forged.auths.json" >/dev/null 2>&1 \
    || { forge_cleanup; broken "could not stand a node up with the forged attestation to test rejection"; }

forged_out="$("$AUTHS_BIN" witness status --port "$FORGE_PORT" 2>&1)"
forged_code=$?
forge_cleanup
if [ "$forged_code" -eq 0 ]; then
    red "ours=verified-forged expected=rejected — \`status\` accepted a node whose attestation is for a DIFFERENT binary; the node could be running anything and still claim a green build: ${forged_out}"
fi
printf '%s\n' "$forged_out" | grep -qiE 'reject|different binary|not running what it attests' \
    || red "ours=opaque-rejection expected=distinct-reason — the forged build was rejected (exit $forged_code) but with no distinct reason an operator can act on: ${forged_out}"

green "the node proves which binary it runs: a live node served a signed version+digest build attestation, \`witness status\` verified it against the node's own self-measurement of the running binary, and a forged attestation (valid signature over a different binary) was rejected with a distinct reason — an operator vouching for the network is itself vouchable"
