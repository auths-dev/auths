#!/usr/bin/env bash
# harness/ensure-build-attestation.sh — produce the signed build attestation for
# the released witness image's binary, so a stood-up node can PROVE which binary
# it runs.
#
# This is the operator-side dogfood: the operator (here, the harness) signs the
# exact binary the released image ships, using `auths artifact sign --ci`, and
# pins the resulting `.auths.json`. Standup mounts it into the node
# (`auths witness up --build-attestation`), the node measures its own running
# binary and serves both at `/build`, and `auths witness status` confirms the
# signature holds AND attests the digest the node measured of itself. A forged
# attestation (one over a DIFFERENT binary) is rejected by that digest check.
#
# Producing the attestation over the RELEASED IMAGE'S binary is the whole point:
# the binary the node runs is `/usr/local/bin/auths-witness` inside
# $WITNESS_IMAGE, so we extract THAT exact file and sign it. The node's
# self-measurement of `/proc/self/exe` is byte-identical to it, so a genuine
# attestation matches and a swapped one does not.
#
# Prints the absolute path to the attestation file on stdout. Idempotent: a
# cached attestation for the current image is reused.
set -euo pipefail
. "$(dirname "$0")/env.sh"

WITNESS_IMAGE="${WITNESS_IMAGE:-auths-witness:net-fixture}"
AUTHS_BIN="$SUITE_DIR/bin/auths"
OUT_DIR="$HARNESS_STATE/build-attestation"
ATTESTATION="$OUT_DIR/build.auths.json"
EXTRACTED="$OUT_DIR/auths-witness"

[ -x "$AUTHS_BIN" ] \
    || { echo "no bin/auths — run the suite rebuild first (recurve rebuild network)" >&2; exit 2; }
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "no container engine — cannot extract the image binary to sign" >&2
    exit 2
fi
docker image inspect "$WITNESS_IMAGE" >/dev/null 2>&1 \
    || { echo "witness image absent ($WITNESS_IMAGE) — run harness/ensure-image.sh first" >&2; exit 2; }

mkdir -p "$OUT_DIR"

# Extract the EXACT binary the released image runs (/usr/local/bin/auths-witness,
# per the canonical deployment Dockerfile). docker cp is byte-identical, so the
# node's self-measurement of /proc/self/exe will match this file's digest.
cid="$(docker create "$WITNESS_IMAGE")"
trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$cid:/usr/local/bin/auths-witness" "$EXTRACTED" >/dev/null 2>&1 \
    || { echo "could not extract /usr/local/bin/auths-witness from $WITNESS_IMAGE" >&2; exit 2; }

digest="$(shasum -a 256 "$EXTRACTED" | awk '{print $1}')"

# Reuse a cached attestation iff it already attests this exact binary digest.
if [ -f "$ATTESTATION" ]; then
    cached="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["payload"]["digest"]["hex"])' "$ATTESTATION" 2>/dev/null || true)"
    if [ "$cached" = "$digest" ]; then
        # Absolute path on stdout.
        cd "$OUT_DIR" && printf '%s\n' "$(pwd)/build.auths.json"
        exit 0
    fi
fi

# Dogfood the platform's own CI artifact signer over the released binary.
# --allow-unlogged keeps this a local, offline self-check (no transparency log
# is needed to PROVE which binary runs — the signature + the live self-measured
# digest are sufficient and are what `status` checks).
"$AUTHS_BIN" artifact sign "$EXTRACTED" \
    --ci \
    --commit 0000000000000000000000000000000000000000 \
    --ci-platform local \
    --allow-unlogged \
    --sig-output "$ATTESTATION" >/dev/null 2>&1 \
    || { echo "auths artifact sign --ci failed over the image binary" >&2; exit 2; }

cd "$OUT_DIR" && printf '%s\n' "$(pwd)/build.auths.json"
