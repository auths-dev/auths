#!/usr/bin/env bash
# NET-1 — the relay's HTTP surface stores-and-forwards an opaque envelope off-box.
# GREEN means: `murmur-relay serve-http` accepts a JSON deposit, a drain returns the
# SAME opaque ciphertext exactly once, a byte-identical re-deposit is recognised as a
# replay (idempotent), and a prekey bundle round-trips through the directory. RED means
# the http surface is absent or drops/garbles the round-trip. BROKEN means we could not
# drive the binary at all.
#
# No crypto here on purpose: the relay only ever sees {mailbox, ciphertext}; the
# AUTHENTICATED end-to-end round-trip (seal → deposit → drain → open) is the engine's own
# test (`cargo test -p murmur-relay`, http_round_trip_delivers_an_authenticated_message).
# This probe judges the TRANSPORT — that two separate devices can reach the same mailbox.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/murmur)
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a regression: the http surface absent, or the round-trip leaking
# plaintext / double-delivering. That must be RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'no-http-surface|double-delivered|plaintext-leaked|not built|connection refused'; then
        red "ours=http-round-trip-broken expected=stored-and-forwarded — the relay http surface regressed (\"$(printf '%s' "$out" | head -1)\")"
    fi
    green "the captured http round-trip stored-and-forwarded one opaque envelope exactly once"
fi

command -v curl >/dev/null 2>&1 || broken "curl not available"
relay_ready || broken "no staged bin/murmur-relay — run the suite rebuild first"

# Boot serve-http on an ephemeral port; read the bound address from its banner.
LOG="$(mktemp)"
"$RELAY_BIN" serve-http 127.0.0.1:0 >"$LOG" 2>&1 &
RELAY_PID=$!
trap 'kill "$RELAY_PID" 2>/dev/null' EXIT

BASE=""
for _ in $(seq 1 50); do
    BASE="$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "$LOG" | head -1)"
    [ -n "$BASE" ] && break
    sleep 0.1
done
[ -n "$BASE" ] || broken "serve-http did not report a listen address: $(head -1 "$LOG" 2>/dev/null)"

# The wire is a compact BINARY frame. Build one OuterEnvelope frame by hand:
#   [ver:u8=1][mbx_len:u16=8]["mbx-net1"][ciphertext = 1 2 3 4 5]
# (printf writes the bytes incl. the NUL in mbx_len; pipe to curl --data-binary @-).
build_frame() { printf '\x01\x00\x08mbx-net1\x01\x02\x03\x04\x05'; }
DEP1="$(build_frame | curl -s -X POST "$BASE/deposit" -H 'Content-Type: application/octet-stream' --data-binary @-)"
# The drain response is a length-prefixed binary list; read it as hex.
DRAIN1="$(curl -s "$BASE/drain/mbx-net1" | od -An -tx1 | tr -d ' \n')"
DRAIN2="$(curl -s "$BASE/drain/mbx-net1" | od -An -tx1 | tr -d ' \n')"
DEP2="$(build_frame | curl -s -X POST "$BASE/deposit" -H 'Content-Type: application/octet-stream' --data-binary @-)"
curl -s -X PUT "$BASE/prekey/did:keri:Enet1" --data-binary $'\x09\x08\x07' >/dev/null
PK="$(curl -s "$BASE/prekey/did:keri:Enet1" | od -An -tu1 | tr -s ' ')"

# GREEN requires every leg: deposit queued (JSON outcome); the drain hex carries the
# ciphertext bytes 0102030405; a second drain is the empty list (count=0 → 00000000); a
# re-deposit is deduped; the prekey bytes round-trip.
if printf '%s' "$DEP1"   | grep -q 'queued' \
   && printf '%s' "$DRAIN1" | grep -q '0102030405' \
   && [ "$DRAIN2" = "00000000" ] \
   && printf '%s' "$DEP2"   | grep -q 'deduped_replay' \
   && printf '%s' "$PK"     | grep -q '9 8 7'; then
    green "the relay http surface stored-and-forwarded one opaque binary envelope exactly once, deduped a replay, and round-tripped a prekey bundle"
fi

red "ours=http-round-trip-broken expected=stored-and-forwarded — deposit='${DEP1}' drain='${DRAIN1}' redrain='${DRAIN2}' redeposit='${DEP2}' prekey='${PK}'"
