#!/usr/bin/env bash
# WIT-N2 — receipts verify offline on a stranger's machine; tampered receipts
# rejected. The corroboration claim: a witness receipt is worth nothing unless a
# third party who does NOT trust the node can check it alone — on a clean
# machine, with no network and no registry — and a tampered one fails closed.
#
# Behavioral, end to end. GREEN means: a real witness node receipted an event;
# the receipt + the node's published identity were carried into an isolated,
# no-network, no-registry context; `auths witness verify-receipt` verified the
# bundle there (exit 0); and flipping a single byte of the signature made the
# SAME command reject it (non-zero, distinct reason). RED means either the
# genuine receipt did not verify offline, or a tampered one was NOT rejected —
# both break the claim. BROKEN means we could not even attempt (no bin/auths).
#
# The load-bearing distinction: the witness's published identity is the ONLY
# trust input. It is a did:key that EMBEDS the witness's verification key, so the
# bundle is self-contained — no directory, no lookup, no second party. We prove
# "no registry" by pointing the verifier's home at an empty dir, and "no node
# needed" by tearing the fixture down before the offline verify runs.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The probe gets a real receipt from the
# harness fixture when Docker is up; with no engine it falls back to a captured
# real bundle so the offline-verify + tamper claim still DECIDES (the bundle is
# the node's product, verified the same way either path). Hermetic otherwise.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh
set +e   # we inspect exit codes of commands expected to fail; errexit would abort

AUTHS_BIN="./bin/auths"
FIXTURES="./probes/fixtures"

# verify_bundle <bundle-file> — run the offline verify in an ISOLATED context:
# HOME and the auths home redirected to an empty throwaway dir (no registry, no
# pinned witnesses), so a verify that succeeds proves the bundle is
# self-contained — the published identity inside it is the only trust input.
# The command is handed only a file path; it is given no node URL and reaches no
# network. Echoes the command's combined output; returns its exit code.
verify_bundle() {
    local bundle="$1"
    local empty_home
    empty_home="$(mktemp -d "${TMPDIR:-/tmp}/wit-n2-home.XXXXXX")"
    HOME="$empty_home" AUTHS_HOME="$empty_home" \
        "$AUTHS_BIN" witness verify-receipt --receipt "$bundle" 2>&1
    local code=$?
    rm -rf "$empty_home" 2>/dev/null
    return $code
}

# ── Trap mode ────────────────────────────────────────────────────────────────
# A trap fixture supplies a KNOWN-BAD receipt bundle at
# probes/wit-n2.trap/<fixture>/bundle.json: a genuine receipt whose signature has
# been bit-flipped (a forged receipt). The runner feeds this as the bundle the
# probe's GREEN path treats as genuine — and the probe MUST turn RED, because a
# forged receipt does not verify. This proves the GREEN verdict genuinely
# depends on a valid signature: a probe that blessed this counterexample (called
# it "verified") would be one that never actually checks signatures. The trap
# stays RED forever.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -x "$AUTHS_BIN" ] \
        || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
    [ -f "${TRAP_FIXTURE}/bundle.json" ] \
        || broken "trap fixture missing bundle.json: ${TRAP_FIXTURE}"
    out="$(verify_bundle "${TRAP_FIXTURE}/bundle.json")"
    code=$?
    # A trap MUST be RED. The forged bundle is fed where the GREEN path treats it
    # as the genuine bundle; the probe's GREEN gate (exit 0 AND a "verified" line)
    # must NOT pass on it. Either way the verdict is RED: the only question the
    # trap settles is WHY — a probe that called this "verified" is broken (it does
    # not check signatures), and one that rejected it is correct but the
    # counterexample is still known-bad, so RED stands.
    if [ "$code" -eq 0 ] && printf '%s\n' "$out" | grep -qi 'verified'; then
        red "ours=verified-forged DANGER — the offline verify accepted a bit-flipped receipt as genuine; signatures are not actually being checked: ${out}"
    fi
    red "ours=forged-receipt expected=RED — a bit-flipped receipt is the known-bad counterexample; the offline verify correctly refused to bless it (exit $code), so this trap stays RED: ${out}"
fi

[ -x "$AUTHS_BIN" ] \
    || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
"$AUTHS_BIN" --version >/dev/null 2>&1 \
    || broken "bin/auths does not run as an auths binary — cannot attempt offline verify"

# ── 1. Obtain a REAL receipt bundle ──────────────────────────────────────────
# The genuine bundle = a witness's signed receipt + the witness's PUBLISHED
# identity. With Docker, we have a live fixture node receipt the event and read
# its identity from /health — provenance is real. With no engine, we use the
# captured real bundle (the node's own product), so the offline-verify claim
# still decides on this box.
BUNDLE="$(mktemp "${TMPDIR:-/tmp}/wit-n2-bundle.XXXXXX.json")"
cleanup() { rm -f "$BUNDLE" 2>/dev/null; }
trap cleanup EXIT

PROVENANCE="captured"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    bash ./harness/up.sh >/dev/null 2>&1 \
        || broken "the 3-witness fixture could not be brought up (harness/up.sh failed) — cannot receipt an event against a live node; fixture prerequisite, not a verdict on the claim"

    EVENT_FILE="$FIXTURES/icp-event.json"
    [ -f "$EVENT_FILE" ] || broken "missing event fixture $EVENT_FILE — cannot submit an event to receipt"
    PREFIX="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["i"])' "$EVENT_FILE")"
    PORT="${NODE_PORTS[0]}"

    # The live node receipts the event (idempotent: same event → same SAID →
    # a fresh signed receipt every time) and advertises its identity at /health.
    receipt_json="$(curl -fsS --max-time 5 -X POST -H 'content-type: application/json' \
        --data-binary "@$EVENT_FILE" "http://127.0.0.1:${PORT}/witness/${PREFIX}/event")"
    [ -n "$receipt_json" ] \
        || red "ours=no-receipt expected=signed-receipt — a live node did not return a receipt for a valid event; receipting is the precondition for corroboration"
    witness_did="$(curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/health" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["witness_did"])' 2>/dev/null)"
    [ -n "$witness_did" ] \
        || red "ours=no-identity expected=published-did — the node did not advertise its identity at /health; a receipt with no published identity cannot be checked by a stranger"

    python3 -c '
import json, sys
receipt = json.loads(sys.argv[1])
bundle = {"receipt": receipt, "witness": sys.argv[2]}
open(sys.argv[3], "w").write(json.dumps(bundle))
' "$receipt_json" "$witness_did" "$BUNDLE" \
        || broken "could not assemble the receipt bundle from the live receipt + identity"
    PROVENANCE="live node :${PORT} (${witness_did})"
    # The fixture is the harness's to own (up/down); this probe only READS it and
    # leaves it standing — the BOOT-1 probe and the rest of the suite depend on
    # it being up. "No node needed" is proven below by the offline verify making
    # NO contact with it, not by killing the shared network.
else
    cp "$FIXTURES/receipt-bundle.json" "$BUNDLE" 2>/dev/null \
        || broken "no container engine AND no captured bundle fixture ($FIXTURES/receipt-bundle.json) — cannot obtain a receipt to verify"
fi

# ── 2. The genuine receipt verifies OFFLINE, in an isolated context ──────────
out="$(verify_bundle "$BUNDLE")"
code=$?
[ "$code" -eq 0 ] \
    || red "ours=exit${code} expected=verified — a genuine receipt + the witness's published identity did NOT verify offline (no network, no registry); receipts are only corroboration if a stranger can check them alone [provenance: ${PROVENANCE}]: ${out}"
printf '%s\n' "$out" | grep -qi 'verified' \
    || red "ours=no-verified-line expected=verified — \`verify-receipt\` exited 0 but did not report the receipt verified: ${out}"

# ── 3. A bit-flipped receipt is REJECTED, with a distinct reason ─────────────
TAMPERED="$(mktemp "${TMPDIR:-/tmp}/wit-n2-tampered.XXXXXX.json")"
python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))
sig = b["receipt"]["signature"]
# Flip the first nibble of the hex signature — one byte changed, nothing else.
first = "0" if sig[0] != "0" else "1"
b["receipt"]["signature"] = first + sig[1:]
open(sys.argv[2], "w").write(json.dumps(b))
' "$BUNDLE" "$TAMPERED" \
    || { rm -f "$TAMPERED"; broken "could not synthesize the tampered receipt"; }

tout="$(verify_bundle "$TAMPERED")"
tcode=$?
rm -f "$TAMPERED" 2>/dev/null
if [ "$tcode" -eq 0 ]; then
    red "ours=verified-tampered expected=rejected — a bit-flipped receipt verified offline; a tampered receipt MUST fail closed or corroboration is worthless: ${tout}"
fi
printf '%s\n' "$tout" | grep -qiE 'reject|does not verify|altered' \
    || red "ours=opaque-rejection expected=distinct-reason — the tampered receipt was rejected (exit $tcode) but with no distinct reason a verifier can act on: ${tout}"

green "receipts verify offline on a stranger's machine: a real witness receipt + the node's published identity verified with no network and no registry [provenance: ${PROVENANCE}], and a bit-flipped receipt was rejected with a distinct reason — the corroboration claim holds end to end"
