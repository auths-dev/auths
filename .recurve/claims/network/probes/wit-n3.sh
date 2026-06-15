#!/usr/bin/env bash
# WIT-N3 — the node serves a conformant key-state notice (KSN), cross-verified
# against the pinned keripy oracle, both directions. The wire-conformance claim:
# a thin client can trust an identity's current key-state from the node's notice
# alone, and an implementation we do NOT control (keripy 1.3.4) agrees that
# notice IS a key-state notice — and accepts ours / publishes one we accept.
#
# Behavioral, end to end. GREEN means: a live node, having witnessed a real
# controller inception, serves a KERI-conformant key-state record at a stable
# endpoint; that record reconstructs byte-for-byte inside the keripy oracle
# (node → oracle); a record the keripy oracle publishes ingests on the node
# (oracle → node); AND a stale notice (a lower sequence than a newer state the
# verifier holds) is detected as stale, not silently accepted. RED means any of
# those fails — the wire shape diverged, the oracle rejected it, or staleness
# went undetected. BROKEN means we could not even attempt (no bin/auths, no
# keripy oracle, or the fixture could not stand up).
#
# This extends interop's IOP-L3c (the KSN wire shape, owned and cross-verified
# there) to the RUNNING node: the same oracle, the same versions.lock pin, now
# against a notice a live witness actually served from events it corroborated.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The probe reuses the harness 3-witness
# fixture (up.sh) and leaves it standing for the rest of the suite — it only
# READS the running node, submitting one throwaway controller's events.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh
set +e   # we inspect exit codes of commands expected to fail; errexit would abort

AUTHS_BIN="./bin/auths"
FIXTURES="./probes/fixtures"
ORACLE="./harness/ksn_oracle.py"
EMIT="./harness/ksn_emit.py"

# oracle_present — 0 if the pinned keripy oracle is importable, else non-zero.
# The conformance claim is meaningless without the implementation we compare to.
oracle_present() { python3 -c 'import keri' >/dev/null 2>&1; }

# ── Trap mode ────────────────────────────────────────────────────────────────
# A trap fixture supplies a KNOWN-BAD stale key-state record at
# probes/wit-n3.trap/<fixture>/{ksn.json,last_seen}: a notice at sequence S fed
# to a verifier that already trusts a NEWER state (last_seen > S). The node's
# staleness gate MUST reject it. The probe's GREEN path treats `--reject-stale-
# below` accepting a notice as "fresh"; here it must instead fail closed, so the
# probe turns RED — proving the freshness check genuinely depends on the
# sequence, not a rubber stamp. A verifier that accepted this stale notice would
# trust a rewound, replayed view of the identity. The trap stays RED forever.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -x "$AUTHS_BIN" ] \
        || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
    [ -f "${TRAP_FIXTURE}/ksn.json" ] && [ -f "${TRAP_FIXTURE}/last_seen" ] \
        || broken "trap fixture missing ksn.json/last_seen: ${TRAP_FIXTURE}"
    last_seen="$(cat "${TRAP_FIXTURE}/last_seen")"
    out="$("$AUTHS_BIN" key-state --ingest "${TRAP_FIXTURE}/ksn.json" --reject-stale-below "$last_seen" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then
        red "ours=accepted-stale DANGER — the node ingested a stale key-state notice (seq below last-seen ${last_seen}) as fresh; a rewound/replayed view was trusted: ${out}"
    fi
    printf '%s\n' "$out" | grep -qiE 'stale|reject' \
        || red "ours=opaque-stale-rejection expected=distinct-reason — the stale notice was refused (exit $code) but without a reason a verifier can act on: ${out}"
    red "ours=stale-ksn expected=RED — a stale key-state notice (seq below last-seen ${last_seen}) is the known-bad counterexample; the freshness gate correctly refused it (exit $code), so this trap stays RED: ${out}"
fi

[ -x "$AUTHS_BIN" ] \
    || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
"$AUTHS_BIN" --version >/dev/null 2>&1 \
    || broken "bin/auths does not run as an auths binary — cannot attempt the KSN conformance check"
oracle_present \
    || broken "the pinned keripy oracle ($(oracle_version)) is not importable (python3 -c 'import keri') — the KSN conformance claim has no oracle to compare against; install it (see harness/versions.lock)"

# ── 1. A live node witnesses a real controller inception ─────────────────────
# The node can only notice a key-state it actually saw. We need a live fixture
# node and a full, conformant inception for it to witness, then serve.
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
    || broken "no container engine — the KSN claim is about a RUNNING node serving a notice; without a live node there is nothing to cross-verify (fixture prerequisite, not a verdict)"

bash ./harness/up.sh >/dev/null 2>&1 \
    || broken "the 3-witness fixture could not be brought up (harness/up.sh failed) — cannot have a live node witness an event; fixture prerequisite, not a verdict on the claim"

EVENT_FILE="$FIXTURES/keri-icp.json"
[ -f "$EVENT_FILE" ] || broken "missing event fixture $EVENT_FILE — cannot submit a conformant inception to witness"
PREFIX="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["i"])' "$EVENT_FILE")"
PORT="${NODE_PORTS[0]}"
NODE="http://127.0.0.1:${PORT}"

# The live node witnesses the inception (idempotent — first-seen wins; re-runs of
# this probe re-submit the same event and get the same receipt).
receipt_json="$(curl -fsS --max-time 5 -X POST -H 'content-type: application/json' \
    --data-binary "@$EVENT_FILE" "${NODE}/witness/${PREFIX}/event")"
[ -n "$receipt_json" ] \
    || red "ours=no-receipt expected=witnessed — a live node did not witness a valid conformant inception; it cannot notice a key-state it never saw"

# ── 2. The node serves a key-state notice for the identity it witnessed ──────
ksn="$(curl -fsS --max-time 5 "${NODE}/witness/${PREFIX}/key-state")"
ksn_code=$?
[ "$ksn_code" -eq 0 ] && [ -n "$ksn" ] \
    || red "ours=no-ksn-endpoint expected=served-notice — the node did not serve a key-state notice at /witness/${PREFIX}/key-state (curl exit $ksn_code); a thin client has nothing to trust"

# The served record must be the KERI ksn wire shape, not the auths-internal
# envelope — labels and order are the conformance surface.
fields="$(printf '%s' "$ksn" | python3 -c 'import json,sys;print(",".join(json.load(sys.stdin).keys()))' 2>/dev/null)"
expected="vn,i,s,p,d,f,dt,et,kt,k,nt,n,bt,b,c,ee,di"
[ "$fields" = "$expected" ] \
    || red "ours=fields:[${fields}] expected=[${expected}] — the served notice is not the KERI ksn wire record shape; a peer cannot read it"

# ── 3. node → oracle: keripy agrees the node's notice IS a key-state notice ──
oracle_out="$(printf '%s' "$ksn" | python3 "$ORACLE" 2>&1)"
oracle_code=$?
[ "$oracle_code" -eq 0 ] && printf '%s\n' "$oracle_out" | grep -q 'ORACLE-OK' \
    || red "ours=oracle-rejected expected=ORACLE-OK — the keripy oracle ($(oracle_version)) did not reconstruct the node's served key-state record (the node's notice is not conformant): ${oracle_out}"

# ── 4. oracle → node: the node ingests a notice the keripy oracle published ──
ORACLE_KSN="$(mktemp "${TMPDIR:-/tmp}/wit-n3-oracle.XXXXXX.json")"
cleanup() { rm -f "$ORACLE_KSN" 2>/dev/null; }
trap cleanup EXIT
python3 "$EMIT" > "$ORACLE_KSN" 2>/dev/null \
    || broken "the keripy oracle emitter ($EMIT) failed — cannot test the oracle→node direction"
ingest_out="$("$AUTHS_BIN" key-state --ingest "$ORACLE_KSN" 2>&1)"
ingest_code=$?
[ "$ingest_code" -eq 0 ] \
    || red "ours=ingest-failed expected=accepted — the node could not ingest a key-state notice the keripy oracle published; the wire shape is not bidirectionally interoperable: ${ingest_out}"

# ── 5. adversarial twin: a stale notice is detected as stale ─────────────────
# A verifier holding a NEWER state (here: one sequence past the served notice)
# must refuse to rewind to the node's (now stale) notice. We re-present the
# oracle's seq-0 notice while claiming to already trust seq 1 — staleness must
# fire, with a distinct reason, never a silent accept.
served_seq_hex="$(printf '%s' "$ksn" | python3 -c 'import json,sys;print(json.load(sys.stdin)["s"])' 2>/dev/null)"
served_seq="$((16#${served_seq_hex:-0}))"
newer_hex="$(printf '%x' "$((served_seq + 1))")"
stale_out="$("$AUTHS_BIN" key-state --ingest "$ORACLE_KSN" --reject-stale-below "$newer_hex" 2>&1)"
stale_code=$?
if [ "$stale_code" -eq 0 ]; then
    red "ours=accepted-stale expected=rejected — a verifier holding a newer state ingested a stale (seq below ${newer_hex}) notice as fresh; a rewound view must be detected, not trusted: ${stale_out}"
fi
printf '%s\n' "$stale_out" | grep -qiE 'stale|reject' \
    || red "ours=opaque-stale expected=distinct-reason — the stale notice was refused (exit $stale_code) but without a reason a verifier can act on: ${stale_out}"

green "the node serves a conformant key-state notice: a live node witnessed a real inception and served a KERI ksn wire record that the keripy oracle ($(oracle_version)) reconstructs byte-for-byte (node→oracle), the node ingests a notice the oracle publishes (oracle→node), and a stale notice is detected as stale — IOP-L3c's wire conformance now holds against the running node"
