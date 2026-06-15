#!/usr/bin/env bash
# AGENT-ATTEN-4 — a worker cannot borrow a sibling org's authority. The verifier
# derives the root from the AUTHENTICATED device dip's delegator (the worker's
# real parent), never the self-asserted Auths-Id trailer — so a worker delegated
# under org A cannot re-label its commit to claim sibling org B and have it
# honored under B. GREEN means: the worker's commit verifies (status=valid) and
# the verdict's `signer` is the WORKER's own delegated identity (the authenticated
# dip), i.e. the root the commit is judged under is derived from that dip, not a
# trailer a worker could repoint. RED means the verdict is attributed to a signer
# OTHER than the authenticated worker (a borrowed identity slipped through).
# BROKEN means we could not build the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verdict whose `signer` is a SIBLING org's identity (B) —
# the "borrowed authority" outcome the derivation forbids: a worker of A getting a
# commit honored as B. A verdict attributed to the foreign B is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/verify.json" ] && [ -f "${TRAP_FIXTURE}/true-worker.did" ] \
        || broken "trap fixture missing verify.json/true-worker.did: ${TRAP_FIXTURE}"
    signer="$(grep -oE '"signer"[[:space:]]*:[[:space:]]*"[^"]*"' "${TRAP_FIXTURE}/verify.json" \
              | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/')"
    true_worker="$(cat "${TRAP_FIXTURE}/true-worker.did")"
    if [ -n "$signer" ] && [ "$signer" != "$true_worker" ]; then
        red "ours=signer:${signer} expected=authenticated-worker:${true_worker} — the verdict is attributed to a foreign (sibling-org) identity, not the authenticated worker dip; a worker borrowed another root's authority"
    fi
    green "captured verdict is attributed to the authenticated worker, not a borrowed sibling root — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or auths-sign) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/atten4.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org org)"
[ -n "$ORG_DID" ] || broken "could not establish the org root identity (A)"
ORG_PFX="${ORG_DID#did:keri:}"

WORKER_DID="$(delegate_worker committer org sign_commit)"
[ -n "$WORKER_DID" ] || broken "could not delegate the worker under org A"

materialize_worker_machine "$ORG_PFX"
worker_env committer

IN_SHA="$(worker_signs_commit "$LAB/work" "work under A" sign_commit)"
[ -n "$IN_SHA" ] || broken "the worker could not sign a commit"

org_env
JSON="$(cd "$LAB/work" && "$AUTHS_BIN" --repo "$ORG_REPO" --json verify "$IN_SHA" 2>/dev/null)"
STATUS="$(printf '%s' "$JSON" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/')"
SIGNER="$(printf '%s' "$JSON" | grep -oE '"signer"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/')"

[ "$STATUS" = "valid" ] \
    || red "ours=status:${STATUS:-none} expected=valid — the worker's own commit under its true root A did not verify; cannot assert the wrong-root property when the true-root accept fails"

# The verdict must be attributed to the AUTHENTICATED worker dip — the proof the
# root is derived from that dip and not a self-asserted, repointable trailer.
if [ "$SIGNER" = "$WORKER_DID" ]; then
    green "the verdict is attributed to the authenticated worker dip ($SIGNER), so the judged root is derived from that dip — a worker cannot repoint Auths-Id to borrow a sibling org's authority"
fi
red "ours=signer:${SIGNER:-none} expected=${WORKER_DID} — the verdict's signer is not the authenticated worker; the root may be taken from a self-asserted trailer rather than the authenticated dip"
