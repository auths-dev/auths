#!/usr/bin/env bash
# AGENT-ATTEN-1 — a delegated worker's commit REACHES the scope gate through the
# CLI (the end-to-end wiring). GREEN means: an org->worker chain is built with
# real CLI calls, the worker (a dip-rooted delegate) signs an in-scope commit,
# and `auths verify` ACCEPTS it (status=valid) with the worker as device and the
# org root as identity — the verify path replayed the worker's delegated KEL with
# delegator-aware lookup and landed on the scope gate, instead of dying before it
# with "Delegator lookup required". RED means the in-scope commit was not
# accepted (the gate was not reached, or attenuation regressed). BROKEN means we
# could not even build the chain (no staged binary).
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/the-intern-that-couldnt)
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap fixture captures the documented PRE-WIRING failure: a verify run that
# died BEFORE the scope gate with "Delegator lookup required …" (the AGT-1 RED).
# A worker commit that fails on RESOLUTION rather than reaching the gate is the
# regression this probe forbids — RED on it.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/verify.out" ] \
        || broken "trap fixture missing verify.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/verify.out")"
    if printf '%s' "$out" | grep -qiE 'delegator lookup required|failed to replay'; then
        red "ours=died-before-gate expected=reached-scope-gate — the worker commit failed on KEL resolution (\"$(printf '%s' "$out" | head -1)\") instead of being judged by scope; the end-to-end wiring regressed"
    fi
    green "captured verify reached a scope verdict (did not die on resolution) — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or auths-sign) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/atten1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org org)"
[ -n "$ORG_DID" ] || broken "could not establish the org root identity"
ORG_PFX="${ORG_DID#did:keri:}"

WORKER_DID="$(delegate_worker committer org sign_commit)"
[ -n "$WORKER_DID" ] || broken "could not delegate the worker (scope sign_commit)"

materialize_worker_machine "$ORG_PFX"
worker_env committer

IN_SHA="$(worker_signs_commit "$LAB/work-in" "in-scope work" sign_commit)"
[ -n "$IN_SHA" ] || broken "the worker could not sign an in-scope commit"

org_env
STATUS="$(verify_commit_status "$LAB/work-in" "$IN_SHA")"

# The accept verdict is the proof the gate was reached AND the in-scope claim was
# honored. Anything else (a resolution wall, a scope rejection of an in-scope
# claim) is the gap.
if [ "$STATUS" = "valid" ]; then
    green "the worker's in-scope commit reached the scope gate and was accepted (status=valid) — delegator-aware replay landed on the gate, worker=device, org-root=identity"
fi
[ -z "$STATUS" ] \
    && red "ours=no-verdict expected=valid — \`auths verify\` produced no status for the worker's in-scope commit; the verify path did not reach a scope verdict"
red "ours=status:${STATUS} expected=valid — the worker's in-scope commit was not accepted; the end-to-end path did not land an in-scope claim on the gate as accepted"
