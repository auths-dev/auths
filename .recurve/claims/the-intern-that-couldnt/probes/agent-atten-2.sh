#!/usr/bin/env bash
# AGENT-ATTEN-2 — a broadened mid-chain commit is rejected with the DISTINCT
# OutsideAgentScope verdict. GREEN means: the SAME worker holding anchored
# {sign_commit} signs (a) an in-scope commit claiming sign_commit -> accepted, and
# (b) a beyond-scope commit claiming admin -> rejected with status
# `outside-agent-scope` (NOT a signature failure, NOT a generic invalid), despite
# a valid signature and a valid delegation chain. RED means the over-claim was
# not refused by scope (or was refused for the wrong reason). BROKEN means we
# could not build the chain.
#
# The visceral beat: valid signature, still rejected — by containment.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verify run whose verdict is GENERIC ("invalid" / a bare
# signature failure) for a beyond-scope claim — i.e. the over-claim was caught for
# the wrong reason, not as a distinct scope verdict naming the capability. The
# claim's whole point is the DISTINCT verdict; a generic invalid is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/verify.json" ] \
        || broken "trap fixture missing verify.json: ${TRAP_FIXTURE}"
    status="$(grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]*"' "${TRAP_FIXTURE}/verify.json" \
              | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/')"
    if [ "$status" != "outside-agent-scope" ]; then
        red "ours=status:${status:-none} expected=outside-agent-scope — the beyond-scope claim was rejected by a GENERIC verdict, not the distinct scope verdict that names the offending capability; the containment property is not attributable"
    fi
    green "captured verdict is the distinct outside-agent-scope — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or auths-sign) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/atten2.XXXXXX")"
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
OUT_SHA="$(worker_signs_commit "$LAB/work-out" "over-claim admin" admin)"
[ -n "$IN_SHA" ] && [ -n "$OUT_SHA" ] || broken "the worker could not sign both commits"

org_env
IN_STATUS="$(verify_commit_status "$LAB/work-in" "$IN_SHA")"
OUT_STATUS="$(verify_commit_status "$LAB/work-out" "$OUT_SHA")"

# Accept half must hold (an in-scope claim verifies) AND the over-claim must be
# the DISTINCT scope verdict.
[ "$IN_STATUS" = "valid" ] \
    || red "ours=in-scope:${IN_STATUS:-none} expected=valid — the accept half failed; cannot attribute the reject to scope when the in-scope twin does not even verify"

if [ "$OUT_STATUS" = "outside-agent-scope" ]; then
    green "valid signature, still rejected: the beyond-scope (admin) commit is refused as outside-agent-scope while the in-scope (sign_commit) twin verifies — a distinct containment verdict, not a signature failure"
fi
[ -z "$OUT_STATUS" ] \
    && red "ours=no-verdict expected=outside-agent-scope — \`auths verify\` produced no status for the beyond-scope commit"
red "ours=status:${OUT_STATUS} expected=outside-agent-scope — the beyond-scope (admin) commit was not rejected by the distinct scope verdict; containment is not enforced at verify for this claim"
