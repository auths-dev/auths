#!/usr/bin/env bash
# AGENT-ATTEN-3 — a mid-chain key-holder cannot self-widen: issuance must REFUSE a
# delegation that grants more than the delegator itself holds (the subset rule).
# GREEN means: a manager holding anchored {sign_commit} CAN delegate a sub-worker
# a subset {sign_commit} (accept), but CANNOT delegate a sub-worker
# {sign_commit, deploy} — issuance refuses (non-zero exit, no agent minted),
# because a delegate can only narrow. RED means issuance ALLOWS the over-grant (a
# second-tier scoped delegate can self-widen) — the documented open gap: the
# issuance-time subset check reads the delegator's OWN KEL, but a scoped agent's
# scope is anchored in ITS delegator's KEL, so it reads "unrestricted" and the
# wider grant slips through. BROKEN means we could not build the chain.
#
# Note: the verify-time gate (ATTEN-2) still contains any over-claim, so this is a
# defense-in-depth gap at issuance, not a containment bypass.
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures an issuance run that SUCCEEDED (exit 0, an agent did was
# minted) for an over-grant — the self-widen this claim forbids. Exit 0 on an
# over-grant is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/issue.code" ] && [ -f "${TRAP_FIXTURE}/issue.out" ] \
        || broken "trap fixture missing issue.code/issue.out: ${TRAP_FIXTURE}"
    code="$(cat "${TRAP_FIXTURE}/issue.code")"
    if [ "$code" -eq 0 ] && grep -qE 'did:keri:' "${TRAP_FIXTURE}/issue.out"; then
        red "ours=exit0-agent-minted expected=refused — the over-grant (more than the delegator holds) was ISSUED instead of refused; a mid-chain key-holder self-widened"
    fi
    green "captured over-grant issuance was refused (no agent minted) — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/atten3.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org org)"
[ -n "$ORG_DID" ] || broken "could not establish the org root identity"

# The manager is a scoped delegate of the org, holding {sign_commit}.
MANAGER_DID="$(delegate_worker manager org sign_commit)"
[ -n "$MANAGER_DID" ] || broken "could not delegate the manager (scope sign_commit)"

# Accept half: the manager delegating a SUBSET {sign_commit} must succeed.
SUB_OK_DID="$(delegate_worker subworker-ok manager sign_commit)"
sub_ok_rc=$?
if [ $sub_ok_rc -ne 0 ] || [ -z "$SUB_OK_DID" ]; then
    red "ours=subset-refused expected=subset-allowed — the manager could not delegate a sub-worker a SUBSET of its own scope (exit $sub_ok_rc); the subset rule over-rejects: $(cat "$LAB/agent-add-subworker-ok.out" 2>/dev/null | tail -1)"
fi

# Adversarial half: the manager delegating MORE than it holds
# ({sign_commit, deploy}) must be REFUSED at issuance.
OVER_DID="$(delegate_worker subworker-wide manager sign_commit deploy)"
over_rc=$?

if [ $over_rc -ne 0 ] && [ -z "$OVER_DID" ]; then
    green "the manager (holding {sign_commit}) delegated a SUBSET sub-worker but the {sign_commit,deploy} over-grant was refused at issuance (exit $over_rc) — a key-holder cannot mint authority it was never given"
fi
red "ours=over-grant-issued expected=refused — the manager (holding only {sign_commit}) successfully delegated a sub-worker {sign_commit,deploy} (exit $over_rc, did=${OVER_DID:-none}); the issuance-time subset check reads the delegator's own KEL, not its delegator-anchored seal, so a scoped delegate self-widens"
