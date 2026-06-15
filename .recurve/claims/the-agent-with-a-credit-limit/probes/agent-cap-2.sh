#!/usr/bin/env bash
# AGENT-CAP-2 — the usage count is a VERIFIABLE FACT held by the verifier, not the
# app's private number. The cap is enforced against the verifier's own monotonic
# usage ledger (kept under the verify repo, keyed by the credential SAID), so
# "how much has been spent" survives across verifications and cannot be reset by
# the presenter.
#
# GREEN means BOTH halves hold:
#   (accept) after the verifier admits an in-budget count, that count is RECORDED:
#     re-presenting a LOWER count is rejected as a rolled-back counter — proof the
#     verifier holds the high-water mark itself, not the presented integer.
#   (reject / forged-fact) a claimed usage count presented against a credential
#     that carries NO quantitative cap (a presence-only credential) is NOT honored
#     as an enforceable usage fact — the credential verifies the same with or
#     without the claimed count. A bare integer is not authority; only a real
#     `calls:` cap binds the verifier's ledger to the credential's authority.
#
# RED means either the verifier did not retain the count (a replayed lower count
# was admitted, so the "fact" is the presenter's to set), or a claimed count was
# honored against a credential with no cap (a forged number became a limit).
# BROKEN means we could not build the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a verify run that ADMITTED (status=valid) a replayed LOWER
# count after a higher one had already been recorded — i.e. the presenter rolled
# its own counter back. A count the presenter can lower at will is not a verifier-
# held fact; that captured "valid" on the replay is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay-verify.json" ] \
        || broken "trap fixture missing replay-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/replay-verify.json" 2>/dev/null)"
    if [ "$status" = "valid" ]; then
        red "ours=replay-admitted-valid expected=usage_counter_rolled_back — a replayed LOWER count was admitted after a higher one was recorded; the usage count is the presenter's to set, not a verifier-held fact"
    fi
    green "captured replay was rejected (status=${status:-none}, not valid) — the verifier holds the count; the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cap2.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org finance)"
[ -n "$ORG_DID" ] || broken "could not establish the finance org root identity"
AGENT_DID="$(delegate_agent procurement finance sign_commit)"
[ -n "$AGENT_DID" ] || broken "could not delegate the procurement agent"

# ── Accept half: the count is a verifier-held fact (it is recorded, not claimed). ─
CAP_SAID="$(issue_capped finance "$AGENT_DID" calls:5 sign_commit)"
[ "$(issue_rc)" -eq 0 ] && [ -n "$CAP_SAID" ] \
    || broken "could not issue the capped credential (exit $(issue_rc))"

OBS="$LAB/obs.json"
# Spend within budget: 0 then 2 — the verifier advances its high-water mark to 2.
for n in 0 2; do
    write_observation "$OBS" "$CAP_SAID" "$n"
    st="$(verify_status finance "$CAP_SAID" "$OBS")"
    [ "$st" = "valid" ] \
        || red "ours=in-budget:${st:-none} expected=valid — an in-budget count ($n) did not verify; cannot show the count is a retained fact when the accept path does not hold"
done
# Now re-present a LOWER count (1 < recorded 2). If the count were the presenter's,
# this would re-open budget; because the verifier holds the high-water mark, it is
# refused as a rolled-back counter.
write_observation "$OBS" "$CAP_SAID" 1
REPLAY_STATUS="$(verify_status finance "$CAP_SAID" "$OBS")"
[ "$REPLAY_STATUS" = "usage_counter_rolled_back" ] \
    || red "ours=replay:${REPLAY_STATUS:-none} expected=usage_counter_rolled_back — re-presenting a lower count was not rejected; the verifier did not retain the count as its own fact (the presenter can rewind it)"

# ── Reject half: a claimed count is not authority without a real cap. ──────────
# A presence-only credential carries no quantitative bound. Presenting an
# arbitrary "usage" count against it must change nothing — a bare integer cannot
# become an enforceable limit the verifier honors.
PLAIN_SAID="$(issue_capped finance "$AGENT_DID" sign_commit)"
[ "$(issue_rc)" -eq 0 ] && [ -n "$PLAIN_SAID" ] \
    || broken "could not issue the presence-only credential (exit $(issue_rc))"
write_observation "$OBS" "$PLAIN_SAID" 999999
WITH_CLAIM="$(verify_status finance "$PLAIN_SAID" "$OBS")"
WITHOUT_CLAIM="$(verify_status finance "$PLAIN_SAID")"
if [ "$WITH_CLAIM" = "valid" ] && [ "$WITHOUT_CLAIM" = "valid" ]; then
    green "the verifier holds the count as its own fact (a recorded high-water mark of 2 refuses a replayed lower count = usage_counter_rolled_back), while a claimed count (999999) presented against a presence-only credential is NOT honored as a usage fact (verify=valid with and without it) — only a real calls: cap binds enforcement, never a bare integer"
fi
red "ours=presence-with-claim:${WITH_CLAIM:-none}/without:${WITHOUT_CLAIM:-none} expected=valid/valid — a claimed usage count altered the verdict of a credential that carries no quantitative cap; a forged number was treated as an enforceable usage fact"
