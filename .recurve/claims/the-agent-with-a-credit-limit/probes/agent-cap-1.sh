#!/usr/bin/env bash
# AGENT-CAP-1 — a credential can carry a QUANTITATIVE cap predicate, and a
# MALFORMED one is REFUSED AT ISSUANCE (not accepted as an opaque string).
#
# GREEN means BOTH halves hold:
#   (accept) a credential issued with `calls:3` issues AND verifies, with the
#     predicate parsed and enforced — `calls_used=3` against it yields the
#     distinct cap_exceeded verdict, proving the bound survived issue -> verify
#     as a real predicate rather than dead text.
#   (reject) a credential issued with a MALFORMED quantitative predicate (a
#     `calls:`-resource capability whose bound is missing/non-numeric/negative —
#     `calls:`, `calls:abc`, `calls:-1`) is REFUSED at `credential issue` (non-zero
#     exit, no credential minted). The whole point of a quantitative grammar is
#     that a bound that does not parse cannot be silently accepted as an opaque,
#     UNCAPPED capability — that would be a budget that never fires.
#
# RED means the malformed predicate was ISSUED anyway and carries no enforceable
# cap (the documented open gap: issuance does not validate the `calls:` resource,
# so `calls:abc` is stored as an opaque string and the credential verifies valid
# at any count — a cap that is silently no cap). BROKEN means we could not build
# the chain.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/the-agent-with-a-credit-limit)
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures an issuance run that SUCCEEDED (exit 0, a credential SAID was
# minted) for a malformed quantitative predicate — the silent-accept this claim
# forbids. Exit 0 on a malformed `calls:` cap is RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/issue.code" ] && [ -f "${TRAP_FIXTURE}/issue.out" ] \
        || broken "trap fixture missing issue.code/issue.out: ${TRAP_FIXTURE}"
    code="$(cat "${TRAP_FIXTURE}/issue.code")"
    if [ "$code" -eq 0 ] && grep -qE '"credential_said"[[:space:]]*:[[:space:]]*"E' "${TRAP_FIXTURE}/issue.out"; then
        red "ours=exit0-credential-minted expected=refused — a malformed quantitative predicate (a calls: cap with no valid bound) was ISSUED instead of refused; the cap is silently an opaque, uncapped string"
    fi
    green "captured malformed-cap issuance was refused (no credential minted) — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/cap1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

ORG_DID="$(bootstrap_org finance)"
[ -n "$ORG_DID" ] || broken "could not establish the finance org root identity"

AGENT_DID="$(delegate_agent procurement finance sign_commit)"
[ -n "$AGENT_DID" ] || broken "could not delegate the procurement agent"

# ── Accept half: a well-formed `calls:3` cap issues, verifies, and ENFORCES. ──
GOOD_SAID="$(issue_capped finance "$AGENT_DID" calls:3 sign_commit)"
good_rc="$(issue_rc)"
[ "$good_rc" -eq 0 ] && [ -n "$GOOD_SAID" ] \
    || red "ours=well-formed-cap-refused expected=issuable — issuing a credential with the well-formed cap calls:3 failed (exit $good_rc): $(tail -1 "$LAB_DIR/last-issue.out" 2>/dev/null); the quantitative predicate is not even issuable"

# It must parse and enforce: at calls_used=3 the bound is reached -> cap_exceeded.
OBS="$LAB/obs-good.json"; write_observation "$OBS" "$GOOD_SAID" 3
GOOD_STATUS="$(verify_status finance "$GOOD_SAID" "$OBS")"
[ "$GOOD_STATUS" = "cap_exceeded" ] \
    || red "ours=well-formed-cap:${GOOD_STATUS:-none} expected=cap_exceeded — the calls:3 predicate did not survive issue->verify as a real bound (a count at the cap was not refused); the accept half failed"

# ── Reject half: a MALFORMED quantitative predicate must be refused at issuance. ─
# `calls:abc` is the canonical case: a non-numeric bound on the reserved `calls`
# resource. It must NOT be minted as an opaque uncapped capability.
BAD_SAID="$(issue_capped finance "$AGENT_DID" calls:abc)"
bad_rc="$(issue_rc)"

if [ "$bad_rc" -ne 0 ] && [ -z "$BAD_SAID" ]; then
    green "calls:3 issues, verifies, and enforces (cap_exceeded at the bound), while the malformed calls:abc predicate is REFUSED at issuance (exit $bad_rc, no credential minted) — a quantitative cap that does not parse cannot be silently accepted as an opaque, uncapped string"
fi

# RED detail: the malformed cap was minted. Show that it carries no enforceable
# bound — a credential that verifies valid at a count that should be over budget.
caps="$(cred_caps finance "$BAD_SAID")"
OBS_BAD="$LAB/obs-bad.json"; write_observation "$OBS_BAD" "$BAD_SAID" 99
bad_status="$(verify_status finance "$BAD_SAID" "$OBS_BAD")"
red "ours=malformed-cap-issued expected=refused — the malformed predicate calls:abc was ISSUED (exit $bad_rc, said=${BAD_SAID:-none}, stored caps=[${caps}]) and carries NO enforceable bound (verify at calls_used=99 -> ${bad_status:-none}, not cap_exceeded); issuance accepts a quantitative cap that does not parse as an opaque, uncapped string"
