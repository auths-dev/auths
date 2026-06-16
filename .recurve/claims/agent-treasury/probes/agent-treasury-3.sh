#!/usr/bin/env bash
# AGENT-TREASURY-3 — The per-agent P&L is a stream of signed, verifiable receipts;
# a self-reported / forged P&L is excluded from the rebalancing signal. The manager
# moves capital on the VERIFIED books only, never an agent's word.
#
# GREEN: a real sub-agent slice receipt verifies (valid) — the verifiable P&L atom;
#   AND a forged/self-reported receipt (a fabricated SAID, and a credential minted
#   by a FOREIGN issuer the manager never delegated) does NOT verify against the
#   manager's registry (status != valid) — so it cannot move a dollar of allocation.
# RED: a forged/foreign receipt verifies valid (the books can be faked). BROKEN:
#   could not build the chain. Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/forged-receipt-verify.json" ] \
        || broken "trap fixture missing forged-receipt-verify.json: ${TRAP_FIXTURE}"
    status="$(jq -r '.data.status // empty' "${TRAP_FIXTURE}/forged-receipt-verify.json" 2>/dev/null)"
    if [ "$status" = "valid" ]; then
        red "ours=status:valid expected=non-valid — a forged/self-reported P&L receipt verified valid; the manager would rebalance on fabricated books"
    fi
    green "captured forged-receipt verdict is non-valid (excluded) — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths (or jq) — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/treasury3.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

MGR_DID="$(bootstrap_manager manager)"; [ -n "$MGR_DID" ] || broken "could not establish manager"
FLIP="$(delegate_subagent flip manager)"; [ -n "$FLIP" ] || broken "could not delegate flip"
FLIP_SAID="$(issue_slice manager "$FLIP" calls:4)"; [ "$(issue_rc)" -eq 0 ] && [ -n "$FLIP_SAID" ] \
    || broken "could not issue the flip slice (exit $(issue_rc))"

# The verified P&L atom: a real in-slice receipt verifies.
OBS="$LAB/obs.json"
write_observation "$OBS" "$FLIP_SAID" 1
REAL="$(verify_status manager "$FLIP_SAID" "$OBS")"
[ "$REAL" = "valid" ] \
    || broken "the real slice receipt did not verify (status=${REAL:-none}); cannot test exclusion of forged receipts"

# Forgery 1: a fabricated SAID the manager never issued — must not verify.
FAKE_SAID="ECredForgedXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
write_observation "$OBS" "$FAKE_SAID" 1
FORGED="$(verify_status manager "$FAKE_SAID" "$OBS")"
[ "$FORGED" != "valid" ] \
    || red "ours=forged-said:valid expected=non-valid — a fabricated receipt (a SAID the manager never issued) verified valid; the P&L can be forged"

# Forgery 2: a credential minted by a FOREIGN issuer (a second, unrelated root) —
# presenting it against the manager's registry must not verify as the manager's P&L.
sandbox_env "$LAB/foreign"   # a separate registry/root
bootstrap_manager rogue >/dev/null
ROGUE_AGENT="$(delegate_subagent rogue-agent rogue)"
ROGUE_SAID="$(issue_slice rogue "$ROGUE_AGENT" calls:9)"
# Switch back to the manager's registry and try to verify the rogue receipt there.
sandbox_env "$LAB"
write_observation "$OBS" "$ROGUE_SAID" 1
FOREIGN="$(verify_status manager "$ROGUE_SAID" "$OBS")"
[ "$FOREIGN" != "valid" ] \
    || red "ours=foreign-issuer:valid expected=non-valid — a receipt minted by a foreign issuer verified as the manager's P&L; an outsider could pump a sub-agent's allocation"

green "a real slice receipt verifies (valid), while a fabricated SAID (${FORGED:-none}) and a foreign-issuer receipt (${FOREIGN:-none}) do NOT verify against the manager's registry — the manager rebalances on verifiable books only; a self-reported or forged P&L is excluded"
