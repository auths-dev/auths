#!/usr/bin/env bash
# UI-TRUST — the trust state survives the material (REVIEW-GATED, security-
# tradeoff). The verified-continuation badge and the non-continuation key-change
# warning must hold WCAG AA behind Liquid Glass, in light/dark/increased-contrast
# and under Reduce Transparency + Reduce Motion — translucency never weakens a
# security signal.
#
# This is a SUBJECTIVE visual claim: a green deterministic gate is NECESSARY but
# NOT SUFFICIENT. The app's contrast test proves the AA FLOOR (the falsifiable
# part), but whether the badge reads behind glass on a real backdrop under Reduce
# Transparency / Reduce Motion is the OPERATOR'S call, confirmed by SIMULATING —
# never self-closed here. So GREEN requires BOTH the AA floor AND a recorded
# operator review verdict; the skeleton has the floor but no recorded review, so
# this is RED until the operator confirms.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'glass-dilutes-signal|below-aa|contrast-floor-failed|not reviewed'; then
        red "ours=signal-diluted-below-aa expected=aa-floor-held+operator-confirmed — a token set dropped the trust signal below AA behind glass (\"$(printf '%s' "$out" | head -1)\"); the contrast floor regressed"
    fi
    green "captured token set held AA behind glass and carried an operator review verdict — the adversarial twin holds"
fi

[ -n "${MURMUR_APP:-}" ] && [ -d "$MURMUR_APP" ] \
    || broken "no app repo found beside the auths tree (../murmur) — cannot assert the trust-state contrast"

# The falsifiable FLOOR: the token layer + the contrast math exist (the app's
# contrast test gates the AA floor deterministically).
TOKENS="$MURMUR_APP/Murmur/Sources/Shared/TrustTokens.swift"
[ -f "$TOKENS" ] || broken "no trust-state token layer at $TOKENS — the contrast floor cannot be asserted"

# The REVIEW verdict: a recorded operator confirmation (a review note the
# operator writes after simulating the badge under Reduce Transparency / Motion).
# REVIEW-GATED: a green gate alone never promotes this; the operator's recorded
# verdict does.
REVIEW="$SUITE_DIR/cycles/ui-trust/review.md"
if [ -f "$REVIEW" ] && grep -qiE 'CONFIRMED|reads behind glass' "$REVIEW"; then
    green "the AA contrast floor holds AND the operator recorded a review verdict confirming the trust state reads behind glass under Reduce Transparency / Reduce Motion"
fi

red "ours=aa-floor-only-no-operator-review expected=aa-floor+operator-confirmed — the deterministic contrast floor is met, but the SUBJECTIVE behind-glass judgement (under Reduce Transparency / Reduce Motion) is review-gated and not yet operator-confirmed; UI-TRUST is open (build it, screenshot it on a sim, leave it for review)"
