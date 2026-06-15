#!/usr/bin/env bash
# ENC-7 — the multi-device key lifecycle (REVIEW-GATED, security-tradeoff —
# NEVER auto-closed). N delegated devices × per-device Signal identity keys ×
# prekey bundles, with continuity that must hold across rotation AND delegation
# SIMULTANEOUSLY, is the combinatorial state machine where the subtle break hides
# (PRD §10 release gate). A green ENC-1..6 gate is NECESSARY but NOT SUFFICIENT
# here: the lifecycle must be SPECIFIED and pass the EXTERNAL cryptographic audit
# before any real user.
#
# So GREEN requires BOTH the falsifiable floor (the lifecycle is specified — the
# spec artifact exists) AND a recorded external-audit verdict. The implementer's
# own self-tests are a floor, not an audit; this gap promotes only through
# REVIEW.md, never through an unattended cycle and never through a green gate.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures the documented failure: the multi-device lifecycle was
# closed on self-tests alone (no external audit), or a rotation-during-delegation
# continuity break slipped through. That must be RED.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/capture.out" ] \
        || broken "trap fixture missing capture.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/capture.out")"
    if printf '%s' "$out" | grep -qiE 'closed-on-self-tests|no-external-audit|rotation-delegation-continuity-broke|not audited|not built|feature absent'; then
        red "ours=closed-without-external-audit expected=specified+externally-audited — the multi-device key lifecycle was closed on self-tests alone or a rotation-during-delegation continuity break slipped through (\"$(printf '%s' "$out" | head -1)\"); the release gate regressed"
    fi
    green "captured lifecycle was specified and carried an external cryptographic audit verdict — the adversarial twin holds"
fi

# The falsifiable FLOOR: the multi-device key-lifecycle spec artifact exists (the
# N-devices × Signal-identity-keys × prekey-bundles state machine, continuity
# across rotation AND delegation, is written down — not just asserted).
SPEC="$SUITE_DIR/cycles/enc-7/key-lifecycle.md"
[ -f "$SPEC" ] && grep -qiE 'rotation.*delegation|delegation.*rotation' "$SPEC" \
    || red "ours=lifecycle-unspecified expected=specified+externally-audited — the multi-device key-lifecycle spec (N devices × Signal identity keys × prekey bundles, continuity across rotation AND delegation) is not written down yet at cycles/enc-7/key-lifecycle.md; ENC-7 is open"

# The REVIEW verdict: a recorded EXTERNAL cryptographic-audit confirmation. A
# green gate alone NEVER promotes this — the external auditor's recorded verdict
# does (PRD §10: external review before any non-demo user).
AUDIT="$SUITE_DIR/cycles/enc-7/external-audit.md"
if [ -f "$AUDIT" ] && grep -qiE 'AUDIT PASSED|externally reviewed' "$AUDIT"; then
    green "the multi-device key lifecycle is specified AND an external cryptographic audit recorded a passing verdict — the KERI↔Signal join over N devices held under external review"
fi

red "ours=specified-floor-only-no-external-audit expected=specified+externally-audited — the multi-device key lifecycle is written down, but the EXTERNAL cryptographic audit (PRD §10 release gate, REVIEW-GATED) has not recorded a passing verdict; ENC-7 is open and never self-closes"
