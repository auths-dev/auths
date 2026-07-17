#!/usr/bin/env bash
# AGENT-AUDIT-1 — the north-star surface: a party who did NOT operate the agent can
# re-derive its spend OFFLINE and detect a tampered proof, with no trust in the
# operator that produced the log.
#
# `auths-mcp-gateway verify-spend` re-verifies every signed per-call proof through the
# SAME verifier the live gate uses, re-derives the spend, and exits non-zero on any
# non-`consistent` verdict — needing only the issuer's registry (to resolve the agent
# + delegator KELs) and the persisted spend log. This is the "receipts anyone can
# verify, without trusting you" half of the pitch. Eleven probes gate the gateway's
# live path; NONE gated this — the one surface that proves the category exists.
#
# GREEN requires BOTH halves:
#   1. Acceptance: an honest spend log verifies `consistent` (exit 0).
#   2. Adversary:  a proof tampered AFTER signing (one byte of the signed
#      `call_commit`) is caught `tampered-proof` (exit non-zero). A verifier that
#      accepts the tampered log is not auditing signatures — it is trusting the
#      operator, which is the whole thing this claim forbids.
#
# RED  = verify-spend is absent, OR the honest log is not consistent, OR the tampered
#        log is accepted (the audit does not actually re-verify the signatures).
# BROKEN = no staged binary / missing transcript.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. Hermetic: throwaway sandbox, no network,
# never touches ~/.auths or the user's git config.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# A known-bad fixture: a verify-spend run over a tampered log that was ACCEPTED
# (reported consistent) instead of caught tampered-proof — the regression this
# probe forbids. The captured verdict must show the tamper was caught.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/verify.out" ] \
        || broken "trap fixture missing verify.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/verify.out")"
    if ! printf '%s' "$out" | grep -qiE 'tampered-proof|failed verification|inconsistent'; then
        red "ours=accepted expected=tampered-proof — verify-spend reported \"$(printf '%s' "$out" | head -1)\" over a post-signing-tampered log; the audit did not re-verify the signed proof, so it is trusting the operator"
    fi
    green "the tampered log was caught (tampered-proof) — the offline audit re-verifies signatures, not the operator's word"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

TRANSCRIPT="$(transcript_path agent-mcp-1)"
[ -f "$TRANSCRIPT" ] || broken "missing replay transcript: $TRANSCRIPT"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/audit1.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# ONE drive (the chain build is not idempotent). The replay persists the signed
# spend log into the sandbox registry and prints the exact standalone audit command
# — `verify-spend`'s --log/--registry/--agent/--root — which we then run ourselves,
# as an independent auditor would, over the persisted artifacts.
RAW="$(gateway_replay "$TRANSCRIPT" 2>/dev/null)"
AUDIT_ARGS="$(printf '%s\n' "$RAW" | sed -n 's/^▸* *audit-cmd: //p' | head -1)"
[ -n "$AUDIT_ARGS" ] \
    || red "ours=no-audit-cmd expected=verify-spend — replay emitted no 'audit-cmd:' line; the gateway does not expose an offline spend-audit command over the persisted log (\"$(printf '%s' "$RAW" | tail -1)\")"

LOG="$(printf '%s' "$AUDIT_ARGS" | sed -n 's/.*--log \([^ ]*\).*/\1/p')"
[ -f "$LOG" ] \
    || red "ours=no-spend-log expected=$LOG — replay did not persist a signed spend log for the audit to re-verify"

# ── Half 1: the honest log must re-derive consistent, offline ─────────────────
HONEST="$("$GATEWAY_BIN" verify-spend $AUDIT_ARGS 2>&1)"
honest_rc=$?
accept_ok=0
[ $honest_rc -eq 0 ] && printf '%s' "$HONEST" | grep -qi 'consistent' && accept_ok=1

# ── Half 2: a proof tampered after signing must be caught tampered-proof ───────
# Flip one byte of the signed `call_commit` in a COPY of the log (verify-spend takes
# --log by path, so the registry stays untouched and we never re-drive the gateway).
TAMPERED="$LAB/tampered-spend.jsonl"
python3 - "$LOG" "$TAMPERED" <<'PY'
import json, sys, pathlib
src, dst = sys.argv[1], sys.argv[2]
lines = [l for l in pathlib.Path(src).read_text().splitlines() if l.strip()]
entry = json.loads(lines[0])
cc = entry.get("call_commit")
if isinstance(cc, list) and cc:          # signed message bytes → flip one
    cc[0] ^= 0x01
    lines[0] = json.dumps(entry)
pathlib.Path(dst).write_text("\n".join(lines) + "\n")
PY
TAMPER_ARGS="$(printf '%s' "$AUDIT_ARGS" | sed "s#--log [^ ]*#--log $TAMPERED#")"
TAMPER_OUT="$("$GATEWAY_BIN" verify-spend $TAMPER_ARGS 2>&1)"
tamper_rc=$?
adversary_ok=0
[ $tamper_rc -ne 0 ] \
    && printf '%s' "$TAMPER_OUT" | grep -qiE 'tampered-proof|failed verification|inconsistent' \
    && adversary_ok=1

if [ $accept_ok -eq 1 ] && [ $adversary_ok -eq 1 ]; then
    green "offline audit holds: an honest spend log re-derived consistent, and a proof tampered after signing was caught tampered-proof — a third party can verify the receipts without trusting the operator"
fi

if [ $accept_ok -ne 1 ]; then
    red "ours=$(printf '%s' "$HONEST" | head -1) expected=consistent(exit 0) — the honest, untampered spend log did not re-derive consistent offline (rc=$honest_rc); the counterparty audit surface does not work"
fi

red "ours=accepted(rc=$tamper_rc) expected=tampered-proof — verify-spend accepted a log whose signed call_commit was altered after signing (\"$(printf '%s' "$TAMPER_OUT" | head -1)\"); it is not re-verifying the proofs, so it trusts the operator — the north-star property is absent"
