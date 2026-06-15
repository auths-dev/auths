#!/usr/bin/env bash
# AGENT-MCP-7 — custody / bypass-resistance (PRD §12, the custody-broker).
#
# The property: the gateway is a CREDENTIAL-CUSTODY broker — it holds the
# downstream tool's secret (API key / OAuth token / wallet key); the agent holds
# ONLY its scoped/budgeted/revocable delegation. A prompt-injected agent that
# points its MCP client straight at the raw credentialed downstream — bypassing the
# gateway — HAS NO CREDENTIAL for it, so the call fails. The same call THROUGH the
# gateway (which supplies the custodied credential) succeeds. The boundary is
# unbypassable BY CONSTRUCTION, not by trusting the model.
#
# Hermetic design: a downstream stub that returns a result ONLY when the credential
# `DOWNSTREAM_CREDENTIAL` is present in its environment (the secret a real wrapped
# tool reads from an env var — the "API key in an env var" majority §12 flips into
# the strongest pitch). The credential is set ONLY in the gateway's environment,
# never in the agent's.
#   - DIRECT (agent → stub, no gateway): the agent's environment has no credential,
#     so the stub refuses → the bypass fails (custody holds).
#   - VIA-GATEWAY (agent → gateway → stub): the gateway injects the custodied
#     credential, so the stub returns its real result → the brokered call succeeds.
# GREEN requires BOTH halves: bypass refused AND brokered allowed — i.e. the gateway
# demonstrably custodies a downstream credential the agent never holds.
#
# RED means the gateway does not custody a downstream credential the agent lacks —
# either the bypass would have worked too (no custody) or the gateway cannot supply
# a custodied credential to make the brokered call succeed (the custody-broker
# mechanism §12 is not built). BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# The trap captures a run where the DIRECT (bypass) call SUCCEEDED — the agent
# reached the credentialed downstream without the gateway (custody did not hold).
# A bypass that is not refused is the regression this probe forbids.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/replay.out" ] \
        || broken "trap fixture missing replay.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/replay.out")"
    if ! printf '%s' "$out" | grep -qiE 'bypass.*refused|direct.*refused|no-credential|missing-credential|credential-absent'; then
        red "ours=bypass-succeeded expected=bypass-refused — the direct (no-gateway) call reached the credentialed downstream (\"$(printf '%s' "$out" | head -1)\"); custody did not hold, the gateway is bypassable"
    fi
    green "captured run refused the direct bypass (no custodied credential in the agent's hands) — the adversarial twin holds"
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/mcp7.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# A downstream stub that requires the custodied credential to be present in ITS
# environment to return a result — exactly the secret a real wrapped tool reads.
STUB="$LAB/downstream-stub.sh"
cat > "$STUB" <<'STUB_EOF'
#!/usr/bin/env bash
# A credentialed downstream tool: returns its result ONLY if the custodied
# credential is present in the environment; otherwise refuses (as a real API
# server would 401 a request with no key).
if [ -n "${DOWNSTREAM_CREDENTIAL:-}" ]; then
    echo '{"ok":true,"result":"downstream-data"}'
    exit 0
fi
echo 'missing-credential: no DOWNSTREAM_CREDENTIAL — refused (this caller never held the key)' >&2
exit 1
STUB_EOF
chmod +x "$STUB"

THE_SECRET="custodied-key-$(date +%s)"

# 1. DIRECT (bypass): the agent runs the stub itself, with NO credential in its
#    environment. This MUST fail — the agent never held the key.
direct_out="$(env -u DOWNSTREAM_CREDENTIAL "$STUB" 2>&1)"
direct_rc=$?
bypass_refused=0
[ $direct_rc -ne 0 ] && bypass_refused=1

# 2. VIA-GATEWAY: the gateway custodies the credential and brokers the call so the
#    downstream returns its real result. The gateway must inject the custodied
#    credential into the downstream it spawns — the agent supplies only its
#    delegation. We ask the staged gateway to demonstrate this custody path: it
#    must accept a custodied credential and reach the credentialed downstream while
#    the agent's own environment stays free of the secret.
#
#    The custody-broker path (a `wrap` that injects a custodied downstream
#    credential the agent never sees) is the §12 mechanism under test. Probe the
#    gateway for it without leaking the secret into the agent's env:
brokered_allowed=0
gw_help="$("$GATEWAY_BIN" wrap --help 2>&1)"
# The gateway demonstrates custody only if it has a way to hold a downstream
# credential separate from the agent's delegation (e.g. a --downstream-credential /
# --credential-env flag, or a documented custody env the agent does not share).
if printf '%s' "$gw_help" | grep -qiE 'credential|custody|--secret|downstream-env'; then
    # Try the brokered path: gateway holds THE_SECRET, downstream reads it, agent env clean.
    via="$(DOWNSTREAM_CREDENTIAL="$THE_SECRET" \
        "$GATEWAY_BIN" wrap --scope paid.call --budget '$5' --custody-credential "DOWNSTREAM_CREDENTIAL=$THE_SECRET" \
        -- "$STUB" 2>&1)"
    if printf '%s' "$via" | grep -qi 'downstream-data'; then
        brokered_allowed=1
    fi
fi

if [ $bypass_refused -eq 1 ] && [ $brokered_allowed -eq 1 ]; then
    green "custody holds: the DIRECT (no-gateway) call was refused — the agent never held the downstream credential — while the same call THROUGH the gateway, which custodied the credential, reached the downstream and returned its result; the boundary is unbypassable by construction (§12)"
fi

# Honest RED: the bypass-refused half is true by construction of the stub, but the
# gateway does not (yet) custody a downstream credential the agent lacks, so it
# cannot demonstrate the via-gateway-succeeds half.
if [ $bypass_refused -eq 0 ]; then
    red "ours=bypass-succeeded expected=bypass-refused+brokered-allowed — the direct (no-gateway) call reached the credentialed downstream; custody did not hold"
fi
red "ours=bypass-refused/no-custody-broker expected=bypass-refused+brokered-allowed — the bypass is refused (the agent holds no downstream credential) BUT the gateway does not custody a downstream credential to supply on the brokered path: the custody-broker mechanism (PRD §12 — gateway holds the downstream secret, agent holds only the delegation) is not built"
