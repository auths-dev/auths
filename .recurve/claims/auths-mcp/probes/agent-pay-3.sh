#!/usr/bin/env bash
# AGENT-PAY-3 — the INVERTED payment-mode default: REAL money is the DEFAULT, TEST
# is a single opt-in flag; the budget cap is the MANDATORY safety seatbelt; the mode
# is DISCLOSED so real money is never silent (a deliberate operator inversion — PRD
# §11 / §9 AGENT-PAY-3).
#
# THE DECISION THIS CLAIM ENCODES: real money is now the DEFAULT (no flag → Stripe
# LIVE api.stripe.com/sk_live_, x402 base MAINNET real USDC), and TEST is a single
# opt-in (`--test-mode` / AUTHS_MCP_TEST_MODE=1 → sk_test_ / base-sepolia). BECAUSE
# real is the default, the cross-rail budget cap is the SEATBELT and MUST be
# mandatory — the gateway must REFUSE to wrap a payment rail without a `--budget`.
# And the mode must be DISCLOSED (`mode=real|test` + a startup banner) so an operator
# always knows whether real money is live.
#
# HERMETIC — needs NO real money. The probe drives a MODE-DISCLOSURE / DRY-RUN
# surface only (`auths-mcp wrap --show-mode …` — RESOLVE the PaymentMode port +
# DISCLOSE it, never serve the proxy, never charge). It tests mode-SELECTION, the
# cap GUARD, and DISCLOSURE — never a live charge. The expected disclosure shapes the
# build will emit are recorded under probes/fixtures/payment-mode-*.expected.json.
#
# GREEN means the gateway implements the inverted default over a clean PaymentMode
# port, and the resolved-mode dry-run discloses it:
#   1. MODE RESOLUTION + DISCLOSURE.
#        default (no flag) → mode=real    (Stripe LIVE / base MAINNET disclosed)
#        --test-mode       → mode=test    (sk_test_ / base-sepolia disclosed)
#   2. CAP IS MANDATORY (the seatbelt — the critical safety probe).
#        a payment-rail wrap WITH --budget is ACCEPTED;
#        WITHOUT --budget it is REFUSED (fail-closed), in BOTH modes.
#   3. MODE IS DISCLOSED.
#        a real-mode wrap discloses mode=real; a test-mode wrap discloses mode=test —
#        real money is never silent.
#
# RED means the inverted default is not built: no --show-mode / PaymentMode-resolution
# disclosure surface, OR --budget is still optional so a payment rail can be wrapped
# UNCAPPED (the seatbelt is skippable — the safety hole), OR the mode is not disclosed
# (silent real money). BROKEN means no staged binary.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN.
set -uo pipefail
cd "$(dirname "$0")/.."
. ./harness/env.sh
. ./probes/_contract.sh
set +e

# ── Trap mode ─────────────────────────────────────────────────────────────────
# Two forbidden regressions, each a RECORDED known-bad wrap stream the probe MUST
# turn RED:
#   cap-omitted-allowed — a payment rail wrapped with NO --budget that was ALLOWED
#       (real money live and UNCAPPED — the seatbelt was skippable).
#   mode-not-disclosed  — real money active (live Stripe / mainnet x402) but the mode
#       was NOT disclosed (silent real money).
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/wrap.out" ] \
        || broken "trap fixture missing wrap.out: ${TRAP_FIXTURE}"
    out="$(cat "${TRAP_FIXTURE}/wrap.out")"
    name="$(basename "${TRAP_FIXTURE}")"

    case "$name" in
        cap-omitted-allowed)
            # The seatbelt must REFUSE a budget-less payment-rail wrap. This stream
            # ALLOWED it (no --budget, yet the proxy served and real money was live).
            # GREEN only if the captured stream actually refused (budget-required);
            # this known-bad one did not → RED.
            if printf '%s' "$out" | grep -qiE 'budget-required|refus|mandatory.*budget|--budget .* required'; then
                green "captured stream REFUSED the budget-less payment-rail wrap (budget-required) — the seatbelt held; the adversarial twin holds"
            fi
            red "ours=cap-omitted-allowed expected=budget-required — a payment rail was wrapped with NO --budget and the proxy served ANYWAY (\"$(printf '%s' "$out" | grep -i 'no --budget' | head -1)\"); real money is live and UNCAPPED — the mandatory-cap seatbelt was skippable (the safety hole this claim forbids)"
            ;;
        mode-not-disclosed)
            # Real money is active in this stream (live Stripe endpoint / sk_live_ /
            # mainnet x402) but NO mode disclosure was emitted. GREEN only if a
            # mode=real (or mode=test) disclosure is present; this known-bad one has
            # real money live with NO `mode=` field → RED (silent real money).
            real_live=0
            printf '%s' "$out" | grep -qiE 'sk_live_|api\.stripe\.com|mainnet|network=base[^-]' && real_live=1
            disclosed=0
            printf '%s' "$out" | grep -qiE 'mode=real|mode=test|REAL MONEY|TEST MODE' && disclosed=1
            if [ $disclosed -eq 1 ]; then
                green "captured stream DISCLOSED the payment mode (mode=… banner present) — the mode is not silent; the adversarial twin holds"
            fi
            red "ours=mode-not-disclosed expected=mode=real(disclosed) — real money is live (live Stripe / mainnet x402 in the stream) but NO mode disclosure was emitted (no mode= field, no banner); real money is SILENT — the disclosure this claim mandates is absent"
            ;;
        *)
            broken "unknown trap fixture: $name"
            ;;
    esac
fi

bin_ready || broken "no staged bin/auths-mcp-gateway — run the suite rebuild first"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/pay3.XXXXXX")"
trap 'rm -rf "$LAB"' EXIT
sandbox_env "$LAB"

# A trivial downstream stub — the wrap line needs a downstream command, but the
# --show-mode dry-run RESOLVES + DISCLOSES the payment mode and exits; it never
# actually spawns/serves it (served:false, charged:false). Nothing is charged.
STUB="$LAB/downstream-stub.sh"
printf '#!/usr/bin/env bash\nexec cat\n' > "$STUB"
chmod +x "$STUB"

# show_mode <extra-args...> — drive the resolve+disclose dry-run and echo its output.
# Everything before `--` is gateway flags; the stub is the (un-served) downstream.
show_mode() {
    "$GATEWAY_BIN" wrap --show-mode "$@" --scope paid.call -- "$STUB" 2>&1
}

# ── 1. MODE RESOLUTION + DISCLOSURE ────────────────────────────────────────────
# default (no flag) → mode=real ; --test-mode → mode=test.
REAL_OUT="$(show_mode --budget '$5')"
TEST_OUT="$(show_mode --test-mode --budget '$5')"

mode_real_ok=0
# default discloses REAL: a mode=real token AND the live-rail resolution (sk_live_ /
# api.stripe.com / base mainnet) so an operator sees real money is live.
if printf '%s' "$REAL_OUT" | grep -qiE 'mode=real|mode: *real' \
   && printf '%s' "$REAL_OUT" | grep -qiE 'sk_live_|api\.stripe\.com|mainnet|REAL MONEY'; then
    mode_real_ok=1
fi

mode_test_ok=0
# --test-mode discloses TEST: a mode=test token AND the sandbox-rail resolution
# (sk_test_ / base-sepolia).
if printf '%s' "$TEST_OUT" | grep -qiE 'mode=test|mode: *test' \
   && printf '%s' "$TEST_OUT" | grep -qiE 'sk_test_|base-sepolia|TEST MODE'; then
    mode_test_ok=1
fi

# ── 2. CAP IS MANDATORY (the seatbelt) ─────────────────────────────────────────
# A payment-rail wrap WITH --budget is accepted; WITHOUT --budget it is REFUSED
# (fail-closed) in BOTH modes. We read the disclosure dry-run so nothing is charged.
WITH_BUDGET_OUT="$REAL_OUT"                          # the real-mode dry-run WITH --budget
NOBUDGET_REAL_OUT="$(show_mode)"                     # real mode, NO --budget
NOBUDGET_TEST_OUT="$(show_mode --test-mode)"         # test mode, NO --budget
nobudget_real_rc=0; printf '%s' "$NOBUDGET_REAL_OUT" | grep -qiE 'budget-required|refus|mandatory.*budget' && nobudget_real_rc=1
nobudget_test_rc=0; printf '%s' "$NOBUDGET_TEST_OUT" | grep -qiE 'budget-required|refus|mandatory.*budget' && nobudget_test_rc=1

cap_ok=0
# WITH --budget the dry-run resolved a mode (not a budget-required refusal), AND
# WITHOUT --budget BOTH modes refused budget-required — the seatbelt is mandatory and
# cannot be skipped.
if printf '%s' "$WITH_BUDGET_OUT" | grep -qiE 'mode=real|mode: *real' \
   && [ $nobudget_real_rc -eq 1 ] && [ $nobudget_test_rc -eq 1 ]; then
    cap_ok=1
fi

# ── 3. MODE IS DISCLOSED ───────────────────────────────────────────────────────
# (folded into checks 1: a real-mode wrap discloses mode=real, a test-mode wrap
# discloses mode=test — captured by mode_real_ok / mode_test_ok above.)
disclose_ok=0
[ $mode_real_ok -eq 1 ] && [ $mode_test_ok -eq 1 ] && disclose_ok=1

if [ $mode_real_ok -eq 1 ] && [ $mode_test_ok -eq 1 ] && [ $cap_ok -eq 1 ] && [ $disclose_ok -eq 1 ]; then
    green "the inverted payment-mode default is built over a clean PaymentMode port: with NO flag the gateway resolves to REAL and discloses mode=real (Stripe LIVE / base MAINNET) — real money is the DEFAULT; with --test-mode it resolves to TEST and discloses mode=test (sk_test_ / base-sepolia). The cross-rail budget cap is the MANDATORY seatbelt — a payment-rail wrap WITHOUT --budget is refused budget-required in BOTH modes (fail-closed), WITH --budget it resolves. The mode is DISCLOSED either way so real money is never silent (PRD §11/§9 AGENT-PAY-3)."
fi

# Honest RED — name exactly which half of the safety contract is unbuilt.
miss=""
[ $mode_real_ok -eq 0 ] && miss="${miss}no-real-default-disclosure(default→mode=real+live-rails absent) "
[ $mode_test_ok -eq 0 ] && miss="${miss}no-test-opt-in-disclosure(--test-mode→mode=test+sandbox-rails absent) "
[ $cap_ok       -eq 0 ] && miss="${miss}cap-not-mandatory(budget-less payment wrap not refused budget-required in both modes — the seatbelt is skippable) "
[ $disclose_ok  -eq 0 ] && miss="${miss}mode-not-disclosed(no mode=real|test in the resolved-mode report — silent real money) "
red "ours=${miss}expected=real-default+test-opt-in+mandatory-cap+mode-disclosed — the inverted payment-mode default is not built: the gateway has no --show-mode/PaymentMode-resolution disclosure surface, --budget is still optional so a payment rail can be wrapped UNCAPPED (the seatbelt is skippable), and the mode is not disclosed (real money would be silent). The BUILD wires a clean PaymentMode port (real default, single --test-mode/AUTHS_MCP_TEST_MODE=1 opt-in), the mandatory-cap guard, and the mode=real|test disclosure (PRD §11/§9 AGENT-PAY-3)."
