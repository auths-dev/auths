#!/usr/bin/env bash
# BOOT-3 — every authored probe can run: the full probe set executes on the
# built tree and EVERY verdict is a decision (RED or GREEN), never BROKEN.
#
# Why this is a real claim, not bookkeeping: a probe that exits 2 (BROKEN) — or
# times out, or crashes — did not measure its claim. The runner maps all of
# those to BROKEN and the matrix counts them, but a suite whose baseline is full
# of BROKEN has no baseline at all: the burndown cannot start, because "is this
# behavior present?" has no answer for those gaps. This probe is the gate that a
# fresh agent inherits a CLEAN baseline — every other authored probe decided,
# so the first sculpt cycle faces RED/GREEN, never a wall of "could not measure".
#
# Behavioral, end to end. GREEN means: each authored sibling probe
# (probes/*.sh, minus this meta-probe and the sourced _contract.sh) ran against
# the already-built tree and exited 0 or 1 — a real verdict. RED means at least
# one came back BROKEN (exit 2 / timeout / crash / 127), naming the offender and
# the prerequisite it is missing, which is exactly the env/fixture gap this
# claim exists to close.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. This probe is hermetic — it runs
# already-authored sibling probes against already-built artifacts; it builds
# nothing itself. (The siblings are hermetic too, by the same contract, so the
# meta-run stays in seconds.)
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh
# env.sh sets `errexit`; this probe DELIBERATELY runs sibling probes that are
# expected to exit non-zero (RED is exit 1, and the trap's sibling exits 2) and
# inspects their codes by hand. errexit would abort the meta-run on the first
# such exit — exactly the verdicts we exist to count. Turn it off.
set +e

PROBES_DIR="./probes"
SELF="$(basename "$0")"            # boot-3.sh — never run ourselves (infinite recursion)
# Anything other than 0/1 is "could not decide". The runner coerces timeout
# (124), signals, and 127 to BROKEN the same way; we treat them identically.
is_decision() { [ "$1" -eq 0 ] || [ "$1" -eq 1 ]; }

# A bound on each hermetic sibling so one hung probe can't wedge the meta-run.
# Portable: GNU `timeout` / Homebrew `gtimeout` where present (Linux CI), and a
# no-op passthrough on a bare macOS box — the siblings are hermetic by contract
# (seconds), and the recurve runner's own outer timeout is the backstop.
if command -v timeout >/dev/null 2>&1; then
    run_bounded() { timeout 110 "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
    run_bounded() { gtimeout 110 "$@"; }
else
    run_bounded() { "$@"; }
fi

# ── Assemble the probe set under test ────────────────────────────────────────
# Live: every authored sibling probe on disk. Trap: the KNOWN-BAD probe set the
# runner hands us via TRAP_FIXTURE — a probe that cannot decide. A clean
# baseline that swallowed a BROKEN sibling would be a baseline built on a lie;
# the trap proves this probe still turns RED when a sibling cannot measure.
declare -a probe_set=()
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -d "${TRAP_FIXTURE}" ] || broken "trap fixture dir absent: ${TRAP_FIXTURE}"
    while IFS= read -r p; do probe_set+=("$p"); done \
        < <(find "${TRAP_FIXTURE}" -maxdepth 1 -name '*.sh' | sort)
    [ "${#probe_set[@]}" -gt 0 ] \
        || broken "trap fixture holds no *.sh probe: ${TRAP_FIXTURE}"
else
    while IFS= read -r p; do
        base="$(basename "$p")"
        [ "$base" = "$SELF" ] && continue          # no self-recursion
        [ "$base" = "_contract.sh" ] && continue   # sourced helper, not a probe
        probe_set+=("$p")
    done < <(find "$PROBES_DIR" -maxdepth 1 -name '*.sh' | sort)
    # If the only authored probe is this one, there is nothing to attest to —
    # that is an un-set-up suite, not a clean baseline. Fail closed.
    [ "${#probe_set[@]}" -gt 0 ] \
        || broken "no sibling probes found under $PROBES_DIR — nothing to attest a clean baseline over"
fi

# ── Run each probe; a verdict that is not a decision is the RED line ──────────
# We run WITHOUT TRAP_FIXTURE in the child env so each sibling exercises its
# real (live) path — we are measuring whether the authored probes can decide on
# the built tree, not re-running their traps.
declare -a broken_probes=()
for probe in "${probe_set[@]}"; do
    # Run each sibling in a clean subshell with its real (live) path: no
    # TRAP_FIXTURE (we are measuring the live verdict, not re-running its trap),
    # NO_COLOR for stable output. `run_bounded` caps a hung probe where a
    # timeout tool exists.
    ( unset TRAP_FIXTURE RECURVE_PROBE; export NO_COLOR=1
      run_bounded bash "$probe" >/dev/null 2>&1 )
    code=$?
    is_decision "$code" || broken_probes+=("$(basename "$probe"):exit=$code")
done

if [ "${#broken_probes[@]}" -gt 0 ]; then
    red "ours=BROKEN baseline expected=all-decide — $(( ${#broken_probes[@]} )) authored probe(s) could not measure on the built tree (exit≠0,1): ${broken_probes[*]} — fix the missing env/fixture prerequisite so the baseline is RED/GREEN, never BROKEN"
fi

green "clean baseline: ${#probe_set[@]} authored probe(s) ran on the built tree and every one returned a decision (RED or GREEN), zero BROKEN — the burndown can start"
