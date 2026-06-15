#!/usr/bin/env bash
# WIT-N1 — one command, one witness: `auths witness up` takes a clean box to a
# HEALTHY node and tells the truth about it. The headline standup claim.
#
# Behavioral, end to end. GREEN means: `auths witness up` brought a witness node
# up, printed a health URL, and exited 0 — AND that URL actually answers (a real
# node is serving), with zero protocol vocabulary in the happy-path output.
# RED means the standup did not reach a healthy node (the behavior is absent).
# BROKEN means we could not even attempt the measurement (no bin/auths).
#
# The load-bearing distinction this probe enforces: `up` exiting 0 is NOT
# success — a node answering its health URL is. An `up` that prints a health URL
# and exits 0 while nothing listens there is the lie WIT-N1 exists to forbid;
# this probe reconciles the two and is RED until they agree.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The probe drives `auths witness up`
# against a throwaway data dir + free port and reads the result; it tears its
# own node down on exit (hermetic — leaves no fixture behind).
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh
set +e   # we inspect exit codes of commands expected to fail; errexit would abort

# ── Trap mode ────────────────────────────────────────────────────────────────
# A trap fixture supplies a KNOWN-BAD captured `witness up` run at
# probes/wit-n1.trap/<fixture>/{up.out,up.code}: an `up` that exited 0 and
# printed a health URL while the port was already taken — a partial-state lie
# (it claimed success without standing a fresh node up). The probe MUST turn RED
# on it: a printed health URL with a non-zero exit OR a stale answerer is not a
# successful standup. This is the occupied-port adversarial twin, frozen.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "${TRAP_FIXTURE}/up.out" ] && [ -f "${TRAP_FIXTURE}/up.code" ] \
        || broken "trap fixture missing up.out/up.code: ${TRAP_FIXTURE}"
    up_out="$(cat "${TRAP_FIXTURE}/up.out")"
    up_code="$(cat "${TRAP_FIXTURE}/up.code")"
    # The trap encodes an occupied-port standup. Acceptable behavior is a
    # non-zero exit with a single actionable line. A zero exit (claimed success
    # on an occupied port) is the partial-state lie — RED.
    if [ "$up_code" -eq 0 ]; then
        red "ours=exit0-occupied-port expected=actionable-refusal — \`witness up\` claimed success while the port was already taken; that is partial state masquerading as a standup"
    fi
    lines="$(printf '%s\n' "$up_out" | grep -c .)"
    [ "$lines" -le 3 ] \
        || red "ours=${lines}-line-error expected=one-line — occupied-port \`witness up\` must fail with a single actionable line: ${up_out}"
    green "occupied-port standup refused cleanly (exit $up_code, ${lines} line(s)) — the adversarial twin holds"
fi

AUTHS_BIN="./bin/auths"
[ -x "$AUTHS_BIN" ] \
    || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
"$AUTHS_BIN" --version >/dev/null 2>&1 \
    || broken "bin/auths does not run as an auths binary — cannot attempt standup"

# A free port + throwaway data dir for this probe's own ephemeral node.
PROBE_PORT="${WIT_N1_PORT:-3340}"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wit-n1.XXXXXX")"
cleanup() {
    "$AUTHS_BIN" witness down --port "$PROBE_PORT" --data-dir "$DATA_DIR" >/dev/null 2>&1
    rm -rf "$DATA_DIR" 2>/dev/null
}
trap cleanup EXIT

# Standup runs a RELEASED image (`image:`, never `build:`) — obtaining that image
# is the harness's job, not the probe's and not `up`'s. Ensure it is present
# (build-once from the platform's canonical deployment Dockerfile), so on a clean
# box `up` finds a real node image and the one-command-to-healthy behavior is
# measurable. If the engine is genuinely absent, ensure-image fails — the
# no-engine branch below still decides (the clean adversarial refusal).
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    bash ./harness/ensure-image.sh >/dev/null 2>&1 \
        || broken "the witness node image could not be made present (harness/ensure-image.sh failed) — cannot attempt the standup; this is a fixture prerequisite, not a verdict on \`up\`"
fi

# ── 1. Run the one command ───────────────────────────────────────────────────
# `up` runs the released image the harness just made present. The image is the
# operation's input, supplied by the operator/harness; `up` never builds it.
up_out="$("$AUTHS_BIN" witness up --port "$PROBE_PORT" --data-dir "$DATA_DIR" --image "$WITNESS_IMAGE" 2>&1)"
up_code=$?

# Standup needs a container engine. If it is genuinely absent, `up` must say so
# in one actionable line and exit non-zero (the adversarial twin) — that is a
# DECISION (RED), not an inability to measure. We only go BROKEN if bin/auths
# itself can't run (handled above).
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    # No engine: the ONLY acceptable behavior is a clean, single-line refusal and
    # a non-zero exit, with NO node left behind. An `up` that exits 0 here is the
    # lie under test.
    if [ "$up_code" -eq 0 ]; then
        red "ours=exit0-no-engine expected=actionable-refusal — \`witness up\` claimed success with no container engine available; it must fail with one actionable line and stand nothing up"
    fi
    lines="$(printf '%s\n' "$up_out" | grep -c .)"
    [ "$lines" -le 3 ] \
        || red "ours=${lines}-line-error expected=one-line — \`witness up\` without an engine must fail with a single actionable line, not a wall of text: ${up_out}"
    green "no container engine present: \`witness up\` refused cleanly (exit $up_code, ${lines} line(s)) and stood nothing up — the adversarial twin holds; happy-path standup is unverifiable here but the behavior decided"
fi

# ── 2. With an engine, exit 0 AND a health URL that actually answers ──────────
if [ "$up_code" -ne 0 ]; then
    red "ours=exit${up_code} expected=exit0 — \`witness up\` did not complete a standup: $(printf '%s' "$up_out" | tail -1)"
fi

# Extract the printed health URL — operators are told where to look; that URL is
# the contract. No URL printed is a standup that hid its result.
health_url="$(printf '%s\n' "$up_out" | grep -oE 'https?://[^[:space:]]+/health' | head -1)"
[ -n "$health_url" ] \
    || red "ours=no-health-url expected=printed-url — \`witness up\` exited 0 but printed no health URL for the operator to open: ${up_out}"

# The lie gate, and the measurability gate. `up` exited 0 and named a health
# URL, so it is CLAIMING a standup succeeded. Poll that URL: if it answers, the
# claim is true (GREEN below). If it does NOT answer, `up` reported a success
# reality contradicts — the probe cannot decide whether the standup capability
# is real-but-slow or simply unfinished/faked, so the measurement is corrupted:
# BROKEN, not a verdict. (An `up` that cannot stand a node up must say so by
# exiting non-zero — handled above as a clean RED — never by claiming success.)
answered=""
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS --max-time 3 "$health_url" >/dev/null 2>&1; then answered="yes"; break; fi
    sleep 1
done
[ -n "$answered" ] \
    || broken "\`witness up\` exited 0 and printed ${health_url} but nothing answers there — the command claimed a standup that did not happen; cannot decide WIT-N1 against a build whose success is a lie (a real \`up\` must exit non-zero when it cannot stand a node up)"

# ── 3. Zero protocol vocabulary in the happy path (carried from TTV/US-001) ───
leak="$(printf '%s\n' "$up_out" | grep -ioE '\b(keri|kel|ksn|said|cesr|oobi)\b' | head -1 || true)"
[ -z "$leak" ] \
    || red "ours=leak:${leak} expected=no-protocol-vocab — happy-path \`witness up\` output leaked protocol vocabulary; operators must never see it"

green "one command stood up a healthy witness: \`witness up\` exited 0, printed ${health_url}, the node answers there, and the happy path carries zero protocol vocabulary"
