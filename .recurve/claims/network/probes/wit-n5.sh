#!/usr/bin/env bash
# WIT-N5 — zero protocol vocabulary in the operator happy path. An operator
# stands a witness up, checks on it, registers it, reads its logs, and tears it
# down — and must never need the trust kernel's vocabulary (key event logs,
# key-state notices, self-addressing identifiers, the CESR wire, signing
# thresholds, and the like) to do any of it. This probe makes the
# vocabulary-invisible rule a guarantee instead of a hope.
#
# Behavioral, end to end — AND source-anchored (the claim is about output
# STRINGS, so reads:source is legitimate; see the gap's smallest_fix). GREEN
# means: every line the full operator happy path prints — `up`, `status`,
# `register`, `logs`, `down`, with and without a build attestation — passes a
# case-insensitive whole-word scan against the canonical protocol-vocabulary
# denylist the PRODUCT owns, AND that denylist lives in exactly one place (no
# divergent hand-maintained copy survives in the node crate). RED means either a
# happy-path line leaked a protocol term, or the rule has no single owner the
# probe can anchor to (it is a hope spread across ad-hoc test lists, not a
# guarantee). BROKEN means we could not even attempt the measurement.
#
# The load-bearing distinction this probe enforces: a green is only real if the
# words it forbids are the words the PRODUCT forbids. A probe carrying its own
# private jargon list could drift from the surface it guards and bless a leak it
# never thought to name. So the probe extracts the denylist from the product
# source (one source of truth) and scans the LIVE happy path against exactly it.
#
# Contract: 0 GREEN · 1 RED · 2 BROKEN. The probe stands up its OWN throwaway
# node (free port + throwaway data dir) and tears it down on exit (hermetic —
# the shared fixture is untouched).
set -uo pipefail
cd "$(dirname "$0")/.."   # the suite dir (.../claims/network)
. ./harness/env.sh
. ./probes/_contract.sh
set +e   # we inspect exit codes of commands expected to fail; errexit would abort

AUTHS_BIN="./bin/auths"

# The one place the operator-vocabulary rule lives in the product. The probe
# anchors to THIS file's PROTOCOL_VOCABULARY list so probe and surface cannot
# drift (quality constitution §3 — one source of truth).
VOCAB_SRC="$AUTHS_SRC/crates/auths-witness-node/src/vocabulary.rs"

# Extract the canonical denylist (the bare lowercase terms inside the
# PROTOCOL_VOCABULARY const) from the product source. This is the rule the
# happy path is held to; the probe never invents its own.
read_denylist() {
    # Pull the PROTOCOL_VOCABULARY const body, then every "quoted" token on it.
    awk '/pub const PROTOCOL_VOCABULARY/{f=1} f{print} f&&/\];/{exit}' "$VOCAB_SRC" \
        | grep -oE '"[a-z]+"' | tr -d '"' | sort -u
}

# scan_clean <label> <text> — RED (via the caller) if any denylisted term
# appears as a whole word, case-insensitively, in <text>. Whole-word so a benign
# word that merely contains a term (e.g. "prefixed", "did:key:") is not flagged.
# Prints the first leak as "label:term" on stdout, empty if clean.
first_leak() {
    local text_lower
    text_lower="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
    local term
    while IFS= read -r term; do
        [ -n "$term" ] || continue
        # \b word boundaries make the match whole-word and case-insensitive
        # (input already lowercased; the list is lowercase by construction).
        if printf '%s' "$text_lower" | grep -qE "\\b${term}\\b"; then
            printf '%s:%s' "$1" "$term"
            return 0
        fi
    done <<< "$DENYLIST"
    printf ''
}

# ── Trap mode ────────────────────────────────────────────────────────────────
# A trap fixture supplies a KNOWN-BAD captured happy-path transcript at
# probes/wit-n5.trap/<fixture>/happy-path.out: operator output that DOES carry
# protocol vocabulary (e.g. a `status` line that leaked "KEL"/"threshold"). The
# probe MUST turn RED on it — a scanner that called a jargon-laden transcript
# clean would be one whose denylist is cosmetic. The trap stays RED forever.
if [ -n "${TRAP_FIXTURE:-}" ]; then
    [ -f "$VOCAB_SRC" ] \
        || broken "the product's canonical vocabulary source is missing ($VOCAB_SRC) — cannot anchor the scan to the rule the surface is held to"
    [ -f "${TRAP_FIXTURE}/happy-path.out" ] \
        || broken "trap fixture missing happy-path.out: ${TRAP_FIXTURE}"
    DENYLIST="$(read_denylist)"
    [ -n "$DENYLIST" ] \
        || broken "the product's PROTOCOL_VOCABULARY denylist read as empty — cannot decide the trap"
    transcript="$(cat "${TRAP_FIXTURE}/happy-path.out")"
    leak="$(first_leak "trap" "$transcript")"
    [ -n "$leak" ] \
        || red "ours=clean-on-jargon DANGER — the scanner passed a happy-path transcript that carries protocol vocabulary; the vocabulary rule is cosmetic and an operator can be shown jargon undetected"
    red "ours=${leak} expected=RED — the captured transcript leaks protocol vocabulary (whole-word, case-insensitive); the scanner caught it, so this trap stays RED"
fi

# ── 0. The rule has a single owner the probe can anchor to ───────────────────
[ -f "$VOCAB_SRC" ] \
    || red "ours=no-canonical-denylist expected=one-owner — the product exposes no single source of truth for the operator-vocabulary rule (expected $VOCAB_SRC); a rule with no owner is a hope, not a guarantee"
DENYLIST="$(read_denylist)"
[ -n "$DENYLIST" ] \
    || red "ours=empty-denylist expected=nonempty — the product's PROTOCOL_VOCABULARY denylist is empty; the happy-path scan would be vacuously green"

# The rule must actually forbid the trust kernel's load-bearing vocabulary —
# not a token subset that lets the headline terms slip through. These are the
# terms §US-001 and §6 name (and the gap's adversarial twin); the canonical
# list must contain every one or the guarantee has holes.
for required in keri kel ksn said cesr oobi acdc tel verkey prefix threshold; do
    printf '%s\n' "$DENYLIST" | grep -qx "$required" \
        || red "ours=denylist-missing:${required} expected=covers-the-kernel-vocabulary — the canonical operator-vocabulary denylist omits a load-bearing protocol term; the rule has a hole a leak could slip through"
done

# One source of truth (quality constitution §3): the node crate must not also
# carry a DIVERGENT, hand-maintained jargon list elsewhere — a second copy is
# exactly how the surface and its guard drift. The only place a literal jargon
# array may live is the canonical vocabulary.rs.
stray="$(grep -rlE '"keri"[[:space:]]*,[[:space:]]*"kel"' \
    "$AUTHS_SRC/crates/auths-witness-node/src" 2>/dev/null \
    | grep -v '/vocabulary.rs$' | head -1)"
[ -z "$stray" ] \
    || red "ours=divergent-denylist:${stray#$AUTHS_SRC/} expected=one-source-of-truth — a second hand-maintained jargon list lives outside the canonical vocabulary.rs; it will drift from the rule it duplicates"

# ── 1. Stand the node up so the happy path is real, not imagined ─────────────
[ -x "$AUTHS_BIN" ] \
    || broken "no bin/auths — run the suite rebuild first (recurve rebuild network)"
"$AUTHS_BIN" --version >/dev/null 2>&1 \
    || broken "bin/auths does not run as an auths binary — cannot exercise the operator happy path"

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
    || broken "no container engine — the operator happy path stands a node up; without a live node there is no happy-path output to scan (fixture prerequisite, not a verdict)"

bash ./harness/ensure-image.sh >/dev/null 2>&1 \
    || broken "the witness node image could not be made present (harness/ensure-image.sh) — cannot stand a node up to exercise the happy path"

ATTESTATION="$(bash ./harness/ensure-build-attestation.sh 2>/dev/null)"
[ -n "$ATTESTATION" ] && [ -f "$ATTESTATION" ] \
    || broken "could not produce the signed build attestation (harness/ensure-build-attestation.sh) — the attested-node happy path needs it"

PORT="${WIT_N5_PORT:-3350}"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wit-n5.XXXXXX")"
cleanup() {
    "$AUTHS_BIN" witness down --port "$PORT" --data-dir "$DATA_DIR" >/dev/null 2>&1
    rm -rf "$DATA_DIR" 2>/dev/null
}
trap cleanup EXIT

# Capture EVERY line the operator sees across the full happy path. Standup with
# a build attestation is the headline path (`status` then renders the build
# verdict — the surface most likely to reach for protocol words), so the node
# the probe stands up carries one.
HAPPY=""
append() { HAPPY+="$1"$'\n'; }

up_out="$("$AUTHS_BIN" witness up --port "$PORT" --data-dir "$DATA_DIR" \
    --image "$WITNESS_IMAGE" --build-attestation "$ATTESTATION" 2>&1)"
up_code=$?
[ "$up_code" -eq 0 ] \
    || broken "the node did not stand up (exit $up_code) — standup prerequisite, not a verdict on vocabulary: $(printf '%s' "$up_out" | tail -1)"
append "$up_out"

# `status` against the attested node — health + the build verdict it renders.
append "$("$AUTHS_BIN" witness status --port "$PORT" 2>&1)"
# `register` — the operator opens a signed candidate entry for the directory.
append "$("$AUTHS_BIN" witness register --endpoint https://wit.example.org 2>&1)"
# `logs` — the operator reads the node's logs.
append "$("$AUTHS_BIN" witness logs --data-dir "$DATA_DIR" 2>&1)"
# `down` — tearing the node back down.
append "$("$AUTHS_BIN" witness down --port "$PORT" --data-dir "$DATA_DIR" 2>&1)"

# ── 2. Every happy-path line passes the canonical scan ───────────────────────
leak="$(first_leak "happy-path" "$HAPPY")"
[ -z "$leak" ] \
    || red "ours=${leak} expected=no-protocol-vocabulary — a line the operator happy path printed leaked a protocol term (whole-word, case-insensitive) the product itself forbids; operators must never see the trust kernel's vocabulary: $(printf '%s\n' "$HAPPY" | grep -iE "\\b${leak#happy-path:}\\b" | head -1)"

green "the operator happy path carries zero protocol vocabulary: every line \`witness up|status|register|logs|down\` printed (attested standup included) passed a whole-word, case-insensitive scan against the product's own canonical denylist (covering keri/kel/ksn/said/cesr/oobi/acdc/tel/verkey/prefix/threshold and more), and that denylist lives in exactly one place — the vocabulary-invisible rule is a guarantee with one owner, not a hope spread across ad-hoc lists"
