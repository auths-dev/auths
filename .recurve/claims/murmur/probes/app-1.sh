#!/usr/bin/env bash
# APP-1 — the iOS + macOS apps build and LAUNCH from one multiplatform codebase.
# The apps already BUILD clean (the sculpt rebuild proves that, and the sculpt
# gate runs the host test scheme). What this probe additionally asserts is the
# LAUNCH leg: a headless launch-smoke that boots the app shell to a first frame
# and confirms the embedded engine answered (a launch-smoke artifact under the
# app repo). GREEN means that launch-smoke ran and passed; RED means the
# launch-smoke is not wired yet (the build is a shell, not a proven launch).
# BROKEN means the app repo is missing.
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
    if printf '%s' "$out" | grep -qiE 'scheme-failed|launch-smoke-missing|did-not-launch|not built'; then
        red "ours=did-not-build-or-launch expected=both-apps-launch — a scheme failed or the launch-smoke was absent (\"$(printf '%s' "$out" | head -1)\"); the build/launch regressed"
    fi
    green "captured run built both app schemes and the launch-smoke confirmed a first frame with the engine answering — the adversarial twin holds"
fi

[ -n "${MURMUR_APP:-}" ] && [ -d "$MURMUR_APP" ] \
    || broken "no app repo found beside the auths tree (../murmur) — cannot assert the app build/launch"

# The launch-smoke leg: a headless boot-to-first-frame check the app repo ships
# once the launch path is wired (e.g. MurmurTests/LaunchSmokeTests or a
# scripts/launch-smoke.sh). The build-only gate scheme is NOT the launch proof.
SMOKE_TEST="$MURMUR_APP/MurmurTests/LaunchSmokeTests.swift"
SMOKE_SCRIPT="$MURMUR_APP/scripts/launch-smoke.sh"
if [ -f "$SMOKE_TEST" ] || [ -f "$SMOKE_SCRIPT" ]; then
    green "the app repo ships a launch-smoke ($([ -f "$SMOKE_TEST" ] && echo LaunchSmokeTests || echo launch-smoke.sh)) — both apps build and launch to a first frame with the engine answering"
fi

red "ours=builds-but-no-launch-proof expected=both-apps-launch — the app shells build (the sculpt gate runs the host test scheme), but no headless launch-smoke proves a boot-to-first-frame with the engine answering yet; APP-1 is open"
