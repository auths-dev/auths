# Cycle: app-1-launch-smoke — APP-1 closed

## Gap
APP-1 — The iOS + macOS apps build and launch from one multiplatform codebase
(missing-surface · headline). Baseline RED: both shells *built*, but no headless
launch-smoke proved a boot-to-first-frame with the embedded engine answering.

## What changed (../murmur — the app sculpt tree)
- **`Murmur/Sources/Shared/LaunchSmoke.swift`** (new) — a first-frame beacon both
  shells share. At the first frame it asks the embedded engine for its version (an
  FFI round-trip — proves the core is linked and answering) and emits one stable,
  greppable line `MURMUR_LAUNCH_SMOKE platform=<ios|macos> engine=ok core=<ver>`
  to both the unified log and stdout. It is a launch *proof*, not telemetry — it
  carries no AID and no message content by construction.
- **`Murmur/Sources/Shared/ContentView.swift`** — a `.task` on the root view fires
  the beacon once at first frame, per-platform.
- **`MurmurTests/LaunchSmokeTests.swift`** (new) — the deterministic, host-side leg
  that runs in the Gate scheme with NO simulator: it exercises the exact engine
  round-trip the beacon makes, asserts the beacon line is well-formed and carries
  the engine's real answer, and guards that it leaks nothing sensitive. A
  regression that makes the engine stop answering across the FFI turns this RED
  before any app launches.
- **`scripts/launch-smoke.sh`** (new) — the real-boot leg. Boots an iPhone
  simulator + launches the macOS app bundle, waits for the beacon off the
  unified log (macOS) and `simctl launch --console-pty` (iOS), then shuts the sim
  back down. Headless and self-cleaning. (A dev/CI check; the deterministic gate
  stays xcodebuild/snapshot/contrast — a sim boot is never the gate.)
- **`project.yml`** — two build-config fixes that made install/launch possible at
  all: a valid version pair (`MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` →
  `CFBundleVersion`) on the apps, and `GENERATE_INFOPLIST_FILE` on the embedded
  `MurmurCore` framework. Without these the simulator refused to *install* the
  shell ("Info.plist does not contain a valid CFBundleVersion" / "Failed to load
  Info.plist from bundle …/MurmurCore.framework") — so it built but never launched.
- **`.gitignore`** — ignore the launch driver's throwaway `.launch-smoke-dd/`
  derived-data tree.

## What changed (. — the auths target tree)
- **`.recurve/claims/murmur/gaps.yaml`** — APP-1 `open → closed`; `observed`
  rewritten to the new reality.

## Verification (the gate is the only arbiter)
- `recurve --config .recurve/murmur.toml probe --gap APP-1` → GREEN.
- Real boot: `scripts/launch-smoke.sh all` → GREEN on both legs
  (`MURMUR_LAUNCH_SMOKE platform=macos engine=ok core=0.1.3`,
  `… platform=ios engine=ok core=0.1.3`).
- Deterministic app gate `./scripts/gate.sh` → exit 0 (8 tests, incl. the 3 new
  LaunchSmokeTests).
- `recurve --config .recurve/murmur.toml matrix --gate` → GATE OK · holding 16 ·
  regressions 0 · broken 0 · stale 0 · traps 1/1 still RED · sculpt murmur gate OK ·
  leakcheck clean.
- Trap discriminates: the probe is GREEN on the real path, RED on
  `probes/app-1.trap/build-broken/` (a captured scheme-failed/launch-smoke-absent
  log).

## Net-new gaps
None.
