# Sculpting cycle: app-1-launch-smoke

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| APP-1 | murmur | headline | missing-surface | `app-1.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **APP-1** — Keep the two native SwiftUI shells building clean under xcodebuild (the iOS app for the simulator, the macOS app for the host) from one multiplatform codebase, embedding murmur-core through the FFI, AND ship a headless launch-smoke that boots each shell to a first frame with the embedded engine answering. Adversarial (the trap): a build configuration that does not produce both apps, or a launch that never reaches a first frame, must fail. TRAP probes/app-1.trap/build-broken/ — a captured build log where a scheme failed or the launch-smoke was absent must turn the probe RED.

## What gets stronger (the REBUILD payoff)

- **APP-1** unlocks: The two-app testbed exists at all — the thing you hold to make the thesis click.

## Definition of done (the GATE)

- [ ] Every gap probe above flips RED → GREEN (`recurve probe --gap <id>`).
- [ ] `recurve matrix --gate` green across all suites: zero regressions, zero broken.
- [ ] Each touched suite's harness green.
- [ ] Tree changes satisfy the quality constitution (parse-don't-validate,
      ports/adapters, one source of truth); build/lint/tests clean; no suppressions.
- [ ] `gaps.yaml` statuses promoted open→closed; `GAPS.md` prose updated to
      describe the NEW reality (the gap becomes a feature note).
- [ ] Anything discovered mid-cycle that can't be closed is filed as a NEW gap
      with its own RED probe (the loop never silently drops scope).

## Matrix baseline (captured at cycle start)

```
    gap         outcome   status     Δ        detail
  ○ APP-1       RED      open                 ours=builds-but-no-launch-proof expected=both-apps-launch —

holding 1 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
GATE OK
```
