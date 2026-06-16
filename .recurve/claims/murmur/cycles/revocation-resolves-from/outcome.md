# Cycle: revocation-resolves-from — RVK-1 closed

## Gap

**RVK-1** (missing-surface, headline) — *Revocation resolves from witness-corroborated
key-state, not a relay's cache; the honest stale-served window is acknowledged.*

Baseline: RED (`ours=feature-absent expected=revoked-rejected-from-corroborated+stale-window-disclosed`).
The delegated-device clawback existed (MSG-4) but the resolved state had no notion of
*where* it came from — a revocation could be resolved from a relay's stale cache and
silently waved through as safe.

## What changed (the real feature)

The clawback now carries **provenance**. PRD §6.5 is explicit that revocation is
detection, not prevention: it is only as fast as a contact re-resolves, and only *safe*
when it gets witness-corroborated state rather than a relay's cache. That honest bound is
now load-bearing in the engine, not just prose.

- `crates/murmur-core/src/corroboration.rs` (new module):
  - `Provenance` — `WitnessCorroborated { confirmed, threshold }` vs
    `RelayCache { revocations_behind_witnesses }`. `is_corroborated()` is decided by the
    *source*, not the contents: a relay cache is never corroborated, even when it happens
    to be current (it was never checked against the witnesses).
  - `CorroboratedState` — pairs a resolved `DelegationState` with its `Provenance`.
    `resolve_revocation()` rejects a revoked device from witness-corroborated state
    (`RevocationResolution::RevokedFromCorroboratedState`) and **discloses** the
    stale-served window for a relay cache (`StaleWindowDisclosed { cache_shows_revoked,
    revocations_behind_witnesses }`) — never laundering a cache into a corroborated
    clawback, and failing closed on a sub-threshold "corroborated" set.
  - `disclose()` emits the two greppable tokens: `revoked-from-corroborated-state` and
    `stale-window-disclosed`. Neither line ever claims a relay cache was corroborated.
- `crates/murmur-core/src/lib.rs` — `prove_revocation_corroborated()` drives both halves
  hermetically: the root anchors then revokes a delegated device; a contact re-resolving
  the witness-corroborated set rejects it; a contact served the *pre-revocation snapshot*
  (the stale cache) is told the window. Fails closed on a revoked device accepted from
  corroborated state, a relay cache trusted over the witnesses, or a hidden stale window.
- `crates/murmur-relay/src/main.rs` — `run_revocation_corroborated` added as an 11th
  `serve` leg, printing the two markers the probe greps for.

## Verdict deltas

- `recurve probe --gap RVK-1`: RED → **GREEN** (`READY→close`).
- `recurve matrix --gate`: **GATE OK** — 0 regressions / broken / stale / missing,
  **12/12 traps still RED** (the new `rvk-1.trap/revoked-from-corroborated` counterexample
  among them), leakcheck **clean** over both trees, app sculpt gate **OK**.
- `recurve coverage --gate`: exit 0 — no prose/ledger drift.
- `cargo test -p murmur-core -p murmur-relay`: **85 passed, 0 failed**.
- `cargo clippy`: clean (no warnings, no suppressions).

## Honest boundary preserved

The feature does not oversell revocation as an instant global kill. A corroborated
rejection is the only *safe* outcome; a relay cache is always *disclosed* as a window,
never trusted over the witnesses — exactly the prevention-vs-detection bound the PRD
insists on. The trap proves the inverse fails RED: accepting a revoked device from
corroborated state, trusting a relay cache over the witnesses, or hiding the stale window.
