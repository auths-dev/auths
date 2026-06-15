# Cycle BOOT-3 — every authored probe can run: the baseline decides, never BROKEN

- **Date:** 2026-06-13
- **Gap:** `BOOT-3` (class `staging`, severity `feature`)
- **Result:** **CLOSED — promoted.** Probe authored and baselined RED, then
  driven GREEN; trap RED; all three federated gates green (network `matrix
  --gate`, demos `rictl matrix --gate`, interop `ictl matrix --gate`).
  `open → closed` in `gaps.yaml`; GAPS.md §BOOT-3 rewritten to the closed
  reality. A second probe (WIT-N1) was authored in the same wave and promoted
  `open` (RED) — it is the sibling whose happy path the clean baseline had to
  make measurable.
- **auths rev:** branch `dev-auths-network`.

## The claim, and why it was genuinely RED

BOOT-3 is the gate that a fresh agent inherits a CLEAN baseline: every authored
probe returns a DECISION (RED / GREEN), never BROKEN (exit 2 / timeout / crash).
A baseline with a BROKEN in it is not a baseline — "is this behavior present?"
has no answer there, so the burndown cannot start.

The BROKEN sibling at baseline was **WIT-N1**. Against the BOOT-2 *skeleton*
`auths witness up` — which printed a health URL and exited 0 while standing
nothing up — the WIT-N1 probe could not decide whether the standup capability
was real or faked: the command claimed a success reality contradicted. That is a
corrupted measurement, so the probe returned **BROKEN**, and BOOT-3 saw it:

```
$ bash probes/wit-n1.sh
`witness up` exited 0 and printed http://127.0.0.1:3340/health but nothing
answers there — … cannot decide WIT-N1 against a build whose success is a lie   (exit 2 BROKEN)

$ bash probes/boot-3.sh
ours=BROKEN baseline expected=all-decide — 1 authored probe(s) could not measure
on the built tree (exit≠0,1): wit-n1.sh:exit=2 …   (exit 1 RED)
```

## What was built (the fix was real, not cosmetic)

**Platform (auths, branch `dev-auths-network`):**

- **`crates/auths-witness-node/src/standup.rs`** (new) — the standup *runtime*.
  `stand_up()` materializes the embedded Compose manifest, brings the node +
  monitor up through a `ContainerEngine` port, waits until the node answers its
  health endpoint through a `HealthCheck` port, and returns the proven-live URL.
  Any failure tears down whatever started (no partial state) and returns one
  `StandupError` whose `Display` is a single actionable line. Ports/adapters: the
  orchestration never shells out directly; success is a node answering, not the
  command merely returning. 6 unit tests.
- **`crates/auths-witness-node/src/engine.rs`** (new) — the shipped adapters:
  `DockerEngine` (drives `docker compose`, distils engine failures to one
  actionable line) and `SocketHealthCheck` (a dependency-free raw-socket HTTP GET
  — all it needs is whether the node answers `2xx`). 4 unit tests.
- **`crates/auths-cli/src/commands/witness.rs`** — `auths witness up` now calls
  the real `stand_up()`: it reaches a healthy node and prints the URL, or fails
  honestly (non-zero, one line, nothing left standing) when it cannot — it no
  longer claims success without a node. `down` tears down the per-port project;
  `status` reports a node as healthy only if it actually answers. Added
  `--image` (operators can pin a released tag / run an air-gapped image) and
  `--port` to `down`.

The witness-node feature stayed **additive** (WIT-B2): default
`cargo tree -p auths-cli` shows 0 `auths-witness-node`; `--features witness-node`
shows 1. No core crate points at the node crate. No protocol reimplemented
(WIT-B1) — the node crate composes the platform crates. No source build in the
standup path (WIT-B4) — the manifest declares a *released* `image:`.

**Suite (auths-network, branch `main`):**

- `probes/boot-3.sh` (new) + `probes/boot-3.trap/broken-sibling/` — the meta-probe
  (runs every sibling probe, RED if any is BROKEN) and its permanent
  counterexample (a sibling that exits 2).
- `probes/wit-n1.sh` (new) + `probes/wit-n1.trap/occupied-port/` — the standup
  probe (drives `up`, asserts a real node answers with zero protocol vocabulary;
  asserts the clean refusal when no engine) and its trap (an `up` that exited 0
  on an occupied port — a partial-state lie — stays RED).
- `gaps.yaml` — BOOT-3 promoted `open → closed`; WIT-N1 promoted `open` (RED),
  both with real dated baselines.
- `gaps.draft.yaml`, `GAPS.md` — BOOT-3/WIT-N1 marked promoted; §BOOT-3 rewritten
  to closed reality, §WIT-N1 to the built standup.

## Baseline → after

```
WIT-N1:  BROKEN (skeleton up lied)         →  RED   (real up fails honestly here)
BOOT-3:  RED    (a BROKEN sibling present)  →  GREEN (every authored probe decides)
```

## Gate status at promote

- BOOT-3 probe → **GREEN**; trap `broken-sibling` → **RED**.
- WIT-N1 probe → **RED** (no obtainable node image on this box); trap
  `occupied-port` → **RED**. The happy-path GREEN is exercised by the
  `auths-witness-node` unit tests (scripted engine + health check).
- Network `recurve matrix --gate` → **GATE OK** (holding 4, 0 regressions/broken/
  stale, traps 2/2 RED).
- Demos `rictl matrix --gate` → **GATE OK** (holding 46, 0 regressions; each
  demo's `bin/auths` re-copied from the rebuilt lean `target/release/auths`).
- Interop `./scripts/build.sh && ./ictl matrix --gate` → **GATE OK** (holding 27,
  0 regressions).
- `auths-witness-node` 15 tests pass; clippy `-D warnings` clean on the crate and
  on `auths-cli` under both default and `--features witness-node`. Default build
  stayed lean (WIT-B2 verified). No suppressions. No loop vocabulary in any
  platform file.

## Notes for the next agent

- **WIT-N1 is RED, not closed.** A green WIT-N1 needs an *obtainable* node image:
  the released `ghcr.io/auths-dev/auths-witness:latest` is not pullable in this
  environment and no local image is built (the platform witness Dockerfile's musl
  build did not complete here). This is the SAME prerequisite BOOT-1's 3-node
  fixture waits on — closing either one closes the image gap for both. The
  standup runtime itself is done and unit-proven; only the live image is missing.
- BOOT-1 remains RED (its 3-node Compose fixture needs the same node image). It
  holds RED and does not block the gate.
- `coverage --gate` is non-green by design: the 22 still-draft WIT-* GAPS.md
  sections are orphan prose until promoted. §BOOT-1/2/3 and §WIT-N1 are covered.
