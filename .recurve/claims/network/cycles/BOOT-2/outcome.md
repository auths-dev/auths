# Cycle BOOT-2 — the skeleton builds: rebuild produces the artifacts probes read

- **Date:** 2026-06-13
- **Gap:** `BOOT-2` (class `staging`, severity `feature`)
- **Result:** **CLOSED — promoted.** Probe authored and baselined RED, then
  driven GREEN; trap RED; all three federated gates green (network `matrix
  --gate`, demos, interop). `open → closed` in `gaps.yaml`; GAPS.md §BOOT-2
  rewritten to the built reality.
- **auths rev:** branch `dev-auths-network`.

## What was built

**Platform (auths, branch `dev-auths-network`):**

- **`crates/auths-witness-node`** (new) — the node-operator orchestration crate,
  behind the additive `witness-node` workspace feature. It COMPOSES the
  platform's public crate APIs (`auths-witness`, `auths-keri`, `auths-verifier`)
  and reimplements no protocol (WIT-B1): it owns the *operation* — the parsed
  standup intent (`StandupRequest`), the embedded node+monitor Compose manifest
  (released image only, never a source build), key custody policy (`KeyCustody`,
  managed-by-default; a file key is an acknowledged downgrade), and the
  operator-facing health URL. The protocol types it renders (`KeyStateNotice`,
  `WitnessQuorum`, the KSN wire version, the server body-size cap) are
  re-exported from the platform, never redeclared. 5 unit tests.
- **`auths witness up|down|status|register|logs`** — the operator verb set added
  to `auths-cli`'s `witness` command. The clap *surface* always compiles in
  (thin defs, no heavy deps; `auths witness --help` is identical in every
  build); the *handler* is feature-split — a `--features witness-node` build runs
  the node via `auths-witness-node`, a lean default build returns one actionable
  line (`… needs the witness build; install it with cargo install auths
  --features witness-node`) and pulls none of the node's dependencies.
- **`Cargo.toml`** — new workspace member + `auths-witness` / `auths-witness-node`
  workspace deps; `auths-cli` gains the optional `auths-witness-node` dep and the
  `witness-node` feature (default-off).

**Suite (auths-network, branch `main`):**

- `recurve.toml` — `[reads.cli]` content-hash rule (`bin/auths` vs
  `target/witness-node/release/auths`) and `[suites.network] rebuild` wired to
  `harness/rebuild.sh`.
- `harness/rebuild.sh` (new) — builds the feature-enabled `auths` into its OWN
  target dir (`target/witness-node`, so the lean `target/release/auths` the demos
  read is never clobbered) and copies it to `bin/auths`.
- `probes/boot-2.sh` (new) — behavioral probe: the rebuild is wired and produces
  `bin/auths`; `bin/auths` is the feature-enabled build with all operator verbs;
  the node crate composes the platform crates; and the feature is ADDITIVE
  (default `cargo tree -p auths-cli` shows no `auths-witness-node`, `--features
  witness-node` shows it).
- `probes/boot-2.trap/node-in-default-tree/` (new) — the permanent counterexample:
  a default `cargo tree` that pulls `auths-witness-node`. A non-additive feature
  (the lean install stopped being lean) is the WIT-B2 regression; the probe MUST
  turn RED on it.
- `gaps.yaml` — BOOT-2 promoted `open → closed` with its real RED baseline.
- `gaps.draft.yaml`, `GAPS.md` — BOOT-2 marked promoted / rewritten to built reality.

## Baseline (RED, dated 2026-06-13)

```
$ bash probes/boot-2.sh
no bin/auths — the suite rebuild has not run (recurve rebuild network → harness/rebuild.sh)   (exit 1)

$ TRAP_FIXTURE=…/boot-2.trap/node-in-default-tree bash probes/boot-2.sh   # after rebuild
default auths-cli build pulls auths-witness-node — the witness-node feature is NOT additive; the lean install stopped being lean (WIT-B2)   (exit 1)
```

## Gate status at promote

- BOOT-2 probe → **GREEN** (exit 0); trap `node-in-default-tree` → **RED**.
- `auths witness up` on the LEAN default build → one-line "install the witness
  build" error (no node dep pulled); on the FEATURE build → real handler.
- `cargo tree -p auths-cli` default → 0 `auths-witness-node`; `--features
  witness-node` → present (WIT-B2 additive, verified).
- Network `recurve matrix --gate` → **exit 0, GATE OK** (BOOT-2 holding GREEN,
  BOOT-1 holding RED, traps 1/1 RED, 0 regressions/broken/stale).
- Demos `rictl matrix --gate` → **exit 0, GATE OK** (46 holding, 0 regressions);
  the demos' `bin/auths` re-copied from the rebuilt lean `target/release/auths`.
- Interop `./scripts/build.sh && ./ictl matrix --gate` → **exit 0, GATE OK**
  (27 holding, 0 regressions).
- Build + clippy (`-D warnings`) clean on the witness-node crate and `auths-cli`
  under both default and `--features witness-node`. No suppressions.
- No loop vocabulary (`WIT-`/`BOOT-`/`recurve`/`GAP-`) in any platform file.

## Notes for the next agent

- BOOT-1 is still RED (Docker engine unavailable in this environment — see
  `cycles/BOOT-1/outcome.md`); it holds RED and does not block the gate.
- The `up`/`status`/`register`/`down`/`logs` handlers are the SKELETON: they
  materialize the standup manifest + health URL and return cleanly. The real
  runtime bring-up (embedded Compose apply, ≤10-min cold-start, KMS minting) is
  WIT-N1's job and reads the feature-enabled `bin/auths` this cycle produced.
- `coverage --gate` is non-green by design here: GAPS.md carries all 22 WIT-*/
  BOOT-3 draft sections that are not yet promoted into the live ledger (orphan
  prose). §BOOT-1 and §BOOT-2 are both covered. This clears as the drafts land.
