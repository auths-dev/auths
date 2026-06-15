# Cycle WIT-N3 — the node serves conformant key-state notices

- **Date:** 2026-06-13
- **Gap:** `WIT-N3` (class `wire-mismatch`, severity `feature`)
- **Result:** **CLOSED — promoted.** Probe authored greenfield (+ stale-ksn
  trap), baselined RED, driven GREEN; the stale-ksn trap stays RED; the BOOT,
  WIT-N1, and WIT-N2 probes still GREEN; both federated gates green (demos
  `rictl matrix --gate` → exit 0 OK, interop `ictl matrix --gate` → exit 0 OK).
  `open → closed` in `gaps.yaml`; GAPS.md §WIT-N3 rewritten to the closed reality.
- **auths rev:** branch `dev-auths-network` (parent `c4af2513`).

## The claim, and why it was genuinely RED

A witness exists to let strangers corroborate an identity's key-state without
trusting the controller. WIT-N3: a running node serves a **KERI-conformant
key-state notice** (KSN) at a stable endpoint; its payload reconstructs inside
the pinned keripy oracle (node → oracle), and a notice the oracle publishes
ingests on the node (oracle → node). This carries interop's IOP-L3c — the KSN
*wire shape*, owned and cross-verified there — to the **running node**. The
adversarial twin: a stale notice (a lower sequence than a newer state the
verifier holds) is detected as stale, never silently accepted.

The probe (`probes/wit-n3.sh`, authored this cycle) stands up the 3-witness
fixture, has `wit1` witness a full conformant inception, then `GET
…/key-state` and cross-verifies both directions against the oracle. At baseline
it was honestly RED — the running node had **no key-state surface at all**:

```
$ NO_COLOR=1 bash probes/wit-n3.sh
curl: (22) The requested URL returned error: 404
ours=no-ksn-endpoint expected=served-notice — the node did not serve a
key-state notice at /witness/<prefix>/key-state (curl exit 22); a thin client
has nothing to trust                                            (exit 1 RED)
```

The witness server stored *receipts* and *first-seen SAIDs*, but discarded the
event bodies — so even if an endpoint existed, the node had no way to recover a
key-state (keys, thresholds, next-commitment). The wire shape itself
(`KeyStateRecord`) already existed in `auths-keri` from IOP-L3c; what was absent
was the running node serving one from events it corroborated.

## The fix (smallest honest change in `../auths`)

Compose the trust kernel; never re-implement protocol.

1. **Retain the witnessed KEL** (`auths-core/src/witness/storage.rs`): a new
   `events` table keyed by `(prefix, seq)` stores each verified event body
   (first-seen-wins), with `store_event` / `get_kel` (ordered replay input). The
   submit handler writes the body right after it SAID- and signature-checks the
   event, so the node can replay an identity's KEL into its current key-state.
2. **Serve the notice** (`auths-core/src/witness/server.rs`): a new
   `GET /witness/{prefix}/key-state` reads the retained KEL, replays it
   (`TrustedKel::from_trusted_source(&events).replay()`), and serves
   `auths_keri::KeyStateRecord::from_kel(...)` — the canonical KERI ksn wire
   record. 404 when the witness has corroborated no events for the prefix; 500
   (surfaced, never papered over) if a retained KEL fails to replay.
3. **Staleness as a kernel fact** (`auths-keri/src/ksn.rs`):
   `KeyStateRecord::sequence()` and `check_not_stale(last_seen_seq)` (returning
   the existing `KsnError::Stale`), exposed via a new
   `auths key-state --ingest --reject-stale-below <hex>` flag
   (`auths-cli/src/commands/key_state.rs`) — a verifier holding a newer state
   fails closed on a rewind, with a distinct reason.

No protocol was hand-rolled in the node: the wire shape, the replay, and the
staleness check are all `auths-keri`'s (WIT-B1). The `witness-node` feature
stayed additive — the default `cargo tree -p auths-cli` still shows no
`auths-witness-node`, and the lean `target/release/auths` the demos read was
never clobbered (WIT-B2).

## Probe, oracle, and trap

- `probes/wit-n3.sh` — behavioral, end to end: live node witnesses
  `probes/fixtures/keri-icp.json` (a real auths-signed `icp`), serves
  `/key-state`, then (1) `harness/ksn_oracle.py` reconstructs the served record
  inside keripy 1.3.4 field-for-field → `ORACLE-OK`; (2) `harness/ksn_emit.py`
  emits an oracle notice and `auths key-state --ingest` consumes it; (3) a stale
  (lower-seq) notice is rejected via `--reject-stale-below`. Leaves the fixture
  standing (harness owns up/down).
- `probes/wit-n3.trap/stale-ksn/` — a genuine seq-0 oracle notice presented to a
  verifier already trusting seq 1. The freshness gate MUST reject it; the trap is
  RED forever (verified RED this cycle, exit 1).

## Gate (all green, this cycle touched `../auths`)

- Claim probe GREEN, stale-ksn trap RED.
- Suite feature rebuild ran; BOOT-1/2/3, WIT-N1, WIT-N2 probes all still GREEN;
  all six traps RED.
- `auths-keri` + `auths-core` (witness-server) + `auths-cli` (witness-node)
  build & clippy clean (`-D warnings`); new unit tests (storage `events`,
  server `key-state`, keri `check_not_stale`) pass.
- Rebuilt the federated artifacts my `../auths` change made stale (the
  lost-the-laptop FFI xcframework bundling `auths-keri`, then the demo CLIs):
  demos `rictl matrix --gate` → exit 0 GATE OK; interop `ictl matrix --gate`
  → exit 0 GATE OK (IOP-L3c stays GREEN).
- Fixture torn down at cycle end; no `wit` containers linger.

## Files

- `../auths` (branch `dev-auths-network`):
  `crates/auths-core/src/witness/storage.rs`,
  `crates/auths-core/src/witness/server.rs`,
  `crates/auths-keri/src/ksn.rs`,
  `crates/auths-cli/src/commands/key_state.rs`.
- suite (`.recurve`, branch `main`):
  `claims/network/probes/wit-n3.sh`,
  `claims/network/probes/wit-n3.trap/{README.md,stale-ksn/{ksn.json,last_seen}}`,
  `claims/network/probes/fixtures/keri-icp.json`,
  `claims/network/harness/{ksn_oracle.py,ksn_emit.py}`,
  `claims/network/gaps.yaml`, `claims/network/gaps.draft.yaml`,
  `claims/network/GAPS.md`, `claims/network/cycles/WIT-N3/outcome.md`.
