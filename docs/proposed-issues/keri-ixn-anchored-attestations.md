# Anchor device attestations as `ixn` seals so the KEL becomes the authoritative device-event log

## Problem

Auths' KEL today carries only `icp` (inception) and `rot` (rotation) events. Device link/unlink — the lifecycle that authorizes which devices can sign on behalf of a controller — happens entirely outside the KEL: attestation JSON blobs are written to `refs/auths/registry` under `v1/devices/<shard>/did_key_<subject>/attestation.json`, with a parallel `history/<ts>_.auths.json` audit trail. Linking emits a Git commit; unlinking emits another.

This works as a Git-native audit trail but means:

1. **The KEL is not the authoritative ordering of device events.** A consumer who walks just the KEL has no record of which devices were authorized when.
2. **Witnesses don't receipt device events.** Witness servers receipt `icp`/`rot`/`ixn`. Since auths never emits `ixn`, witnesses have no evidence of any device change. Compromise + retroactive device-link tampering would be invisible to a witness-quorum verifier.
3. **No cryptographic chain on device events.** Git commit lineage gives ordering but not the same SAID-chain integrity that KEL events have.

The KERI-spec-aligned answer: emit an `ixn` event on every device link/unlink, with an `a[]` seal containing the SAID of the canonicalized attestation. The attestation blob continues to live in Git (it's the off-event payload the seal commits to) but the **authoritative link/unlink record becomes the sealed `ixn` event in the KEL**.

This is the `ixn`-anchoring conversation raised by `@rank5.syzygy` in our KERI-team comparison: in his (kels) model, every recovery / link / unlink is an event in the chain, not a side-channel artifact. Auths should match that property — without changing its Git-native storage philosophy.

## Current state

### What auths has

- `icp` and `rot` events: emitted, validated, witness-receiptable. See `bash launch-repo/checks/cli/check_e2e_identity_lifecycle.sh` for a working end-to-end example.
- `ixn` event type: **defined and validated** in `crates/auths-keri/src/events.rs` and `crates/auths-keri/src/validate.rs:215-218` — but **never emitted** by any caller. The validator handles `Event::Ixn(ixn)` correctly; production code just doesn't construct one.
- Device attestations: stored as JSON blobs at `refs/auths/registry`. Reference example produced by `auths init`:

  ```json
  {
    "version": 1,
    "rid": ".auths",
    "issuer":  "did:keri:E…",
    "subject": "did:key:zDna…",
    "device_public_key": { "curve": "p256", "key": "03…" },
    "identity_signature": "…",
    "device_signature":   "…",
    "timestamp": "2026-04-14T11:23:48.546747Z",
    "note": "Linked by auths-sdk setup"
  }
  ```

- `Seal` type: defined in `crates/auths-keri/src/events.rs` (search for `pub struct Seal` / `digest_value()`); `validate.rs` already searches for seals via `find_seal_in_kel(events: &[Event], digest: &str)` (`validate.rs:764-782`).
- Attestation storage code path: `crates/auths-storage/src/git/adapter.rs:89` (`REGISTRY_REF = "refs/auths/registry"`).

### What's missing

- An `ixn` event emitter for device link/unlink.
- A canonical-attestation hash function whose output goes into `seal.d`.
- Wiring in `auths-id::device::link` / `auths-id::device::revoke` (or wherever those flows live in `auths-sdk::workflows::device::*`) so each link/unlink builds and writes an `ixn` to the KEL alongside the existing Git ref blob write.
- Witness-receipt path for `ixn` (assuming witness server is wired into the flow at all — see "open question" below).

## Required changes

### Phase 1 — emit `ixn` on device link

- [ ] Add `auths_id::keri::interaction::emit_link_event(controller_signer, attestation: &DeviceAttestation, kel: &mut GitKel) -> Result<IxnEvent, …>`. Implementation:
  1. Canonicalize the attestation JSON (use `json-canon`, same as today)
  2. Compute Blake3-256 SAID of the canonical bytes
  3. Build `IxnEvent { v, t: "ixn", d: <SAID-of-this-event>, i: controller_aid, s: next_seq, p: prev_event_d, a: vec![Seal::Digest { d: <attestation_SAID> }] }` (use whichever `Seal` variant in `auths-keri::events::Seal` represents a digest seal — confirm by reading `seal.digest_value()`)
  4. Run `finalize_ixn_event` (`crates/auths-keri/src/validate.rs:747-762`) to compute the event's own SAID + version-string size
  5. Sign with the controller's current key (Phase 1 of the spec-compliance issue; if that hasn't landed, fall back to in-body `x` for now and migrate later)
  6. Append to KEL via `GitKel::append_event` (or whatever the `auths-infra-git::GitEventLog::append` equivalent is)
- [ ] Wire this into `auths-sdk::workflows::device::link` — every successful device authorization writes the attestation blob AND emits the `ixn`. Both writes should land in the same Git commit if possible (same `refs/auths/registry` ref); if not, emit the `ixn` first so a partial failure leaves a sealed-but-missing-payload state (recoverable: rewrite the payload), not the inverse (orphaned attestation a verifier can't tie to anything).
- [ ] Update `auths device link` CLI to surface the new `ixn` SAID in `--json` output for scriptability.

### Phase 2 — emit `ixn` on device unlink / revoke

- [ ] Same shape, different intent. The `ixn` for unlinking commits to a "revocation attestation" — same canonical attestation shape with an additional field (e.g. `revoked: true`, `revocation_timestamp: …`, signed by the controller). Hash that revocation attestation, put its SAID in the `ixn`'s `a[]`.
- [ ] Wire into `auths-sdk::workflows::device::revoke`.

### Phase 3 — KEL-walk replaces Git-ref-walk for device queries

- [ ] Add `auths-id::device::resolve_authorized_devices(controller_aid, at_seq: Option<u64>) -> Vec<DeviceAuthorization>`. Implementation:
  1. Load the controller's KEL
  2. Walk events; collect every `ixn`'s seals
  3. Resolve each seal's SAID to its on-disk attestation blob
  4. Apply link/unlink semantics in seal order (later unlink overrides earlier link)
  5. Filter to the snapshot at `at_seq` if specified
- [ ] Switch `auths device list` and the device-resolution path used during signature verification to call this function instead of doing a direct Git-ref scan. Old Git-ref scan can stay as a fallback / cross-check during a deprecation window.

### Phase 4 — witness receipts cover device events

- [ ] Confirm `auths-core::witness::server` accepts `ixn` events (it should — the validator does). If not, extend.
- [ ] Update the `WitnessConfig` flow so device link/unlink, when witnesses are configured, sends the new `ixn` to witnesses for receipt — same path as `icp`/`rot` already use.
- [ ] Add a verification rule that, given a controller config requiring `bt > 0` for device events, rejects device authorizations whose `ixn` lacks the witness threshold's worth of receipts.

### Phase 5 — backfill & migration

- [ ] One-off migration tool: scan existing `refs/auths/registry` device blobs, compute their SAIDs, emit one `ixn` per blob in chronological order (use the existing `history/<ts>_.auths.json` timestamps to order). This brings the KEL into sync with already-linked devices.
- [ ] Document that pre-migration attestations have no KEL anchor and require operator action to migrate.

## Acceptance criteria

1. `bash launch-repo/checks/cli/check_e2e_identity_lifecycle.sh` shows an `ixn` event in the KEL for the bootstrap device-A link (currently shows only `icp`).
2. `auths device link` (Phase 3 of the existing e2e check) emits an `ixn` with seq = 2; KEL now has icp(0) → rot(1) → ixn(2).
3. `auths device list` produces identical output whether it walks the KEL (`ixn` seals) or the legacy Git-ref scan, on any pre-existing identity.
4. `cargo test -p auths-id --lib device::resolve_authorized_devices` passes with cases covering: link, link-then-revoke, link-revoke-relink, link with witness threshold unmet (rejected).
5. A witness-quorum-required identity rejects device-link sigs that lack receipts (integration test in `crates/auths-core/tests/cases/witness_quorum.rs`).

## Open questions for design review (resolve before Phase 1)

1. **One `ixn` per device event, or batch?** Spec allows multiple seals in `a[]`. Batching is cheaper but couples link/unlink ordering across devices. Recommend: one event per action for clarity, optimize later if KEL bloat is real.
2. **Same KEL for identity + device events, or separate KELs?** auths today has one KEL per controller. ACDC / TEL designs use a separate Transaction Event Log per registry. For device events, one KEL is fine because every device-event is controller-issued. If we ever support delegated device authorization (a paired admin device authorizes a third device), revisit — that's when a TEL becomes useful.
3. **Pre-Phase-1 spec-compliance work (sister issue) vs this issue: which lands first?** Recommend sister issue lands first (`x` externalization, `drt`, `u128`). This issue depends on signed-event-attachment shape being stable. If we land this issue first, every emitted `ixn` will have an in-body `x` and need migrating later.

## Out of scope

- **TEL (Transaction Event Log) registries.** A more general mechanism than `ixn` seals; the right answer if we ever ship credential issuance (ACDC). Not needed for device-link anchoring.
- **ACDC migration of device attestations.** Separate question — would change the *payload* shape, not the *anchoring* mechanism. Can land independently.
- **Multi-key or weighted-threshold inception.** Different epic (kels-comparison work).

## References

- KERI IETF draft, §6 (`ixn` events) and §7 (anchored seals): https://datatracker.ietf.org/doc/draft-ssmith-keri/
- Existing `Ixn` validation: `crates/auths-keri/src/validate.rs:215-218`
- Existing seal lookup: `crates/auths-keri/src/validate.rs:764-782` (`find_seal_in_kel`)
- Existing finalizer: `crates/auths-keri/src/validate.rs:747-762` (`finalize_ixn_event`)
- Current device-attestation storage: `crates/auths-storage/src/git/adapter.rs:89`
- Working device-attestation reference: `bash launch-repo/checks/cli/check_e2e_identity_lifecycle.sh` and the JSON in `launch-repo/collab_bordumb_rotation.md`
- KERI-team conversation context: `launch-repo/collab_bordumb_rotation.md` and the rank5.syzygy `sign_v1/rec/3` example
- Sister issue (must land first): `keri-spec-compliance-roundtrip.md`
