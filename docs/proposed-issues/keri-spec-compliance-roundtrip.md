# KERI spec-compliance: make `icp`/`rot` events round-trip cleanly through keripy / keria / kerigo

## Problem

Auths emits KERI-shaped events under `refs/auths/registry` at `v1/identities/<shard>/<prefix>/events/<seq>.json`, but they have several deviations from the KERI IETF draft / Smith whitepaper that prevent strict spec-conformant verifiers (`keripy`, `keria`, `kerigo`) from accepting them. None of these are silent-correctness hazards inside auths' own validator — they're interop blockers.

After this issue closes, an auths-emitted `icp` or `rot` should serialize/deserialize through `keripy.kering.Serder` (or equivalent) without modification, with the same SAID computed by both implementations.

## Current state

Reference inception event from `bash launch-repo/checks/cli/check_e2e_identity_lifecycle.sh`:

```json
{
  "v":  "KERI10JSON00012f_",
  "t":  "icp",
  "d":  "EZRCNIzUCUvT1rtLf59o26ZTZPKJPgGX_pJHCJ9h-FRw",
  "i":  "EZRCNIzUCUvT1rtLf59o26ZTZPKJPgGX_pJHCJ9h-FRw",
  "s":  "0",
  "kt": "1",
  "k":  ["1AAIA6CVG04Gvoxo7w1BoZBkWUoxt7jW0jslg7zyQ0jcA_wR"],
  "nt": "1",
  "n":  ["EIygB9e6mf-P6QMSw_29sozWVXqWo3crcUKsnwp7XdSI"],
  "bt": "0",
  "b":  [],
  "c":  [],
  "a":  [],
  "x":  "91ngCQXR…04ac11"
}
```

Four concrete deviations:

### 1. Signature lives inside the event body as `x`

KERI signatures are externalized as **CESR attachments** appended after the event body (see `keripy.coring` indexed-signature codes `-A##`, `-B##` for transferable / non-transferable). Auths puts the issuer's signature in a JSON field named `x`. A strict verifier will either:
- Reject the unknown `x` field, or
- Compute a different SAID than auths because `x` participates in the digest (the SAID is computed over the canonical event with `d` placeholder-filled).

The project already documents the same rule for receipts at `crates/auths-keri/src/witness/receipt.rs:1-12`:
> *"Per the spec, the receipt body contains only [v, t, d, i, s]. Signatures are externalized (not in the body)."*

This is also flagged for receipts in `crates/auths-keri/docs/epics.md:1683`. The fix needs to be applied workspace-wide for KEL events.

### 2. `KeriSequence` width is `u64`, spec says `u128`

Internal type at `crates/auths-keri/src/events.rs` (search for `KeriSequence::new`). Spec mandates `u128` because some KERI use cases (e.g. high-throughput witness chains) produce sequence counts that don't fit in `u64`. Documented in `crates/auths-keri/docs/epics.md` as a known follow-up. Not visible in JSON below `2⁶⁴` but a strictly-typed verifier expecting `u128` diverges.

### 3. Sequence-number serialization may be decimal, not hex

Spec specifies `s` is a **hex string**. Inception's `s: "0"` and rotation's `s: "1"` look identical in hex and decimal — the first observable case is sequence 16 (should be `"10"`, not `"16"`). Currently unverified. Search for `KeriSequence::value`/`Display` impl in `crates/auths-keri/src/events.rs`.

### 4. `drt` (delegated rotation) validation returns "not yet implemented"

`crates/auths-keri/src/validate.rs:221-224`:

```rust
Event::Drt(_) => {
    return Err(ValidationError::Serialization(
        "delegated rotation (drt) validation not yet implemented".to_string(),
    ));
}
```

A `dip` (delegated inception) event type is also defined in `crates/auths-keri/docs/epics.md` (Epic 11) but not implemented. Without `drt`, no delegated identifier in auths can ever rotate — silent dead-end. The validator must accept and verify a well-formed `drt` (delegator seal cross-check, per KERI spec §11).

## Required changes

### Phase 1 — externalize the signature

- [ ] Move signature out of the event JSON body. New on-wire shape: canonical JSON event followed by a CESR attachment block carrying the controller's signature(s) — single transferable indexed signature (`-A`) for single-key inception/rotation; multi-sig indexed group (`-A##`) when multi-key thresholds are introduced.
- [ ] Define a `SignedEvent { event_bytes: Vec<u8>, attachments: Vec<u8> }` wrapper in `auths-keri` and use it everywhere the current `(Event, signature)` tuple is passed.
- [ ] SAID is computed over the placeholder-filled canonical event (no `x`); verify this matches what `keripy` produces for an identical event.
- [ ] Update `validate_event_said` and `verify_event_signature` (or equivalent in `crates/auths-keri/src/validate.rs`) to read the externalized attachment.
- [ ] Storage: write the event body and attachment as separate blobs at `v1/identities/<shard>/<prefix>/events/<seq>.json` + `events/<seq>.attachments.cesr` (or one combined file).
- [ ] Migrate `crates/auths-keri/src/witness/receipt.rs` similarly — receipts already have the doc comment saying signatures should be externalized; the field shape needs to follow.

### Phase 2 — sequence width and serialization

- [ ] Widen `KeriSequence` to `u128`. Audit all callers for casts (`as u64`, `try_into::<u64>`, etc.); none should remain.
- [ ] Confirm `Display`/`Serialize` emits hex strings (`"a"` for sequence 10, `"10"` for sequence 16). Add a serialization test that asserts hex output for at least sequences 0, 9, 10, 16, 255, 256, `u64::MAX + 1`.

### Phase 3 — `drt` validation

- [ ] Implement `validate_delegated_rotation(drt, expected_seq, &mut state)` per KERI spec §11. Required checks:
  - `drt.di` (delegator AID) is a known transferable AID
  - The delegator's KEL contains an `ixn` event with a seal whose `i` is `drt.i` and whose `d` is `drt.d` (cross-KEL seal check; this is the load-bearing constraint)
  - Standard rotation rules apply (chain link, sequence, threshold)
- [ ] Add the cross-KEL lookup interface — likely `trait DelegatorKelLookup { fn find_seal(delegator_aid: &Prefix, seal: &Said) -> Option<KeriSequence>; }` so callers can plug in their KEL store.
- [ ] Add `dip` (delegated inception) parallel — same cross-KEL seal pattern.

### Phase 4 — interop conformance test

- [ ] Add an integration test that:
  1. Generates an `icp` + `rot` pair via auths
  2. Serializes them as wire bytes (JSON event + CESR attachment)
  3. Round-trips through keripy via a subprocess (`python3 -c "from keri.core import serdering; …"`) — or, if keripy is too heavy, a fixture file generated by keripy and checked into the repo
  4. Asserts: SAIDs match, signature verifies, `kering.Serder.kvers == "KERI10"`
- [ ] CI gate: this test must pass for any changes to KEL event serialization.

## Acceptance criteria

1. `rg '"x":' crates/auths-keri/src crates/auths-id/src` returns zero hits in event-body construction code.
2. `KeriSequence` is `u128`; `cargo expand` shows no `u64` in its definition.
3. Sequence 16 round-trips as `"s": "10"` (hex).
4. `cargo test -p auths-keri --lib validate_delegated_rotation` passes.
5. The keripy interop test passes in CI.
6. `crates/auths-keri/docs/spec_compliance_audit.md` updated: every previously-flagged item moved from "open" to "resolved" or has a follow-up issue linked.

## Out of scope

- **Multi-key / weighted-threshold inception** (`kt: ["1/2", "1/2", "1/2"]`). Spec-legal already; using scalar `kt: "1"` is also spec-legal. Whether to expose multi-key controllers at the CLI is a separate product question (covered by the kels comparison work in `launch-repo/collab_bordumb_rotation.md`).
- **`ixn` event emission for device link/unlink anchoring.** That's the sister issue — see `keri-ixn-anchored-attestations.md`. Note: this issue's `drt` work *uses* `ixn` events (delegator's KEL must contain a seal), but only on the read path; emitting them is a different scope.
- **CESR binary (terse) domain.** This issue covers CESR text-domain attachments only. Binary domain is a future optimization.
- **TEL (Transaction Event Log) registries / ACDC.** Separate epic — useful for credential issuance, not required for KEL spec compliance.

## References

- KERI IETF draft: https://datatracker.ietf.org/doc/draft-ssmith-keri/
- Smith whitepaper: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf
- CESR spec: https://datatracker.ietf.org/doc/draft-ssmith-cesr/
- keripy reference: https://github.com/WebOfTrust/keripy
- Existing audit: `crates/auths-keri/docs/spec_compliance_audit.md`
- Existing epic notes: `crates/auths-keri/docs/epics.md`
- Auths' own E2E run showing the `x` field deviation: `launch-repo/checks/cli/output/e2e_lifecycle.md` ("Spec deviations" callout under Inception event)
- Sister issue (architecturally related): `keri-ixn-anchored-attestations.md`
