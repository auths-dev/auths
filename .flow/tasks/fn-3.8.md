# fn-3.8 Implement identity deduplication in meets_threshold

## Description
REWRITE the `verify_multiple_signers` logic from scratch. The current "count every signature" approach violates Radicle's consensus rules (the "Person Rule": one identity = one vote).

## Strict Requirements

1. **REWRITE**: `verify_multiple_signers` must return `BTreeMap<IdentityDid, Vec<VerifyResult>>` -- results grouped by identity, not by device
2. **TOTAL REPLACEMENT**: Delete the previous "count every `is_allowed()` result" logic entirely. The new function groups by identity DID, then `meets_threshold` iterates over the map keys.
3. **Identity DID types**:
   - `did:keri:` signers: grouped by their KERI identity DID (all devices under same identity = 1 entry)
   - `did:key:` signers (legacy): each is its own identity (1 device = 1 entry)
4. **`meets_threshold`**: counts `map.keys().filter(|k| k.has_verified_result()).count()` against threshold

## Implementation

```rust
pub struct IdentityDid(String); // did:keri:... or did:key:... for legacy

pub fn verify_multiple_signers(
    bridge: &impl RadicleAuthsBridge,
    signers: &[SignerInput],
    request_template: &VerifyRequest,
) -> Result<BTreeMap<IdentityDid, Vec<VerifyResult>>, BridgeError>

pub fn meets_threshold(
    results: &BTreeMap<IdentityDid, Vec<VerifyResult>>,
    threshold: usize,
) -> bool
```

The `IdentityDid` for a `did:keri` signer comes from `find_identity_for_device()`. For legacy `did:key` signers, the device DID itself becomes the identity DID.

## Key Files
- `crates/auths-radicle/src/verify.rs:332-338` -- DELETE old `meets_threshold`
- `crates/auths-radicle/src/verify.rs` -- REWRITE `verify_multiple_signers`
- `crates/auths-radicle/src/bridge.rs:225-230` -- `SignerInput` enum

## Test Plan
- Test: 3 devices under same `did:keri` identity -> 1 entry in map -> 1 vote
- Test: 2 different `did:keri` identities -> 2 entries -> 2 votes
- Test: mixed `did:key` + `did:keri` -> correct entry count
- Test: threshold met with exactly enough unique identities
- Test: threshold NOT met when same identity signs from multiple devices
- Test: threshold=1 met by any single device from any identity
## Problem

The current `meets_threshold` at `crates/auths-radicle/src/verify.rs:332-338` counts each `is_allowed()` result independently. If Alice has 3 devices all signing a commit, that counts as 3 verified signers. Per Radicle protocol rules ("multiple signatures made by the set of keys of a Person SHALL be counted as only one vote"), this violates Radicle's consensus rules. Without this fix, the integration would allow a single multi-device identity to unilaterally reach any threshold by signing from enough devices.

## Implementation

In `crates/auths-radicle/src/verify.rs`:

1. Modify `verify_multiple_signers()` or `meets_threshold()`:
   - After verifying each signer, group results by the `identity_did` (the `did:keri:` DID, not the `did:key:` device DID)
   - For legacy `did:key` signers (no KERI identity), each counts as its own identity
   - Count unique identities that have at least one `Verified` result
   - Compare unique identity count against threshold

2. The `VerifyResult::Verified` may need to carry the identity DID for deduplication:
   - Consider adding an `identity_did: Option<String>` field to the `Verified` variant
   - Or return a `VerifiedSigner { device_did, identity_did, result }` struct from `verify_multiple_signers`

3. Handle the mixed case: `[did:key:A (legacy), did:keri:B/device1, did:keri:B/device2]` with threshold 2 -> `did:key:A` = 1 vote, `did:keri:B` = 1 vote -> meets threshold 2

## Key Files
- `crates/auths-radicle/src/verify.rs:332-338` -- `meets_threshold()` (or `verify_multiple_signers`)
- `crates/auths-radicle/src/bridge.rs:225-230` -- `SignerInput` enum (carries identity context)

## Test Plan
- Test: 3 devices under same KERI identity = 1 vote
- Test: 2 different KERI identities = 2 votes
- Test: mixed `did:key` + `did:keri` delegates counted correctly
- Test: threshold met with exactly enough unique identities
- Test: threshold NOT met when same identity has multiple devices signing
- Test: edge case -- threshold=1 met by any single device from any identity
## Problem

The current `meets_threshold` at `crates/auths-radicle/src/verify.rs:332-338` counts each `is_allowed()` result independently. If Alice has 3 devices all signing a commit, that counts as 3 verified signers. Per Radicle protocol rules ("multiple signatures made by the set of keys of a Person SHALL be counted as only one vote"), this is incorrect.

## Implementation

In `crates/auths-radicle/src/verify.rs`:

1. Modify `verify_multiple_signers()` or `meets_threshold()`:
   - After verifying each signer, group results by the `identity_did` (the `did:keri:` DID, not the `did:key:` device DID)
   - For legacy `did:key` signers (no KERI identity), each counts as its own identity
   - Count unique identities that have at least one `Verified` result
   - Compare unique identity count against threshold

2. The `VerifyResult::Verified` may need to carry the identity DID for deduplication:
   - Consider adding an `identity_did: Option<String>` field to the `Verified` variant
   - Or return a `VerifiedSigner { device_did, identity_did, result }` struct from `verify_multiple_signers`

3. Handle the mixed case: `[did:key:A (legacy), did:keri:B/device1, did:keri:B/device2]` with threshold 2 -> `did:key:A` = 1 vote, `did:keri:B` = 1 vote -> meets threshold 2

## Key Files
- `crates/auths-radicle/src/verify.rs:332-338` -- `meets_threshold()` (or `verify_multiple_signers`)
- `crates/auths-radicle/src/bridge.rs:225-230` -- `SignerInput` enum (carries identity context)

## Test Plan
- Test: 3 devices under same KERI identity = 1 vote
- Test: 2 different KERI identities = 2 votes
- Test: mixed `did:key` + `did:keri` delegates counted correctly
- Test: threshold met with exactly enough unique identities
- Test: threshold NOT met when same identity has multiple devices signing

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `verify_multiple_signers` returns `BTreeMap<IdentityDid, Vec<VerifyResult>>`
- [ ] Old "count every signature" logic DELETED
- [ ] `did:keri` devices grouped under single identity entry
- [ ] Legacy `did:key` each gets own identity entry
- [ ] `meets_threshold` iterates map keys, not raw signature count
- [ ] Test: 3 devices, 1 identity = 1 vote
- [ ] Test: 2 identities = 2 votes
- [ ] Test: mixed `did:key` + `did:keri` correct
- [ ] Test: threshold boundary (exact match)
- [ ] Test: same identity multiple devices != multiple votes
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
Rewrote verify_multiple_signers to return BTreeMap<IdentityDid, Vec<VerifyResult>>. Added IdentityDid newtype. meets_threshold counts unique identity keys. Updated SignerInput::PreVerified to carry DID. 7 dedup tests.
## Evidence
- Commits: baa1dae
- Tests: same_keri_identity_multiple_devices_one_vote, two_different_keri_identities_two_votes, mixed_did_key_and_did_keri_correct_count, threshold_one_met_by_any_single_device, mixed_threshold_one_keri_revoked, empty_signers_threshold_zero_passes, mixed_threshold_verification
- PRs:
