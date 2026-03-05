# fn-3.3 Add RadAttestation <-> Attestation conversion layer

## Description
REPLACE any internal logic in `auths-radicle` that expects a single JSON file for attestations. The 2-blob format is the ONLY supported format for Radicle projects. This is one of the two critical "glue" tasks (alongside fn-3.6) that makes the integration real.

## Strict Requirements

1. **REPLACE**: The `TryFrom` conversion is the mandatory gateway -- all attestation I/O in `auths-radicle` goes through `RadAttestation`
2. **ERROR on old format**: If `load_attestation` finds a single JSON file instead of the `{did-key, did-keri}` blob pair, it MUST return an error. No "fix-up" logic. No silent migration.
3. **JCS mandatory**: All `RadCanonicalPayload` serialization MUST use `json-canon` for deterministic output. Non-canonical JSON is a rejection, not a warning.
4. **DELETE** any code paths that read/write single-JSON attestation format in `auths-radicle`

## Implementation

In `crates/auths-radicle/src/attestation.rs`:
1. `impl TryFrom<RadAttestation> for Attestation` -- 2-blob -> verification-ready JSON
2. `impl TryFrom<&Attestation> for RadAttestation` -- JSON -> 2-blob for storage
3. Both conversions enforce JCS canonical ordering via `json-canon`
4. Conversion errors are typed (`AttestationConversionError`), not strings

## Key Files
- `crates/auths-radicle/src/attestation.rs:35-155` -- `RadAttestation`, `RadCanonicalPayload`
- `crates/auths-verifier/src/core/attestation.rs` -- `Attestation` type
- `crates/auths-radicle/src/verify.rs:67-91` -- `AuthsStorage::load_attestation()` return type

## Test Plan
- Round-trip: `Attestation` -> `RadAttestation` -> `Attestation` preserves all fields
- `from_blobs()` -> `Attestation` conversion produces valid attestation
- Malformed input returns `AttestationConversionError` (not panic)
- Serialized payload matches JCS canonical form (byte-for-byte deterministic)
- Single JSON file input returns error (not silently accepted)
## Problem

The bridge's `AuthsStorage::load_attestation()` returns `auths_verifier::core::Attestation`, but RIP-X specifies storing attestations as two raw signature blobs at `refs/keys/<nid>/signatures/{did-key,did-keri}`. The real Git storage (fn-3.6) needs to read 2-blob format and produce the JSON `Attestation` type the bridge expects.

## Implementation

In `crates/auths-radicle/src/attestation.rs`:
1. Add `impl TryFrom<RadAttestation> for Attestation` -- converts 2-blob format to the verification-ready JSON Attestation
2. Add `impl TryFrom<&Attestation> for RadAttestation` -- converts JSON Attestation to 2-blob format for storage
3. Handle the `RadCanonicalPayload` (JCS RFC 8785) serialization that bridges the two formats
4. Ensure canonical field ordering in serialization -- the KERI improvement review notes that cross-language compatibility requires deterministic JSON output (JCS compliance). Use `json-canon` for all payload serialization to prevent signature-valid but semantically-different payloads.

## Key Files
- `crates/auths-radicle/src/attestation.rs:35-155` -- `RadAttestation`, `RadCanonicalPayload`, `from_blobs()`, `to_blobs()`, `verify()`
- `crates/auths-verifier/src/core/attestation.rs` -- `Attestation` type (target type)
- `crates/auths-radicle/src/verify.rs:67-91` -- `AuthsStorage::load_attestation()` return type

## Test Plan
- Unit test: round-trip `Attestation` -> `RadAttestation` -> `Attestation` preserves all fields
- Unit test: `RadAttestation::from_blobs()` -> `Attestation` conversion produces valid attestation
- Unit test: conversion fails gracefully on malformed input
- Unit test: serialized payload matches JCS canonical form (deterministic byte-for-byte)
## Problem

The bridge's `AuthsStorage::load_attestation()` returns `auths_verifier::core::Attestation`, but RIP-X specifies storing attestations as two raw signature blobs at `refs/keys/<nid>/signatures/{did-key,did-keri}`. The real Git storage (fn-3.6) needs to read 2-blob format and produce the JSON `Attestation` type the bridge expects.

## Implementation

In `crates/auths-radicle/src/attestation.rs`:
1. Add `impl TryFrom<RadAttestation> for Attestation` -- converts 2-blob format to the verification-ready JSON Attestation
2. Add `impl TryFrom<&Attestation> for RadAttestation` -- converts JSON Attestation to 2-blob format for storage
3. Handle the `RadCanonicalPayload` (JCS RFC 8785) serialization that bridges the two formats

## Key Files
- `crates/auths-radicle/src/attestation.rs:35-155` -- `RadAttestation`, `RadCanonicalPayload`, `from_blobs()`, `to_blobs()`, `verify()`
- `crates/auths-verifier/src/core/attestation.rs` -- `Attestation` type (target type)
- `crates/auths-radicle/src/verify.rs:67-91` -- `AuthsStorage::load_attestation()` return type

## Test Plan
- Unit test: round-trip `Attestation` -> `RadAttestation` -> `Attestation` preserves all fields
- Unit test: `RadAttestation::from_blobs()` -> `Attestation` conversion produces valid attestation
- Unit test: conversion fails gracefully on malformed input

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `TryFrom<RadAttestation> for Attestation` implemented
- [ ] `TryFrom<&Attestation> for RadAttestation` implemented
- [ ] Single JSON attestation format returns error (not accepted)
- [ ] All serialization uses `json-canon` (JCS)
- [ ] `AttestationConversionError` is a `thiserror` enum
- [ ] Round-trip test passes (all fields preserved)
- [ ] Malformed input test returns typed error
- [ ] JCS canonical form test passes (byte-for-byte)
- [ ] Zero code paths read/write single-JSON attestation format
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
Added TryFrom<RadAttestation> for Attestation and TryFrom<&Attestation> for RadAttestation with JCS canonicalization. Added AttestationConversionError thiserror enum. Enriched RadAttestation with device_did and device_public_key. 8 new tests: round-trip, malformed input, JCS determinism, byte stability.
## Evidence
- Commits:
- Tests: round_trip_attestation_conversion, rad_attestation_to_core_attestation, core_attestation_to_rad_attestation, conversion_rejects_wrong_pubkey_length, jcs_canonical_form_byte_stable, canonical_payload_deterministic
- PRs:
