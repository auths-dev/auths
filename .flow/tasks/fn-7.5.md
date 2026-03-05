# fn-7.5 Structured BridgeError and VerifyResult reason enums

## Description

Replace bare `String` context in `BridgeError` with structured fields carrying typed DIDs. Replace `VerifyResult` reason strings with enum variants. Both in `crates/auths-radicle/src/bridge.rs`.

Depends on fn-7.1 (ResourceId, Role) since VerifyResult reason enums may reference these types.

### BridgeError (bridge.rs ~line 141)

Current: tuple variants each wrapping a single `String` (e.g., `IdentityLoad(String)`). Already `#[non_exhaustive]`.
Proposed: struct variants with typed DID fields. Keep `#[non_exhaustive]`.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeError {
    #[error("failed to load identity {did}: {reason}")]
    IdentityLoad { did: IdentityDID, reason: String },

    #[error("failed to load attestation for device {device_did}: {reason}")]
    AttestationLoad { device_did: DeviceDID, reason: String },

    #[error("identity {did} has corrupt KEL: {reason}")]
    IdentityCorrupt { did: IdentityDID, reason: String },

    #[error("policy evaluation failed for {did}: {reason}")]
    PolicyEvaluation { did: IdentityDID, reason: String },

    #[error("invalid device key: {reason}")]
    InvalidDeviceKey { reason: String },

    #[error("repository access error: {reason}")]
    Repository { reason: String },
}
```

Update all `BridgeError` construction sites in bridge.rs and any other files in auths-radicle.

### VerifyResult reason enums (bridge.rs ~line 41)

Current `VerifyResult` already has `#[non_exhaustive]` with 4 variants: `Verified { reason: String }`, `Rejected { reason: String }`, `Warn { reason: String }`, `Quarantine { reason: String, identity_repo_rid: Option<RepoId> }`. Replace the `String` reasons with typed enums:

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifyReason {
    DeviceAttested,
    LegacyDidKey,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RejectReason {
    Revoked,
    Expired,
    NoAttestation,
    PolicyDenied { capability: String },
    KelCorrupt,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WarnReason {
    ObserveModeRejection(RejectReason),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum QuarantineReason {
    StaleNode,
    MissingIdentityRepo,
    InsufficientKelSequence { have: u64, need: u64 },
}
```

Update `VerifyResult`:
```rust
#[non_exhaustive]
pub enum VerifyResult {
    Verified { reason: VerifyReason },
    Rejected { reason: RejectReason },
    Warn { reason: WarnReason },
    Quarantine { reason: QuarantineReason, identity_repo_rid: Option<RepoId> },
}
```

Add `Display` impls for all reason enums so logging still produces readable messages.

### Files affected

- `crates/auths-radicle/src/bridge.rs` — definitions + all construction sites
- `crates/auths-radicle/src/lib.rs` — re-exports
- Any Heartwood integration code that matches on VerifyResult/BridgeError
- Test files matching on these types

### Quick commands

```bash
cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] `BridgeError` variants carry typed DID fields
- [ ] `VerifyReason`, `RejectReason`, `WarnReason`, `QuarantineReason` enums
- [ ] All reason enums are `#[non_exhaustive]`
- [ ] All reason enums implement `Display`
- [ ] `VerifyResult` uses reason enums instead of `String`
- [ ] All construction sites in bridge.rs updated
- [ ] `cargo build -p auths-radicle --all-features` passes
- [ ] `cargo nextest run -p auths-radicle` passes

## Done summary
Replaced bare String fields in BridgeError with struct variants carrying typed IdentityDID/DeviceDID fields. Added VerifyReason, RejectReason, WarnReason, QuarantineReason enums with Display impls. All enums are #[non_exhaustive]. Updated all construction/match sites across bridge.rs, verify.rs, storage.rs, and 4 test files. Fixed KeriSequence in storage.rs test. 43/43 tests pass.
## Evidence
- Commits:
- Tests:
- PRs:
