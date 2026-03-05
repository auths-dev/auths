# fn-7.6 SDK typed DIDs, Vec<Capability>, ResolvedDid enum

## Description

Three changes: (1) SDK result types use IdentityDID/DeviceDID, (2) Vec<String> capabilities → Vec<Capability>, (3) ResolvedDid struct → enum.

Depends on fn-7.1 (ResourceId for DeviceLinkResult.attestation_id) and fn-7.2 (Ed25519PublicKey for ResolvedDid).

> **Risk note**: Change (3) — converting `ResolvedDid` from struct to enum — is the highest-risk change in this epic. It alters every call site that destructures or constructs `ResolvedDid`, and every `DidResolver` implementor. Consider landing changes (1) and (2) first as a separate commit, then (3) in its own commit for easier bisection if something breaks.

### 1. SDK result types (crates/auths-sdk/src/result.rs)

Replace all bare `String` DID fields:
- `SetupResult.identity_did: String` → `IdentityDID`
- `SetupResult.device_did: String` → `DeviceDID`
- `CiSetupResult.identity_did: String` → `IdentityDID`
- `CiSetupResult.device_did: String` → `DeviceDID`
- `DeviceLinkResult.device_did: String` → `DeviceDID`
- `DeviceLinkResult.attestation_id: String` → `ResourceId`
- `RotationResult.controller_did: String` → `IdentityDID`
- `DeviceExtensionResult.device_did: String` → `DeviceDID`
- `AgentSetupResult.agent_did: String` → `IdentityDID`
- `AgentSetupResult.parent_did: String` → `IdentityDID`
- Any other result structs with String DIDs

Also: `AgentSetupResult.capabilities: Vec<String>` → `Vec<Capability>`

Update all construction sites in:
- `crates/auths-sdk/src/workflows/setup.rs`
- `crates/auths-sdk/src/workflows/device.rs`
- `crates/auths-sdk/src/workflows/rotation.rs`
- `crates/auths-sdk/src/workflows/agent.rs`

### 2. Vec<String> capabilities → Vec<Capability> (plan items 9)

- `AgentSetupConfig.capabilities: Vec<String>` → `Vec<Capability>` (auths-sdk/src/types.rs ~line 375)
- `DeviceLinkConfig.capabilities: Vec<String>` → `Vec<Capability>` (auths-sdk/src/types.rs ~line 586)
- `PairingSessionParams.capabilities` and related fields (auths-sdk/src/pairing.rs)
- `AddMemberCommand.capabilities: Vec<String>` → `Vec<Capability>` (auths-sdk/src/workflows/org.rs)

### 3. ResolvedDid struct → enum (crates/auths-core/src/signing.rs ~line 92)

Current struct has `did: String`, `public_key: Vec<u8>` (→ `Ed25519PublicKey` after fn-7.2), `method: DidMethod`.
Current `DidMethod` enum (~line 60): `Key` (unit), `Keri { sequence: u64, can_rotate: bool }` (struct variant).
Proposed: absorb `DidMethod` fields into `ResolvedDid` variants:
```rust
pub enum ResolvedDid {
    Key {
        did: DeviceDID,
        public_key: Ed25519PublicKey,
    },
    Keri {
        did: KeriDid,
        public_key: Ed25519PublicKey,
        sequence: u64,
        can_rotate: bool,
    },
}

impl ResolvedDid {
    pub fn public_key(&self) -> &Ed25519PublicKey { ... }
    pub fn did_string(&self) -> &str { ... }
}
```

Delete `DidMethod` enum — it's subsumed by the ResolvedDid variants.

ResolvedDid is NOT serialized (no serde) — pure API change.

Note: `ResolvedIdentity` in `crates/auths-core/src/ports/network.rs` (~line 126) is structurally identical to `ResolvedDid` but is a separate type for network resolution. Decide whether to also convert it to an enum or leave it as a struct — if kept as a struct, document why the two types diverge.

Affected `DidResolver` implementors:
- `crates/auths-id/src/resolve.rs` — must return enum variants
- `crates/auths-radicle/src/identity.rs` — must return enum variants
- All callers that destructure `resolved.did`, `resolved.public_key`, `resolved.method`

### Quick commands

```bash
cargo build -p auths-sdk --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-core --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths_cli --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] All SDK result structs use `IdentityDID`/`DeviceDID`/`ResourceId`
- [ ] All capability fields use `Vec<Capability>`
- [ ] `ResolvedDid` is an enum with `Key` and `Keri` variants
- [ ] `DidMethod` enum deleted
- [ ] `public_key()` and `did_string()` accessor methods on `ResolvedDid`
- [ ] Both `DidResolver` implementors updated
- [ ] `cargo build -p auths-sdk --all-features` passes
- [ ] `cargo build -p auths-core --all-features` passes
- [ ] `cargo build -p auths-id --all-features` passes
- [ ] `cargo build -p auths-radicle --all-features` passes (DidResolver impl there)
- [ ] `cargo nextest run --workspace` passes

## Done summary
Completed fn-7.6: SDK typed DIDs, Vec<Capability>, ResolvedDid enum.

Part 1+2: Replaced String fields with IdentityDID, DeviceDID, ResourceId, and Vec<Capability> across SDK result/config types, setup.rs, device.rs, rotation.rs, and CLI callers.

Part 3: Converted ResolvedDid from struct+DidMethod to enum with Key{did,public_key} and Keri{did,public_key,sequence,can_rotate} variants. Applied same pattern to ResolvedIdentity. Deleted DidMethod enum entirely. Updated all 8 construction sites across auths-id, auths-radicle, auths-infra-http. Fixed KeriSequence leftovers in auths-id tests.

All 337 auths-id tests and 70 auths-sdk tests pass.
## Evidence
- Commits: 8a30b64, e6186ee
- Tests:
- PRs:
