# Organization Workflows

The `auths-sdk` crate provides orchestration functions for organization member management. All workflows accept an `OrgContext` carrying injected infrastructure adapters, ensuring the CLI and any future SCIM provider call the same underlying logic.

## OrgContext

Organization workflows use a lightweight `OrgContext` struct instead of the full `AuthsContext` builder. This bundles the five adapters needed for org operations.

```rust
use auths_sdk::workflows::org::OrgContext;
use auths_core::ports::clock::SystemClock;
use auths_core::ports::id::SystemUuidProvider;
use auths_core::signing::StorageSigner;

let uuid_provider = SystemUuidProvider;
let signer = StorageSigner::new(keychain);

let ctx = OrgContext {
    registry: &backend,
    clock: &SystemClock,
    uuid_provider: &uuid_provider,
    signer: &signer,
    passphrase_provider: &passphrase_provider,
};
```

### OrgContext Fields

| Field | Type | Purpose |
|---|---|---|
| `registry` | `&dyn RegistryBackend` | Read/write org member attestations |
| `clock` | `&dyn ClockProvider` | Wall-clock for timestamps |
| `uuid_provider` | `&dyn UuidProvider` | Generate attestation resource IDs |
| `signer` | `&dyn SecureSigner` | Sign attestations with identity key |
| `passphrase_provider` | `&dyn PassphraseProvider` | Obtain key decryption passphrases |

## Add Member

`add_organization_member` verifies the caller holds `manage_members`, creates a cryptographically signed attestation via `auths-id`, and stores it in the registry.

```rust
use auths_sdk::workflows::org::{AddMemberCommand, add_organization_member};

let cmd = AddMemberCommand {
    org_prefix: "EOrg1234567890".into(),
    member_did: "did:key:z6Mk...".into(),
    member_public_key: Ed25519PublicKey::from_bytes(pk_bytes),
    member_curve: auths_crypto::CurveType::Ed25519,
    role: Role::Member,
    capabilities: vec!["sign_commit".into()],
    admin_public_key_hex: hex::encode(&admin_pk),
    signer_alias: KeyAlias::new_unchecked("org-myorg"),
    note: Some("Added by admin".into()),
};

let attestation = add_organization_member(&ctx, cmd)?;
```

## Revoke Member

`revoke_organization_member` verifies admin privileges, checks the member exists and is active, then creates a signed revocation attestation.

```rust
use auths_sdk::workflows::org::{RevokeMemberCommand, revoke_organization_member};

let cmd = RevokeMemberCommand {
    org_prefix: "EOrg1234567890".into(),
    member_did: "did:key:z6Mk...".into(),
    member_public_key: Ed25519PublicKey::from_bytes(pk_bytes),
    member_curve: auths_crypto::CurveType::Ed25519,
    admin_public_key_hex: hex::encode(&admin_pk),
    signer_alias: KeyAlias::new_unchecked("org-myorg"),
    note: Some("Policy violation".into()),
};

let revocation = revoke_organization_member(&ctx, cmd)?;
assert!(revocation.is_revoked());
```

## Update Capabilities

`update_member_capabilities` replaces a member's capability set without re-signing. Takes `&dyn RegistryBackend` and `&dyn ClockProvider` directly.

```rust
use auths_sdk::workflows::org::{UpdateCapabilitiesCommand, update_member_capabilities};

let cmd = UpdateCapabilitiesCommand {
    org_prefix: "EOrg1234567890".into(),
    member_did: "did:key:z6Mk...".into(),
    capabilities: vec!["sign_commit".into(), "sign_release".into()],
    public_key_hex: hex::encode(&admin_pk),
};

let updated = update_member_capabilities(backend, clock, cmd)?;
```

## Error Handling

All org workflows return `Result<Attestation, OrgError>`. The `OrgError` enum covers:

| Variant | Meaning |
|---|---|
| `AdminNotFound` | Caller lacks `manage_members` capability |
| `MemberNotFound` | Target member not in org |
| `AlreadyRevoked` | Member already revoked |
| `InvalidCapability` | Capability string parsing failed |
| `Signing` | Cryptographic signing failed |
| `Storage` | Registry read/write failed |
| `Identity` | Identity loading failed |
| `KeyStorage` | Key storage operation failed |

The CLI wraps these with `anyhow::Context` at the presentation boundary.
