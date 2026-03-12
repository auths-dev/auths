# Signing and Verification

## Signing

### SecureSigner Trait

The `SecureSigner` trait (defined in `auths-core`) abstracts key-based signing operations. It handles loading encrypted keys, obtaining passphrases, decrypting, signing, and secure cleanup.

```rust
// auths_core::signing::SecureSigner

pub trait SecureSigner: Send + Sync {
    fn sign_with_alias(
        &self,
        alias: &KeyAlias,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError>;

    fn sign_for_identity(
        &self,
        identity_did: &IdentityDID,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError>;
}
```

**`sign_with_alias`** loads the encrypted key by alias, calls the passphrase provider (up to 3 attempts on incorrect passphrase), decrypts, and signs. Returns raw Ed25519 signature bytes.

**`sign_for_identity`** resolves the identity DID to an alias via `list_aliases_for_identity()`, then delegates to `sign_with_alias`.

### StorageSigner

`StorageSigner<S: KeyStorage>` is the standard concrete implementation that backs `SecureSigner` with any `KeyStorage` backend:

```rust
use auths_core::signing::StorageSigner;

let signer = StorageSigner::new(Arc::clone(&keychain));
let signature = signer.sign_with_alias(&alias, &passphrase_provider, message)?;
```

### PassphraseProvider Variants

| Type | Usage |
|---|---|
| `PrefilledPassphraseProvider` | CI, tests, headless -- returns a fixed passphrase |
| `CallbackPassphraseProvider` | GUI, FFI -- delegates to a callback function |
| `CachedPassphraseProvider` | Agent sessions -- caches with configurable TTL |
| `UnifiedPassphraseProvider` | Multi-key operations -- prompts once for all keys |

```rust
use auths_core::signing::PrefilledPassphraseProvider;

// Headless / CI
let provider = PrefilledPassphraseProvider::new("my-secret");

// Callback-based (GUI/FFI)
use auths_core::signing::CallbackPassphraseProvider;
let provider = CallbackPassphraseProvider::new(|prompt| {
    Ok(zeroize::Zeroizing::new("user-entered-passphrase".to_string()))
});

// Cached with TTL
use auths_core::signing::CachedPassphraseProvider;
let cached = CachedPassphraseProvider::new(
    Arc::new(inner_provider),
    std::time::Duration::from_secs(300),
);

// Unified (prompts once for all keys in a multi-key operation)
use auths_core::signing::UnifiedPassphraseProvider;
let unified = UnifiedPassphraseProvider::new(Arc::new(inner_provider));
```

### SSHSIG Commit Signing Pipeline

The `auths_sdk::signing` module provides the commit signing pipeline:

```rust
use auths_sdk::signing::{validate_freeze_state, construct_signature_payload, sign_with_seed};

// 1. Check that the identity is not frozen
validate_freeze_state(&repo_path, clock.now())?;

// 2. Construct the SSHSIG signed-data payload
let payload = construct_signature_payload(data, "git")?;

// 3. Create a complete SSHSIG PEM signature
let pem = sign_with_seed(&seed, data, "git")?;
```

### SigningError

```rust
pub enum SigningError {
    IdentityFrozen(String),
    KeyResolution(String),
    SigningFailed(String),
    InvalidPassphrase,
    PemEncoding(String),
}
```

### Artifact Attestation Signing

For signing release artifacts with dual-signed attestations:

```rust
use auths_sdk::signing::{
    sign_artifact_attestation, ArtifactSigningParams, SigningKeyMaterial,
};

let params = ArtifactSigningParams {
    artifact: Arc::new(my_artifact_source),
    identity_key: Some(SigningKeyMaterial::Alias(KeyAlias::new("my-key")?)),
    device_key: SigningKeyMaterial::Direct(my_seed),
    expires_in: Some(31_536_000),
    note: Some("v1.0.0 release".into()),
};

let result = sign_artifact_attestation(params, &ctx)?;
println!("Attestation JSON: {}", result.attestation_json);
println!("RID: {}", result.rid);              // e.g. "sha256:abc123..."
println!("Digest: {}", result.digest);        // hex-encoded SHA-256
```

`SigningKeyMaterial` selects how a key is supplied:

| Variant | Behavior |
|---|---|
| `Alias(KeyAlias)` | Resolves the key from the platform keychain at call time |
| `Direct(SecureSeed)` | Injects a raw Ed25519 seed, bypassing the keychain (for headless CI) |

## Verification

### auths-verifier Crate

`auths-verifier` is the standalone verification library with minimal dependencies, designed for embedding in servers, WASM, and C-FFI contexts.

### Free Functions (async, `native` feature)

These are the primary verification entry points, available with the `native` feature flag (enabled by default):

```rust
use auths_verifier::{
    verify_chain, verify_with_keys, verify_with_capability,
    verify_chain_with_capability, verify_at_time,
    verify_chain_with_witnesses, verify_device_authorization,
};
```

#### verify_chain

Verifies an ordered attestation chain starting from a known root public key.

```rust
pub async fn verify_chain(
    attestations: &[Attestation],
    root_pk: &[u8],
) -> Result<VerificationReport, AttestationError>
```

#### verify_with_keys

Verifies a single attestation's signatures against the issuer's public key.

```rust
pub async fn verify_with_keys(
    att: &Attestation,
    issuer_pk_bytes: &[u8],
) -> Result<VerifiedAttestation, AttestationError>
```

#### verify_with_capability

Verifies a single attestation and checks that it grants a required capability.

```rust
pub async fn verify_with_capability(
    att: &Attestation,
    required: &Capability,
    issuer_pk_bytes: &[u8],
) -> Result<VerifiedAttestation, AttestationError>
```

#### verify_chain_with_capability

Verifies an entire chain and asserts that all attestations share a required capability.

```rust
pub async fn verify_chain_with_capability(
    attestations: &[Attestation],
    required: &Capability,
    root_pk: &[u8],
) -> Result<VerificationReport, AttestationError>
```

#### verify_at_time

Verifies a single attestation against a specific point in time (for historical checks).

```rust
pub async fn verify_at_time(
    att: &Attestation,
    issuer_pk_bytes: &[u8],
    at: DateTime<Utc>,
) -> Result<VerifiedAttestation, AttestationError>
```

#### verify_chain_with_witnesses

Verifies a chain and validates witness receipts against a quorum threshold.

```rust
pub async fn verify_chain_with_witnesses(
    attestations: &[Attestation],
    root_pk: &[u8],
    witness_config: &WitnessVerifyConfig<'_>,
) -> Result<VerificationReport, AttestationError>
```

#### verify_device_authorization

Verifies that a specific device is authorized under a given identity.

```rust
pub async fn verify_device_authorization(
    identity_did: &str,
    device_did: &DeviceDID,
    attestations: &[Attestation],
    identity_pk: &[u8],
) -> Result<VerificationReport, AttestationError>
```

### Sync Utility Functions (always available)

These functions are available on all targets including WASM:

#### did_to_ed25519

Resolves a `did:key:z...` DID to raw Ed25519 public key bytes.

```rust
pub fn did_to_ed25519(did: &str) -> Result<Vec<u8>, AttestationError>
```

Note: KERI DIDs (`did:keri:`) contain opaque SAIDs and require external key state resolution.

#### is_device_listed

Checks if a device appears in a list of already-verified attestations.

```rust
pub fn is_device_listed(
    identity_did: &str,
    device_did: &DeviceDID,
    attestations: &[VerifiedAttestation],
    now: DateTime<Utc>,
) -> bool
```

### Verifier Struct

For more control, use `Verifier` directly with a custom `CryptoProvider` and `ClockProvider`:

```rust
use auths_verifier::Verifier;
use auths_crypto::RingCryptoProvider;
use auths_verifier::clock::SystemClock;

let verifier = Verifier::new(
    Arc::new(RingCryptoProvider),
    Arc::new(SystemClock),
);

let report = verifier.verify_chain(&attestations, &root_pk).await?;
```

### VerificationReport

The result of chain verification:

```rust
pub struct VerificationReport {
    pub status: VerificationStatus,
    pub chain: Vec<ChainLink>,
    pub warnings: Vec<String>,
    pub witness_quorum: Option<WitnessQuorum>,
}

impl VerificationReport {
    pub fn is_valid(&self) -> bool { ... }
}
```

### VerificationStatus

```rust
pub enum VerificationStatus {
    Valid,
    Expired { at: DateTime<Utc> },
    Revoked { at: Option<DateTime<Utc>> },
    InvalidSignature { step: usize },
    BrokenChain { missing_link: String },
    InsufficientWitnesses { required: usize, verified: usize },
}
```

### ChainLink

```rust
pub struct ChainLink {
    pub issuer: String,
    pub subject: String,
    pub valid: bool,
    pub error: Option<String>,
}
```

### Verification Checks

Each attestation undergoes these checks in order:

1. **Revocation** -- rejected if `revoked_at <= reference_time`
2. **Expiration** -- rejected if `reference_time > expires_at`
3. **Timestamp skew** -- rejected if `timestamp > reference_time + 5 minutes`
4. **Issuer public key length** -- must be 32 bytes for Ed25519
5. **Issuer signature** -- verified against canonical attestation data
6. **Device signature** -- verified against canonical attestation data

For chain verification, the issuer of each link (after the root) must match the subject of the preceding link. The root attestation is verified against the provided root public key; subsequent links are verified against the device public key from the previous attestation.
