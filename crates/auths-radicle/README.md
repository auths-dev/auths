# auths-radicle

Radicle protocol integration for Auths.

This crate provides the adapter layer between [Radicle](https://radicle.xyz) and Auths,
enabling policy-based authorization for Radicle commits without introducing new cryptography.

## Zero New Crypto

**This is a fundamental design constraint.**

Auths-radicle does NOT:
- Replace Radicle's signature verification
- Invent new signature formats
- Sign commits on behalf of Auths
- Introduce new cryptographic primitives

Auths **authorizes**, never signs. Radicle handles all cryptography.

### Why?

Radicle already has:
- Ed25519 signatures (via `radicle-crypto`)
- Key management
- Threshold signatures (M-of-N delegates)

Adding Auths-specific crypto would:
- **Duplicate functionality** - Radicle's crypto is battle-tested
- **Create confusion** - Which signature matters?
- **Increase attack surface** - More code = more bugs

### What Auths-radicle Does

1. **Policy evaluation** - Is this key authorized to sign for this identity?
2. **Attestation verification** - Is the device attestation valid and unexpired?
3. **Threshold checking** - Do enough signers meet the policy?

### Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Radicle verifies Ed25519 signature (their code)            │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  Auths-radicle loads identity + attestation                 │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  Auths policy engine evaluates authorization                │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  VerifyResult: Verified / Rejected / Warn                   │
└─────────────────────────────────────────────────────────────┘
```

## Architecture

All Radicle-specific logic is consolidated in this crate:

| Crate | Radicle Dependencies |
|-------|---------------------|
| `auths-core` | None |
| `auths-id` | None |
| `auths-policy` | None |
| `auths-radicle` | All Radicle integration here |

This mirrors how:
- Sigstore started as external adapters
- OpenTelemetry exporters evolved
- OAuth provider SDKs matured

## Usage

```rust
use auths_radicle::{DefaultBridge, RadicleAuthsBridge, VerifyResult};
use auths_radicle::verify::AuthsStorage;

// Implement storage backend
struct MyStorage { /* ... */ }
impl AuthsStorage for MyStorage { /* ... */ }

// Create bridge
let bridge = DefaultBridge::with_storage(my_storage);

// Verify a signer (key bytes from Radicle)
let signer_key: [u8; 32] = /* from Radicle commit */;
let result = bridge.verify_signer(&signer_key, "repo-id", now)?;

match result {
    VerifyResult::Verified { reason } => println!("Allowed: {}", reason),
    VerifyResult::Rejected { reason } => println!("Blocked: {}", reason),
    VerifyResult::Warn { reason } => println!("Warning: {}", reason),
}
```

### Threshold Identities

Radicle supports M-of-N threshold identities. Use `verify_multiple_signers`:

```rust
use auths_radicle::verify::{verify_multiple_signers, meets_threshold};

let signer_keys: Vec<[u8; 32]> = /* all signers from commit */;
let results = verify_multiple_signers(&bridge, &signer_keys, "repo-id", now);

// Check if 2-of-3 threshold is met
if meets_threshold(&results, 2) {
    println!("Threshold met!");
}
```

## Heartwood Integration

Due to SQLite library conflicts between Radicle's `sqlite` crate and Auths'
`rusqlite`, the Heartwood dependencies are not included directly.

To integrate with Radicle's native types:

1. Add `radicle` and `radicle-crypto` as path dependencies in your project
2. Convert Radicle types to bytes before calling the bridge:
   ```rust
   let key_bytes: [u8; 32] = radicle_public_key.as_ref().try_into()?;
   let result = bridge.verify_signer(&key_bytes, &repo_id.to_string(), now)?;
   ```

## Feature Flags

None currently. The crate uses generic byte-based APIs.

## License

MIT OR Apache-2.0
