# Key Management Consolidation Notes

## The Problem

After adding P-256 support, key parsing and signing logic is scattered across 4 crates with duplicated "try Ed25519, then P-256" fallback patterns. The same curve-detection logic was independently added to 6 different functions during the P-256 refactor. This is fragile — adding a third curve would require finding and updating all 6 locations.

## Current State: 47 Functions Across 4 Crates

### Where Things Live

```
auths-crypto          (Layer 0)  — raw primitives, no I/O
auths-core/crypto/    (Layer 2)  — SSH wire format, encryption, sync bridges
auths-id/identity/    (Layer 3)  — KERI-specific key operations
auths-sdk/domains/    (Layer 4)  — workflow orchestration
```

### The Duplicates

**Duplicate 1: Seed extraction from PKCS8 bytes**

Three functions do the same thing — parse PKCS8 DER, detect curve, return a `SecureSeed`:

| Function | Location | Handles |
|---|---|---|
| `extract_seed_from_key_bytes()` | `auths-core/src/crypto/signer.rs:64` | Ed25519 → P-256 fallback |
| `extract_seed_from_pkcs8()` | `auths-core/src/crypto/ssh/keys.rs:22` | Ed25519 → P-256 fallback |
| `load_keypair_from_der_or_seed()` | `auths-id/src/identity/helpers.rs:155` | Ed25519 only (broken for P-256) |

All three call `auths_crypto::parse_ed25519_seed()` and then (in the first two) fall back to `p256::ecdsa::SigningKey::from_pkcs8_der()`. The third one doesn't have the P-256 fallback yet — it's a latent bug.

**Duplicate 2: Public key extraction from key bytes**

Two functions extract the public key from stored key material:

| Function | Location | Handles |
|---|---|---|
| `load_seed_and_pubkey()` | `auths-core/src/crypto/signer.rs:88` | Ed25519 → P-256 fallback |
| `extract_pubkey_from_key_bytes()` | `auths-core/src/crypto/ssh/keys.rs:67` | Ed25519 → P-256 fallback |

Both call `parse_ed25519_key_material()` then fall back to `p256::ecdsa::SigningKey::from_pkcs8_der()` → `VerifyingKey::to_encoded_point(true)`. Copy-paste.

**Duplicate 3: SSHSIG creation with implicit curve detection**

`create_sshsig()` at `auths-core/src/crypto/ssh/signatures.rs:26` tries Ed25519 first, then P-256. This is fragile because it can't distinguish a corrupted Ed25519 key from a valid P-256 key — both are 32-byte seeds. If `create_sshsig_ed25519()` silently produces a garbage Ed25519 signature from a P-256 scalar, the P-256 fallback never triggers.

### The Root Cause

`auths-crypto` only has Ed25519-specific parsers (`parse_ed25519_seed`, `parse_ed25519_key_material`). When P-256 was added, each caller independently added its own P-256 fallback instead of adding a curve-agnostic parser to `auths-crypto`.

## Recommendation: Consolidate Into `auths-crypto`

### Step 1: Add curve-agnostic primitives to `auths-crypto`

Create `auths-crypto/src/key_ops.rs`:

```rust
/// Parsed key material with curve identification.
pub struct ParsedKeyMaterial {
    pub curve: CurveType,
    pub seed: SecureSeed,
    pub public_key: Vec<u8>,  // 32 bytes Ed25519, 33 bytes P-256 compressed
}

/// Parse any supported PKCS8 DER to extract seed + public key + curve.
/// Single source of truth for "what curve is this key?"
pub fn parse_key_material(bytes: &[u8]) -> Result<ParsedKeyMaterial, CryptoError> {
    // Try Ed25519 PKCS8 formats (v1, v2, raw 32-byte)
    if let Ok((seed, maybe_pk)) = parse_ed25519_key_material(bytes) {
        let pk = maybe_pk.map(|p| p.to_vec()).unwrap_or_else(|| {
            // derive from seed
        });
        return Ok(ParsedKeyMaterial { curve: CurveType::Ed25519, seed, public_key: pk });
    }
    // Try P-256 PKCS8
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_der(bytes) {
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let compressed = vk.to_encoded_point(true);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sk.to_bytes());
        return Ok(ParsedKeyMaterial {
            curve: CurveType::P256,
            seed: SecureSeed::new(seed),
            public_key: compressed.as_bytes().to_vec(),
        });
    }
    Err(CryptoError::InvalidPrivateKey(...))
}

/// Sign with any supported curve. Single dispatch point.
pub fn sign(curve: CurveType, seed: &SecureSeed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match curve {
        CurveType::Ed25519 => { /* ring Ed25519KeyPair::from_seed_unchecked */ }
        CurveType::P256 => { /* p256::ecdsa::SigningKey::sign */ }
    }
}

/// Derive public key from seed for any supported curve.
pub fn public_key_from_seed(curve: CurveType, seed: &SecureSeed) -> Result<Vec<u8>, CryptoError> {
    match curve {
        CurveType::Ed25519 => { /* 32 bytes */ }
        CurveType::P256 => { /* 33 bytes compressed */ }
    }
}
```

### Step 2: Replace all duplicates with calls to `auths-crypto`

| Current function | Replace with |
|---|---|
| `signer.rs:extract_seed_from_key_bytes()` | `auths_crypto::parse_key_material(bytes)?.seed` |
| `ssh/keys.rs:extract_seed_from_pkcs8()` | `auths_crypto::parse_key_material(bytes)?.seed` |
| `helpers.rs:load_keypair_from_der_or_seed()` | `auths_crypto::parse_key_material(bytes)` + curve-specific keypair construction |
| `signer.rs:load_seed_and_pubkey()` | `let m = auths_crypto::parse_key_material(bytes)?; (m.seed, m.public_key)` |
| `ssh/keys.rs:extract_pubkey_from_key_bytes()` | `auths_crypto::parse_key_material(bytes)?.public_key` |

### Step 3: Make SSHSIG creation explicitly curve-aware

```rust
// Instead of:
pub fn create_sshsig(seed: &SecureSeed, data: &[u8], namespace: &str) -> Result<String, CryptoError>

// Do:
pub fn create_sshsig(curve: CurveType, seed: &SecureSeed, data: &[u8], namespace: &str) -> Result<String, CryptoError>
```

The caller knows the curve from `ParsedKeyMaterial::curve`. No more implicit "try both and hope" detection.

### Step 4: Thread `CurveType` through the signing path

Currently the signing path is:
```
load encrypted key → decrypt → extract_seed (loses curve info) → sign (guesses curve)
```

Should be:
```
load encrypted key → decrypt → parse_key_material (returns curve + seed) → sign(curve, seed)
```

The curve information should flow from key loading to signing in a single `ParsedKeyMaterial` struct, never lost and never re-guessed.

## Complete Function Inventory

### `auths-crypto/src/key_material.rs`
- `parse_ed25519_seed(bytes)` — Ed25519 only, core parser
- `parse_ed25519_key_material(bytes)` — Ed25519 only, returns seed + optional pubkey
- `build_ed25519_pkcs8_v2(seed, pubkey)` — Ed25519 only, PKCS8 builder
- `extract_seed_at(bytes, offset)` — private helper

### `auths-crypto/src/provider.rs`
- `decode_seed_hex(hex_str)` — Ed25519 only, hex decoder

### `auths-crypto/src/ring_provider.rs`
- `p256_generate()` — P-256 keygen
- `p256_sign(seed, message)` — P-256 signing
- `p256_verify(pubkey, message, sig)` — P-256 verification
- `p256_public_key_from_seed(seed)` — P-256 pubkey derivation
- `verify_ed25519(pubkey, message, sig)` — Ed25519 verification (async)
- `sign_ed25519(seed, message)` — Ed25519 signing (async)
- `generate_ed25519_keypair()` — Ed25519 keygen (async)
- `ed25519_public_key_from_seed(seed)` — Ed25519 pubkey derivation (async)

### `auths-crypto/src/did_key.rs`
- `did_key_to_ed25519(did)` — Ed25519 decode
- `ed25519_pubkey_to_did_key(pk)` — Ed25519 encode
- `ed25519_pubkey_to_did_keri(pk)` — Ed25519 KERI encode
- `p256_pubkey_to_did_key(pk)` — P-256 encode
- `did_key_to_p256(did)` — P-256 decode
- `did_key_decode(did)` — auto-detect curve decode

### `auths-core/src/crypto/signer.rs`
- `extract_seed_from_key_bytes(bytes)` — **DUPLICATE** Ed25519 → P-256 fallback
- `load_seed_and_pubkey(bytes)` — **DUPLICATE** Ed25519 → P-256 fallback
- `encrypt_keypair(raw, passphrase)` — encryption wrapper
- `decrypt_keypair(encrypted, passphrase)` — decryption wrapper

### `auths-core/src/crypto/ssh/keys.rs`
- `extract_seed_from_pkcs8(pkcs8)` — **DUPLICATE** Ed25519 → P-256 fallback
- `build_ed25519_pkcs8_v2_from_seed(seed)` — Ed25519 PKCS8 builder wrapper
- `extract_pubkey_from_key_bytes(bytes)` — **DUPLICATE** Ed25519 → P-256 fallback

### `auths-core/src/crypto/ssh/signatures.rs`
- `create_sshsig(seed, data, namespace)` — Ed25519 → P-256 implicit fallback
- `create_sshsig_ed25519(seed, data, namespace)` — Ed25519 SSHSIG
- `create_sshsig_p256(seed, data, namespace)` — P-256 SSHSIG
- `construct_sshsig_signed_data(data, namespace)` — SSHSIG data blob
- `construct_sshsig_pem(pubkey, sig, namespace)` — SSHSIG PEM builder

### `auths-core/src/crypto/provider_bridge.rs`
- `sign_ed25519_sync(seed, message)` — sync wrapper
- `generate_ed25519_keypair_sync()` — sync wrapper
- `ed25519_public_key_from_seed_sync(seed)` — sync wrapper

### `auths-id/src/identity/helpers.rs`
- `extract_seed_bytes(pkcs8)` — Ed25519 only, direct DER parsing
- `encode_seed_as_pkcs8(seed)` — Ed25519 only, direct DER encoding
- `load_keypair_from_der_or_seed(bytes)` — Ed25519 only, **BROKEN for P-256**
- `generate_keypair_with_seed(rng)` — Ed25519 only

### `auths-id/src/keri/inception.rs`
- `sign_with_pkcs8_for_init(curve, pkcs8, message)` — curve-aware signing (correct pattern)
- `generate_keypair_for_init(curve)` — curve-aware keygen (correct pattern)

## What Good Looks Like

After consolidation, the function inventory shrinks from 47 to ~30, with:

1. **One curve-agnostic parser** in `auths-crypto` (`parse_key_material`)
2. **One curve-agnostic signer** in `auths-crypto` (`sign(curve, seed, msg)`)
3. **One curve-agnostic pubkey deriver** in `auths-crypto` (`public_key_from_seed(curve, seed)`)
4. **Zero "try both curves" fallback patterns** — curve is always known
5. **`CurveType` threaded** from key loading to signing — never lost, never guessed
6. **SSHSIG creation** takes explicit `CurveType` parameter

The `auths-core` and `auths-id` crates become thin wrappers that call `auths-crypto` primitives, adding only:
- SSH wire format encoding (auths-core)
- SSHSIG PEM construction (auths-core)
- Keychain encryption/decryption (auths-core)
- KERI event construction (auths-id)

No crypto logic in layers above `auths-crypto` except format wrapping.
