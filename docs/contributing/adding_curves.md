# Adding New Curves

Auths is designed so that adding a new elliptic curve (or a post-quantum algorithm) is a matter of adding enum variants and letting the compiler tell you what's missing. No grep. No guessing. The curve type is carried explicitly through every layer — from key generation to Sigstore submission.

This document explains the current architecture, what's already supported, and the exact steps to add a new curve.

## Currently supported

| Curve | Key size | Signature size | Default | Crate |
|-------|----------|----------------|---------|-------|
| Ed25519 | 32 bytes | 64 bytes | No | `ring` |
| P-256 (secp256r1) | 33 bytes (compressed) | 64 bytes (r‖s) | **Yes** | `p256` |

P-256 is the default for all operations: identity keys, ephemeral CI keys, SSH commit signing, and Sigstore submission. Ed25519 is available for compatibility. We default to P-256 as it is the same default Sigstore uses, so is useful for bootstrapping.

## Architecture: how curves flow through the system

The core design principle: **the curve is an explicit field, never inferred from key length.** This means adding a new curve that shares a byte length with an existing one (e.g., secp256k1 is also 33 bytes compressed, same as P-256) won't break anything.

### Layer 0: `auths-crypto`

This is where a new curve starts. Three types carry the curve:

**`CurveType` enum** (`crates/auths-crypto/src/provider.rs`):
```rust
pub enum CurveType {
    Ed25519,
    #[default]
    P256,
    // Add new variant here → compiler errors everywhere it's not handled
}
```

**`TypedSeed` enum** (`crates/auths-crypto/src/key_ops.rs`):
```rust
pub enum TypedSeed {
    Ed25519([u8; 32]),
    P256([u8; 32]),
    // Add new variant here
}
```

**`DecodedDidKey` enum** (`crates/auths-crypto/src/did_key.rs`):
```rust
pub enum DecodedDidKey {
    Ed25519([u8; 32]),
    P256(Vec<u8>),
    // Add new variant here
}
```

All three are exhaustive `match` targets. Adding a variant to any of them produces compiler errors at every dispatch site that doesn't handle the new curve. This is the core mechanism — the compiler is the migration tool.

### Layer 0.5: `auths-keri`

**`KeriPublicKey` enum** (`crates/auths-keri/src/keys.rs`):
```rust
pub enum KeriPublicKey {
    Ed25519([u8; 32]),
    P256([u8; 33]),
    // Add new variant with CESR derivation code
}
```

Each variant has a CESR derivation code prefix (`D` for Ed25519, `1AAJ` for P-256). The new curve needs a CESR code — either from the CESR spec or a private-use code.

### Layer 1: `auths-verifier`

**`DevicePublicKey`** (`crates/auths-verifier/src/core.rs`):
```rust
pub struct DevicePublicKey {
    curve: CurveType,   // ← carried explicitly
    bytes: Vec<u8>,
}
```

Validation is per-curve in `try_new()`:
```rust
let valid = match curve {
    CurveType::Ed25519 => bytes.len() == 32,
    CurveType::P256 => bytes.len() == 33 || bytes.len() == 65,
    // Add new curve's valid lengths here
};
```

### Layer 2+: SSH, Sigstore, CLI

Each layer dispatches on `CurveType` or `TypedSeed`. The compiler forces you to handle the new variant at every site.

## Steps to add a new curve

This is a concrete checklist. The order matters — each step unblocks the next.

### Step 1: Add the crypto primitives

**File: `crates/auths-crypto/src/provider.rs`**

1. Add a variant to `CurveType`:
   ```rust
   pub enum CurveType {
       Ed25519,
       #[default]
       P256,
       NewCurve,  // e.g., MlDsa44 for post-quantum
   }
   ```
2. Add constants: `NEW_CURVE_PUBLIC_KEY_LEN`, `NEW_CURVE_SIGNATURE_LEN`
3. Update `CurveType::public_key_len()` and `CurveType::signature_len()`
4. Update `Display` impl

**File: `crates/auths-crypto/src/key_ops.rs`**

1. Add a variant to `TypedSeed`:
   ```rust
   pub enum TypedSeed {
       Ed25519([u8; 32]),
       P256([u8; 32]),
       NewCurve([u8; N]),  // whatever the seed size is
   }
   ```
2. Update `TypedSeed::curve()`, `TypedSeed::as_bytes()`
3. Add a parsing branch in `parse_key_material()` — detect the new PKCS8 OID or key format
4. Add signing logic in `sign()` — dispatch to the new crate
5. Add public key derivation in `public_key()`

**File: `crates/auths-crypto/src/ring_provider.rs`** (or a new provider file)

Add standalone `new_curve_sign()`, `new_curve_verify()`, `new_curve_public_key_from_seed()` functions.

### Step 2: Add DID encoding

**File: `crates/auths-crypto/src/did_key.rs`**

1. Define the multicodec prefix bytes for the new curve (from the [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv))
2. Add `new_curve_pubkey_to_did_key()` function
3. Add variant to `DecodedDidKey`
4. Update `did_key_decode()` to handle the new multicodec prefix

### Step 3: Add KERI support

**File: `crates/auths-keri/src/keys.rs`**

1. Add variant to `KeriPublicKey`
2. Assign a CESR derivation code (check the [CESR spec](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html) for registered codes)
3. Update `KeriPublicKey::parse()` to detect the new prefix
4. Update `KeriPublicKey::verify_signature()` to dispatch verification

**File: `crates/auths-keri/src/codec.rs`**

1. Add `KeyType::NewCurve` with the CESR code
2. Add `SigType::NewCurve` if the signature format differs

### Step 4: Add KERI inception support

**File: `crates/auths-id/src/keri/inception.rs`**

1. Update `generate_keypair()` to handle the new `CurveType`
2. Update `sign_with_pkcs8()` to handle the new curve's signing

### Step 5: Update DevicePublicKey validation

**File: `crates/auths-verifier/src/core.rs`**

Update `DevicePublicKey::try_new()` to accept the new curve's key lengths.

### Step 6: Add SSH wire format support

**File: `crates/auths-core/src/crypto/ssh/encoding.rs`**

1. Add encoding branch in `encode_ssh_pubkey()` for the new curve's SSH key type string
2. Add encoding branch in `encode_ssh_signature()` for the new curve's SSH signature format
3. Check if SSH has a registered key type for the new curve — post-quantum algorithms may not have one yet

**File: `crates/auths-verifier/src/ssh_sig.rs`**

1. Add parsing branch in `parse_pubkey_blob()` for the new SSH key type string
2. Add parsing branch in `parse_sig_blob()` for the new signature format

### Step 7: Add Sigstore/Rekor support

**File: `crates/auths-infra-rekor/src/client.rs`**

Update `pubkey_to_pem()` to produce the correct SPKI PEM for the new curve. For post-quantum algorithms, check if Rekor's DSSE entry type accepts the key format.

### Step 8: Update Python/Node bindings

**Files: `packages/auths-python/src/sign.rs`, `packages/auths-node/src/sign.rs`**

Update the `curve` parameter parsing to accept the new curve name.

### Step 9: Compile and follow the errors

```bash
cargo check --workspace 2>&1 | grep "non-exhaustive"
```

Every `match` on `CurveType`, `TypedSeed`, `KeriPublicKey`, or `DecodedDidKey` that doesn't handle the new variant will error. Fix each one. This is the compiler doing the migration for you.

### Step 10: Add tests

Each crate uses `tests/cases/` for integration tests. Add test cases for:
- Key generation round-trip (generate → derive pubkey → verify signature)
- KERI inception with the new curve (key prefix starts with the right CESR code)
- DID encoding/decoding round-trip
- SSH signature creation and parsing
- `DevicePublicKey` construction with valid/invalid lengths

## Post-quantum considerations

Post-quantum algorithms (ML-DSA/Dilithium, ML-KEM/Kyber, SLH-DSA/SPHINCS+) have different characteristics:

| Property | Ed25519/P-256 | ML-DSA-44 (Dilithium2) |
|----------|---------------|----------------------|
| Public key | 32-33 bytes | 1,312 bytes |
| Signature | 64 bytes | 2,420 bytes |
| Seed | 32 bytes | 32 bytes |

**Impact on auths:**

- `DevicePublicKey.bytes` is `Vec<u8>` — handles any size
- `TypedSeed` seed size may differ (add a new fixed-size array or use `Vec<u8>`)
- SSH wire format may not have registered key types — may need a custom namespace
- CESR derivation codes for PQ algorithms are not yet standardized
- Attestation JSON size grows significantly — 2KB signatures instead of 64 bytes
- Rekor DSSE entries grow but should still be accepted (well under the 100KB limit)

The architecture handles this. The main work is in the crypto primitives (Step 1) and the wire format registrations (Steps 3, 6). The type-driven dispatch through `CurveType`/`TypedSeed` is curve-agnostic by design.

## What NOT to do

- **Don't infer curve from key length.** That's brittle and breaks when curves share key length. Use `CurveType` everywhere.
- **Don't add a new signing function per curve.** Use `TypedSeed` and dispatch in `key_ops::sign()`.
- **Don't add curve-specific public key types.** Use `DevicePublicKey` with its `curve` field.
- **Don't hardcode key lengths in validation.** Put them in `CurveType::public_key_len()`.
