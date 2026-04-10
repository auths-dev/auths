# Curve-Agnostic KERI Architecture

## 0. Why P-256 Is the Default

P-256 is the default curve for all signing operations — identity keys, ephemeral CI keys, and any future signing path. This is not because of the Secure Enclave (which is deferred). It is because P-256 is the curve the broader signing ecosystem has converged on.

**Ecosystem alignment:** Rekor (Sigstore's transparency log) uses ECDSA P-256 for checkpoint signatures. Sigstore's Fulcio CA issues P-256 certificates. The OIDC ecosystem, X.509 certificates, and the Web PKI default to P-256. By choosing P-256 as the default, auths shares cryptographic primitives with the infrastructure it depends on. One curve for identity keys, ephemeral keys, and transparency log verification — no mixed-curve complexity.

**Simplicity:** A single default curve means one key format, one signature format, one set of CESR codes, one verification path in the common case. Ed25519 remains available for users who need it, but the default path is P-256 everywhere. This reduces the testing surface, the documentation surface, and the cognitive load for new contributors.

**Secure Enclave is an additional benefit, not the driver.** When Secure Enclave support ships (deferred to a future epic due to entitlement requirements), P-256 identities will be promotable to hardware-backed storage without changing the identity or the KEL. If Ed25519 were the default, Secure Enclave users would need to create new identities. But this is a bonus — the primary rationale is ecosystem alignment.

**Ephemeral CI signing uses P-256 too.** The `sign_artifact_ephemeral()` path currently generates throwaway Ed25519 keys. After this epic, it generates P-256 keys. The ephemeral key is disposable, so the performance difference is irrelevant (P-256 signing is ~2ms vs Ed25519's ~0.1ms — both negligible for a CI signing operation). Using the same curve everywhere means the verifier has one fast path, not two.

## 1. Blast Radius

Every file, function, and type that assumes Ed25519 — the complete list of what must change.

### CRITICAL (must change for P-256 to work)

| File | What | Why |
|------|------|-----|
| `auths-crypto/src/provider.rs` | `CryptoProvider` trait: all 4 methods have `ed25519` in name | Trait is the crypto abstraction |
| `auths-crypto/src/ring_provider.rs` | `RingCryptoProvider`: hardcoded `ring::Ed25519KeyPair` | Implementation of trait |
| `auths-crypto/src/key_material.rs` | `parse_ed25519_seed()`, `build_ed25519_pkcs8_v2()`, Ed25519 OID `1.3.101.112` | Key parsing |
| `auths-crypto/src/did_key.rs` | `ED25519_MULTICODEC [0xED, 0x01]`, `did_key_to_ed25519()` | DID encoding |
| `auths-keri/src/keys.rs:59` | `KeriPublicKey([u8; 32])` — 32 bytes, Ed25519 only | P-256 is 33 bytes |
| `auths-keri/src/types.rs:530` | `CesrKey::parse_ed25519()` — only parse path | No P-256 parse |
| `auths-keri/src/validate.rs:596-613` | `verify_signature_bytes()`: hardcoded `ring::signature::ED25519` | Core verification |
| `auths-keri/src/validate.rs:677-683` | `validate_signed_event()`: calls `key.parse_ed25519()` | Event validation |
| `auths-keri/src/codec.rs:6-18` | `KeyType`, `SigType` enums: only Ed25519 | CESR encoding |

### HIGH (identity lifecycle)

| File | What |
|------|------|
| `auths-id/src/keri/inception.rs:127-143` | `ring::Ed25519KeyPair`, `D` prefix hardcoded |
| `auths-id/src/keri/rotation.rs:154-176` | Same pattern |
| `auths-id/src/identity/helpers.rs:155` | `load_keypair_from_der_or_seed()` returns `Ed25519KeyPair` |
| `auths-id/src/keri/anchor.rs:95` | `&Ed25519KeyPair` parameter |
| `auths-id/src/attestation/verify.rs:89,99` | `ring::signature::ED25519` |
| `auths-id/src/attestation/create.rs:77` | `ED25519_PUBLIC_KEY_LEN` check |

### MEDIUM (signing/resolution)

| File | What |
|------|------|
| `auths-core/src/crypto/provider_bridge.rs` | All 4 sync wrappers are `_ed25519_` |
| `auths-core/src/crypto/signer.rs:24-58` | `SeedSignerKey`: 32-byte pubkey, `SshAlgorithm::Ed25519` |
| `auths-core/src/signing.rs:78-98` | `ResolvedDid` stores `Ed25519PublicKey` |
| `auths-crypto/src/ssh.rs:42` | `openssh_pub_to_raw_ed25519()` |
| `auths-crypto/src/testing.rs` | All test helpers use `ring::Ed25519KeyPair` |
| `auths-sdk/src/domains/signing/service.rs:591-598` | `sign_artifact_ephemeral()`: Ed25519 seed via `ring::rand` — migrate to P-256 |

### ALREADY CURVE-AGNOSTIC (minimal changes)

| File | Status |
|------|--------|
| `auths-keri/src/crypto.rs` | `compute_next_commitment` / `verify_commitment` hash arbitrary bytes |
| `auths-core/src/storage/keychain.rs` | `KeyStorage` trait stores opaque bytes |
| `auths-crypto/src/pkcs8.rs` | `Pkcs8Der` wraps `Vec<u8>` (any curve) |
| `auths-keri/src/types.rs:25-43` | `validate_prefix_derivation_code` accepts multi-curve prefixes |

## 2. CryptoProvider Trait Redesign

**Decision: Enum dispatch.** Methods take a `CurveType` parameter. Internal match dispatches to curve-specific code.

**Rationale:**
- Parallel methods (`ed25519_sign`, `p256_sign`) doubles the API surface and forces callers to match on curve before calling.
- Trait objects (`Box<dyn SigningKey>`) add heap allocation and dynamic dispatch overhead for hot-path operations.
- Enum dispatch is a single set of methods with internal branching — callers don't need to know the curve, the method does.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    Ed25519,
    P256,
}

pub trait CryptoProvider: Send + Sync {
    fn generate_keypair(&self, curve: CurveType) -> Result<(Pkcs8Der, Vec<u8>), CryptoError>;
    fn sign(&self, curve: CurveType, seed: &SecureSeed, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(&self, curve: CurveType, pubkey: &[u8], message: &[u8], sig: &[u8]) -> Result<(), CryptoError>;
    fn public_key_from_seed(&self, curve: CurveType, seed: &SecureSeed) -> Result<Vec<u8>, CryptoError>;
}
```

Old Ed25519-specific methods marked `#[deprecated]` and migrated internally.

## 3. ring vs p256 Dependency

**Decision: Use `p256 = "0.13"` for P-256 keygen + signing. Keep `ring` for Ed25519 and P-256 verification where already used.**

**Rationale:**
- CESR needs SEC1 compressed public keys (33 bytes). `p256` gives `to_encoded_point(true)` directly. `ring` only exports uncompressed (65 bytes).
- KERI needs raw r||s signatures (64 bytes). `p256`'s `Signature` type is already this format. `ring` has `ECDSA_P256_SHA256_FIXED_SIGNING` but the `p256` API is more ergonomic.
- `cesride` (the Rust CESR reference) uses `p256`. keripy uses Python's `cryptography` with equivalent P-256 ops.
- `ring` stays for Ed25519 (already battle-tested in the codebase) and for checkpoint verification (fn-111).

**Version pin:** `p256 = "0.13"` (latest stable, matches cesride). Rationale: RustCrypto ecosystem, audited, pure Rust (WASM-safe).

## 4. KeriPublicKey Enum

```rust
pub enum KeriPublicKey {
    Ed25519([u8; 32]),
    P256([u8; 33]),  // SEC1 compressed: 0x02/0x03 + 32-byte x-coordinate
}
```

**Serde:** The wire format uses the CESR derivation code prefix as the discriminator. Serialized as the qualified CESR string (e.g., `"Dxy2s..."` for Ed25519, `"1AAJAg..."` for P-256). The derivation code IS the curve indicator — no additional tag.

**Methods:**
- `curve() -> CurveType`
- `as_bytes() -> &[u8]` (raw bytes, 32 or 33)
- `verify_signature(&self, message: &[u8], sig: &[u8]) -> Result<(), ValidationError>` — dispatches Ed25519 → ring, P256 → ring or p256
- `to_cesr(&self) -> String` — CESR qualified string
- `from_cesr(s: &str) -> Result<Self, KeriDecodeError>` — parses prefix to dispatch

## 5. CESR Derivation Codes

Source: cesride `matter/tables.rs`, verified against keripy `coring.py`.

### P-256 (secp256r1)

| Purpose | Code | Raw bytes | Total chars |
|---------|------|-----------|-------------|
| Transferable public key | `1AAJ` | 33 (compressed SEC1) | 48 |
| Non-transferable public key | `1AAI` | 33 (compressed SEC1) | 48 |
| Signature | `0I` | 64 (raw r\|\|s) | 88 |
| Seed | `Q` | 32 | 44 |
| Indexed sig (both lists) | `E` | 64 | 88 |
| Indexed sig (current only) | `F` | 64 | 88 |

### Ed25519 (existing, unchanged)

| Purpose | Code | Raw bytes | Total chars |
|---------|------|-----------|-------------|
| Transferable public key | `D` | 32 | 44 |
| Non-transferable public key | `B` | 32 | 44 |
| Signature | `0B` | 64 | 88 |
| Seed | `A` | 32 | 44 |
| Indexed sig (both lists) | `A` | 64 | 88 |
| Indexed sig (current only) | `B` | 64 | 88 |

### Encoding example: P-256 public key

```
Raw: 33 bytes (0x02 + 32-byte x-coordinate)
Pad size: ps = (3 - 33 % 3) % 3 = 0  -- no padding needed
Code: "1AAJ" (4 chars, occupies 3 bytes in base64url space)
Encoding: "1AAJ" + base64url(33 bytes) = "1AAJ" + 44 chars = 48 chars
```

### Encoding example: P-256 signature

```
Raw: 64 bytes (r || s, each 32 bytes big-endian)
Pad size: ps = (3 - 64 % 3) % 3 = 2  -- prepend 2 zero bytes
Code: "0I" (2 chars, replaces first 2 base64url chars)
Encoding: base64url(0x00 0x00 + 64 bytes) = 88 chars, first 2 replaced with "0I"
```

## 6. Inception Event Format (Side by Side)

### Ed25519 inception

```json
{
  "v": "KERI10JSON000000_",
  "t": "icp",
  "d": "EBfxc4R...",
  "i": "DBfxc4R...",
  "s": "0",
  "kt": "1",
  "k": ["Dxy2sgz..."],
  "nt": "1",
  "n": ["EBfxc4R..."],
  "bt": "0",
  "b": [],
  "c": [],
  "a": []
}
```

The `i` field starts with `D` (Ed25519 transferable). The `k` list contains `D`-prefixed keys. The `n` list contains `E`-prefixed Blake3 digests of the next key's qualified form.

### P-256 inception

```json
{
  "v": "KERI10JSON000000_",
  "t": "icp",
  "d": "EBfxc4R...",
  "i": "1AAJAg...",
  "s": "0",
  "kt": "1",
  "k": ["1AAJAg..."],
  "nt": "1",
  "n": ["EBfxc4R..."],
  "bt": "0",
  "b": [],
  "c": [],
  "a": []
}
```

The `i` field starts with `1AAJ` (P-256 transferable). The `k` list contains `1AAJ`-prefixed keys. The `n` list still uses `E`-prefixed Blake3 digests (digest algorithm is independent of key algorithm).

## 7. Signature Format

**Raw r||s (64 bytes).** This matches keripy exactly.

keripy flow:
```python
der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
(r, s) = utils.decode_dss_signature(der)
sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
```

Rust flow (p256 crate):
```rust
let sig: p256::ecdsa::Signature = signing_key.sign(message);
let raw: [u8; 64] = sig.to_bytes().into();  // already r||s
```

Note: ECDSA P-256 uses SHA-256 internally to hash the message before signing. The `p256` crate handles this transparently — `sign(message)` hashes internally.

## 8. Ed25519 Behavior Preservation

**Before the refactor begins:** Generate a reference Ed25519 identity with a fixed seed (all-zeros or all-ones). Save the complete output to `crates/auths-keri/tests/fixtures/pre_refactor_ed25519.json`:
- Identifier string
- Full inception event JSON
- All key CESR strings
- All signature CESR strings
- Full rotation event JSON (after one rotation)

**After each commit of the refactor:** Re-generate with the same seed through the new code path. Assert byte equality against the fixture. If any byte differs, something broke.

## 9. Cross-Curve Rotation Rejection

**Enforced in `validate_rotation()` in `auths-keri/src/validate.rs`.**

When validating a rotation event:
1. Extract the derivation code prefix from the inception event's `k[0]` (e.g., `D` or `1AAJ`)
2. Extract the derivation code prefix from the rotation event's `k[0]`
3. If they differ → `ValidationError::CurveMismatch { expected: "D", found: "1AAJ" }`

This is a project policy (the KERI spec actually allows cross-curve rotation via digest commitments). We reject it to keep the security model simple: one identity = one curve.

## 10. Secure Enclave (DEFERRED)

**Probe result:** Error -34018 (errSecMissingEntitlement) on Apple M1 Max.
- Unsigned binary: FAILS
- Ad-hoc signed (`codesign -s -`): FAILS
- Apple Development identity signed: FAILS

**Root cause:** Secure Enclave requires a provisioning profile with `com.apple.application-identifier` entitlement. Bare CLI binaries cannot carry provisioning profiles — they need to be embedded in an app-like bundle structure.

**Decision:** Deferred to a future epic. This epic ships software-only P-256 on all platforms.

**Future path:** Embed auths CLI in a `.app` bundle, or use an XPC helper daemon that has the required entitlements.

## 11. keripy Test Vector Schema

Fixtures stored at `crates/auths-keri/tests/fixtures/keripy_vectors.json`:

```json
{
  "version": 1,
  "generated_by": "keripy <version>",
  "curves": {
    "ed25519": {
      "seed_hex": "0000...0000",
      "public_key_cesr": "Dxy2sgz...",
      "inception_event_json": "...",
      "inception_identifier": "DBfxc4R...",
      "rotation_event_json": "...",
      "signature_cesr": "0BAA...",
      "signed_message_hex": "..."
    },
    "p256": {
      "seed_hex": "0000...0000",
      "public_key_cesr": "1AAJAg...",
      "inception_event_json": "...",
      "inception_identifier": "1AAJAg...",
      "rotation_event_json": "...",
      "signature_cesr": "0IAA...",
      "signed_message_hex": "..."
    }
  }
}
```

Generated by `scripts/keripy_test_vectors.py` with a pinned keripy version.

## 12. Default Curve Selection

**P-256 is the default everywhere.** Identity keys, ephemeral CI keys, and any future signing path.

When `auths init` (or `auths id init`) is run:
- No `--curve` flag → `CurveType::P256` (default)
- `--curve p256` → `CurveType::P256`
- `--curve ed25519` → `CurveType::Ed25519`
- `--curve anything-else` → error: "Unknown curve 'anything-else'. Available: p256, ed25519"

The default is applied in the CLI command handler. The SDK `create_identity()` takes `curve: CurveType` as a required parameter — no default in the SDK layer. The CLI is the composition root that applies the default.

**Ephemeral CI signing (`sign_artifact_ephemeral`):** Currently generates Ed25519 throwaway keys. After this epic, generates P-256 throwaway keys. The change is in `auths-sdk/src/domains/signing/service.rs:591-598` — replace `ring::rand` + `SecureSeed` with `p256::ecdsa::SigningKey::random()`. The `did:key:z...` issuer DID uses the P-256 multicodec. The attestation signature uses P-256 raw r||s (64 bytes). This is part of fn-112.3 (auths-crypto P-256 support) to keep the refactor internally consistent.
