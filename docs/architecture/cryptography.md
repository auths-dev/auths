# Cryptography

Ed25519 via ring, the `CryptoProvider` abstraction, key derivation, multicodec encoding, and signature formats.

## Ed25519

Auths uses Ed25519 exclusively for signing and verification. Ed25519 is a deterministic signature scheme based on the Edwards curve Curve25519. It produces 64-byte signatures from 32-byte private keys and 32-byte public keys.

| Property | Value |
|----------|-------|
| Curve | Edwards25519 |
| Private key (seed) | 32 bytes |
| Public key | 32 bytes |
| Signature | 64 bytes |
| Security level | ~128-bit |

## CryptoProvider Abstraction

The `CryptoProvider` trait (`auths-crypto/src/provider.rs`) abstracts all Ed25519 operations behind an async interface. Domain crates (`auths-core`, `auths-sdk`) depend on this trait, never on `ring` directly.

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn verify_ed25519(
        &self, pubkey: &[u8], message: &[u8], signature: &[u8],
    ) -> Result<(), CryptoError>;

    async fn sign_ed25519(
        &self, seed: &SecureSeed, message: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    async fn generate_ed25519_keypair(
    ) -> Result<(SecureSeed, [u8; 32]), CryptoError>;

    async fn ed25519_public_key_from_seed(
        &self, seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError>;
}
```

Two implementations exist:

| Provider | Crate | Target | Backend |
|----------|-------|--------|---------|
| `RingCryptoProvider` | `auths-crypto` (feature: `native`) | Native (macOS, Linux, Windows) | `ring` 0.17 |
| `WebCryptoProvider` | `auths-crypto` (feature: `wasm`) | `wasm32-unknown-unknown` | Web Crypto API |

The `native` feature is the default. The `wasm` feature enables browser-based verification via `auths-verifier`.

### Why an Abstraction

1. **WASM support.** `ring` does not compile to WASM. The Web Crypto API provides Ed25519 in browsers. The trait boundary allows the same verification logic to run on both targets.

2. **No ring leakage.** All method signatures use primitive Rust types or `SecureSeed` -- no ring-specific types cross the trait boundary. Domain crates compile without any ring dependency.

3. **Async by design.** The `RingCryptoProvider` offloads CPU-bound operations to Tokio's blocking pool via `spawn_blocking`, preventing async reactor starvation under load.

## SecureSeed

Private keys cross the `CryptoProvider` boundary as `SecureSeed`, a zeroize-on-drop wrapper for a raw 32-byte Ed25519 seed:

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed([u8; 32]);
```

The seed is the portable key representation. The provider materializes the internal keypair from the seed on each signing call. This trades minor CPU overhead for a pure, ring-free domain layer.

Debug output is redacted: `SecureSeed([REDACTED])`.

## Key Generation

Key generation uses `ring`'s `SystemRandom` CSPRNG:

1. `Ed25519KeyPair::generate_pkcs8(&rng)` produces an 83-byte PKCS#8 v2 DER document
2. The raw 32-byte seed is extracted from bytes `[16..48]` of the PKCS#8 encoding
3. The 32-byte public key is extracted from the `Ed25519KeyPair::public_key()` accessor

The PKCS#8 document is the serialization format for key storage. The raw seed is the runtime format for signing operations.

## Key Material Parsing

The `parse_ed25519_seed` function (`auths-crypto/src/key_material.rs`) handles multiple serialization formats:

| Format | Length | Seed Offset | Public Key |
|--------|--------|-------------|------------|
| PKCS#8 v2 explicit tag | 85 bytes | bytes [16..48] | bytes [53..85] |
| PKCS#8 v2 implicit tag (ring) | 83 bytes | bytes [16..48] | bytes [51..83] |
| PKCS#8 v1 wrapped | 48 bytes | bytes [16..48] | Not included |
| PKCS#8 v1 unwrapped | 46 bytes | bytes [14..46] | Not included |
| Raw seed | 32 bytes | bytes [0..32] | Not included |
| OCTET STRING wrapped | 34 bytes | bytes [2..34] | Not included |

The `build_ed25519_pkcs8_v2` function constructs an 85-byte PKCS#8 v2 DER document from a raw seed and public key, compatible with `ring`'s `Ed25519KeyPair::from_pkcs8`.

## KERI Key Encoding (CESR)

Public keys in KERI events use a simplified CESR (Composable Event Streaming Representation) encoding:

```
"D" + Base64url_no_pad(ed25519_public_key_bytes)
```

The `D` prefix is the KERI derivation code for Ed25519. Parsing (`auths-crypto/src/keri.rs`):

1. Validate the `D` prefix
2. Base64url-decode (no padding) the remaining characters
3. Validate the result is exactly 32 bytes

```rust
pub struct KeriPublicKey([u8; 32]);

impl KeriPublicKey {
    pub fn parse(encoded: &str) -> Result<Self, KeriDecodeError> { ... }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}
```

## DID Key Encoding (Multicodec)

Device identifiers use the `did:key` method with multicodec encoding:

### Encoding

```
[0xED, 0x01] ++ ed25519_public_key_bytes --> Base58btc --> "did:key:z" + encoded
```

- `[0xED, 0x01]` is the varint-encoded Ed25519 multicodec prefix
- Base58btc encoding uses the Bitcoin alphabet
- The `z` prefix in `did:key:z...` indicates Base58btc encoding

### Decoding

```
"did:key:z..." --> strip "did:key:z" --> Base58btc decode --> validate [0xED, 0x01] --> extract 32-byte key
```

The decoded result must be exactly 34 bytes: 2-byte multicodec prefix + 32-byte Ed25519 public key.

### did:keri Encoding

Identity identifiers use a simpler encoding:

```
"did:keri:" + Base58btc(public_key_bytes)
```

No multicodec prefix is used for `did:keri` identifiers.

## SAID Computation (Blake3)

Self-Addressing Identifiers use Blake3-256 hashing:

```
event_json (with d, i, x fields cleared) --> Blake3-256 --> Base64url_no_pad --> "E" + encoded
```

The `E` prefix is the KERI derivation code for Blake3-256. The resulting SAID is 44 characters: 1-byte prefix + 43 characters of Base64url encoding (32-byte hash).

SAIDs are used for:

- **Event identification**: Each KERI event's `d` field
- **Identity prefix**: The inception event's `i` field (identical to `d`)
- **Chain linkage**: Each event's `p` field references the previous event's SAID
- **Next-key commitment**: Blake3 hash of the next public key's raw bytes

## Signature Format

### KERI Event Signatures

KERI events are signed over the canonical event JSON with `d`, `x`, and (for inception) `i` fields cleared. The signature is stored as Base64url (no padding) in the event's `x` field.

```
Event JSON (d="", i="" for icp, x="") --> Ed25519 sign --> Base64url --> x field
```

Inception events are self-signed by the declared key (`k[0]`). Rotation events are signed by the **new** key (the key that satisfied the pre-rotation commitment). Interaction events are signed by the current key.

### Attestation Signatures

Attestation signatures are computed over canonical JSON (produced by `json-canon`) and stored as hex-encoded byte strings:

```
CanonicalAttestationData --> json_canon::to_string --> Ed25519 sign --> hex encode
```

Both `identity_signature` and `device_signature` use the same canonical payload.

## OpenSSH Key Support

The `openssh_pub_to_raw_ed25519` function (`auths-crypto/src/ssh.rs`) parses OpenSSH Ed25519 public key lines:

```
"ssh-ed25519 AAAA... comment" --> 32-byte raw Ed25519 public key
```

This enables importing existing SSH keys for device identification.

## Platform Keychains

Private keys are stored in platform-specific keychains managed by `auths-core`:

| Platform | Backend |
|----------|---------|
| macOS | Security Framework (Keychain) |
| Linux | Secret Service (libsecret) |
| Windows | Windows Credential Manager |
| Fallback | File-based (feature: `keychain-file-fallback`) |

Keys are retrieved by alias at signing time, decrypted in memory, and the `SecureSeed` wrapper ensures they are zeroed on drop.

## Error Types

The `CryptoError` enum covers all cryptographic failure modes:

| Variant | Meaning |
|---------|---------|
| `InvalidSignature` | Signature did not verify |
| `InvalidKeyLength` | Public key is not 32 bytes |
| `InvalidPrivateKey` | Private key material is malformed |
| `OperationFailed` | Backend error (ring/WebCrypto) |
| `UnsupportedTarget` | Operation not available on current compilation target |
