# Cryptography

Curve-agnostic signing and verification, the `CryptoProvider` abstraction, key derivation, wire-format curve tagging, and signature formats.

## Curve Support

Auths is curve-agnostic. **P-256 is the default** for new identities and signing operations; Ed25519 is supported for compatibility with existing KERI deployments, SSH tooling, and Radicle.

| Curve | Role | Private seed | Public key | Signature |
|-------|------|--------------|------------|-----------|
| **P-256** (secp256r1, ECDSA) | Default — CI, mobile, Secure Enclave | 32 bytes | 33 bytes (compressed SEC1) or 65 bytes (uncompressed) | 64 bytes (r‖s) |
| **Ed25519** (RFC 8032, EdDSA) | Compat — SSH, Radicle, legacy KERI | 32 bytes | 32 bytes | 64 bytes |

Every curve-touching type in the workspace uses the `CurveType` enum (`auths-crypto/src/provider.rs`):

```rust
pub enum CurveType {
    Ed25519,
    #[default]
    P256,
}
```

Constants exported for curve dimensions: `ED25519_PUBLIC_KEY_LEN`, `ED25519_SIGNATURE_LEN`, `P256_PUBLIC_KEY_LEN`, `P256_SIGNATURE_LEN`.

## Wire-format Curve Tagging (load-bearing rule)

**Every byte string that represents a public key, signing seed, or signature on a wire or on disk MUST carry its curve tag in-band.** Never dispatch on byte length as a curve tag.

### Why

- 32 bytes is ambiguous between **Ed25519** verkeys and **X25519** ECDH pubkeys.
- 33 bytes is ambiguous between **P-256** compressed verkeys and **secp256k1** compressed verkeys (Bitcoin/Ethereum). If secp256k1 is ever added, length dispatch silently misroutes those bytes to the P-256 verifier; failure surfaces as `InvalidSignature` rather than a routing error, masking the real bug.

### Approved tagging schemes

| Scheme | Shape | Parser | Preferred for |
|--------|-------|--------|---------------|
| **CESR prefix** | `D{base64}` (Ed25519 verkey) · `1AAI{base64}` (P-256 compressed verkey) | `KeriPublicKey::parse` in `auths-keri/src/keys.rs` | KEL / event payloads |
| **Multicodec varint (`did:key:`)** | `z6Mk…` (Ed25519) · `zDna…` (P-256) | `DecodedDidKey::decode` in `auths-crypto/src/did_key.rs` | Identity DIDs |
| **Explicit `curve` field** | Sibling field naming the curve (`"ed25519"` / `"p256"`) | Caller-owned match | FFI / JSON wire formats where CESR or multibase is awkward |

Default when a `curve` field is absent or unrecognized: **`P256`**.

### Compliance checklist for wire-format designers

When adding any new wire format or on-disk representation that carries keys, seeds, or signatures:

- [ ] Each such byte string is accompanied by one of the approved tagging schemes.
- [ ] The parse path returns a curve-aware typed value (`KeriPublicKey`, `DecodedDidKey`, `TypedSeed`), not a raw `Vec<u8>`.
- [ ] The emit path produces a CESR/multicodec/field-tagged shape, not a raw base64url dump.
- [ ] The wire format is documented in this file's "Curve Tagging Inventory" section below.

## Length Dispatch: sanctioned uses

`CurveType::from_public_key_len_fallback` (renamed from `from_public_key_len` in fn-122) exists for one reason: **true external-ingestion boundaries where the tag was already lost upstream**. Examples:

- A WASM consumer hands the verifier raw pubkey bytes from an opaque source.
- A CLI flag accepts a hex-encoded pubkey with no curve hint and no containing envelope.
- Legacy on-disk data generated before the tag was mandated.

Obligations for any call site that uses the `_fallback` helper:

1. A comment at the call site naming why no in-band tag is available.
2. A preference for **failing** over guessing when the length is unknown.
3. A migration note if the boundary can be widened to carry a tag.

**Never** introduce length dispatch at an internal boundary or in new wire formats.

## `CryptoProvider` abstraction

`CryptoProvider` (`auths-crypto/src/provider.rs`) is the async trait that abstracts signing/verification behind a target-agnostic interface. Domain crates (`auths-core`, `auths-sdk`) depend on this trait, never on `ring` or `p256` directly.

```rust
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CryptoProvider: Send + Sync {
    async fn verify_ed25519(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
    async fn verify_p256(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
    async fn sign_ed25519(&self, seed: &SecureSeed, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError>;
    async fn ed25519_public_key_from_seed(&self, seed: &SecureSeed) -> Result<[u8; 32], CryptoError>;
}
```

Providers:

| Provider | Crate | Target | Backend |
|----------|-------|--------|---------|
| `RingCryptoProvider` | `auths-crypto` (feature: `native`) | Native (macOS, Linux, Windows) | `ring` 0.17 + `p256` 0.13 |
| `WebCryptoProvider` | `auths-crypto` (feature: `wasm`) | `wasm32-unknown-unknown` | Web Crypto API |

### Sync helpers

Where async is unavailable (FFI boundaries, embedded signers), the workspace exposes sync helpers on `RingCryptoProvider`:

- `RingCryptoProvider::ed25519_verify(pubkey, message, signature)` — sync `ring::signature::UnparsedPublicKey` wrapper.
- `RingCryptoProvider::p256_verify(pubkey, message, signature)` — sync `p256::ecdsa::VerifyingKey::verify` wrapper.

### Why an abstraction

1. **WASM support.** `ring` does not compile to WASM. The Web Crypto API covers both curves in browsers.
2. **No ring leakage.** Method signatures use primitive Rust types or `SecureSeed` / `TypedSeed` — no ring-specific types cross the trait boundary.
3. **Async by default.** The native provider offloads CPU-bound operations to Tokio's blocking pool via `spawn_blocking`, preventing async reactor starvation under load.

## Typed key material

### `TypedSeed`

`TypedSeed` (`auths-crypto/src/key_ops.rs`) pairs a 32-byte seed with its curve tag. It replaces every `(SecureSeed, CurveType)` pair in the domain layer — the curve travels with the seed, not alongside it.

```rust
pub enum TypedSeed {
    Ed25519([u8; 32]),
    P256([u8; 32]),
}
```

### `TypedSignerKey`

`TypedSignerKey::from_pkcs8(pkcs8_bytes)` parses a PKCS#8 DER key for either curve and returns a typed signer. Key methods:

- `typed.curve() -> CurveType`
- `typed.public_key() -> &[u8]` — raw bytes (32 for Ed25519, 33 for P-256 compressed)
- `typed.cesr_encoded_pubkey() -> String` — CESR-tagged string (`D…` or `1AAI…`), suitable for direct wire emission

Prefer `cesr_encoded_pubkey()` at any FFI or on-disk boundary that emits a pubkey.

### `parse_key_material`

`parse_key_material(bytes: &[u8]) -> Result<ParsedKey, CryptoError>` detects the curve from the PKCS#8 OID and returns `ParsedKey { seed: SecureSeed, public_key: Vec<u8>, curve: CurveType }`. Use this wherever the inbound bytes are opaque PKCS#8 — the curve flows through without ever touching a raw byte length.

### `typed_sign`

`typed_sign(&TypedSeed, message)` dispatches to the correct signer based on the seed's variant. Replaces any call site that used to take `SecureSeed + CurveType`.

## SecureSeed

Private keys cross the `CryptoProvider` boundary as `SecureSeed`, a zeroize-on-drop wrapper for a raw 32-byte seed:

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed([u8; 32]);
```

The seed is the portable key representation. The provider materializes the internal keypair from the seed on each signing call. Debug output is redacted: `SecureSeed([REDACTED])`.

Note: `SecureSeed` is curve-untyped. Prefer `TypedSeed` for any value that will be used with `typed_sign`. `SecureSeed` remains for the curve-agnostic trait surface on `CryptoProvider`.

## Key Generation

Key generation uses `ring`'s `SystemRandom` CSPRNG for both curves:

- **Ed25519**: `Ed25519KeyPair::generate_pkcs8(&rng)` produces an 83-byte PKCS#8 v2 DER document. Raw seed at bytes `[16..48]`, pubkey accessor on the keypair.
- **P-256**: `EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)` produces a PKCS#8 v2 DER document. The curve OID identifies the curve unambiguously.

Both shapes round-trip through `TypedSignerKey::from_pkcs8` → raw seed → re-encoded PKCS#8.

## KERI CESR Encoding

KERI public keys on the wire use CESR (Composable Event Streaming Representation) qualification codes:

| Key type | Prefix | Total length | Decoded bytes |
|----------|--------|--------------|---------------|
| Ed25519 verkey | `D` | 44 chars | 32 bytes |
| P-256 verkey (compressed SEC1) | `1AAI` | 48 chars | 33 bytes |

Parsing via `KeriPublicKey::parse(encoded)` returns a typed `KeriPublicKey::{Ed25519([u8; 32]), P256([u8; 33])}` enum. Signature verification via `key.verify_signature(message, sig)` dispatches on the variant.

**Spec compliance:** `1AAJ` is the CESR spec's P-256 *signature* code, **not** a verkey code. The parser rejects `1AAJ` as a verkey with `UnsupportedKeyType`. Any legacy data emitting `1AAJ` for verkeys must be regenerated.

## did:key Multicodec Encoding

Device identifiers use the `did:key` method. The multibase `z` prefix means Base58btc:

| Curve | Multicodec varint | did:key shape |
|-------|-------------------|---------------|
| Ed25519 | `[0xED, 0x01]` | `did:key:z6Mk…` |
| P-256 | `[0x80, 0x24]` | `did:key:zDna…` |

Encoding:

```
did:key:z + Base58btc([multicodec_prefix] ++ public_key_bytes)
```

Decoding via `DecodedDidKey::decode(did)` returns `{ bytes: Vec<u8>, curve: CurveType }`. The multicodec varint is validated before the key bytes are returned.

### did:keri Encoding

Identity identifiers (`did:keri:…`) are derived from the KERI identity prefix (AID / SAID) rather than wrapping a raw public key. No multicodec prefix; the SAID itself carries the curve indirectly via the inception event's declared keys.

## SAID Computation (Blake3)

Self-Addressing Identifiers use Blake3-256 hashing:

```
event_json (with d, i fields cleared) --> Blake3-256 --> Base64url_no_pad --> "E" + encoded
```

The `E` prefix is the KERI derivation code for Blake3-256. The resulting SAID is 44 characters: 1-byte prefix + 43 characters of Base64url encoding (32-byte hash).

SAIDs are used for:

- **Event identification**: Each KERI event's `d` field
- **Identity prefix**: The inception event's `i` field (identical to `d`)
- **Chain linkage**: Each event's `p` field references the previous event's SAID
- **Next-key commitment**: Blake3 hash of the next public key's raw bytes

## Signature Format

### KERI event signatures (attachments)

KERI events are serialised as canonical JSON **without** any signature field. Signatures attach out-of-band as CESR indexed-signature groups:

```
-A##<indexed siger>…
```

where `##` is the count-of-sigs code and each `<siger>` is a CESR-qualified signature prefix (`0B…` for Ed25519 sigs, `0C…` for P-256 sigs per CESR spec, followed by base64url of the signature bytes). Encoded via `cesride::Siger`.

Inception events are self-signed by the declared key (`k[0]`). Rotation events are signed by the **new** key (the key that satisfied the pre-rotation commitment). Interaction events are signed by the current key.

### Attestation signatures

Attestation and action-envelope signatures are computed over canonical JSON (produced by `json-canon`) and stored as hex-encoded byte strings in a sibling `signature` field of the envelope. The signing curve is conveyed by the signer's typed key; verifiers **must** look up the curve via the signer's DID or an explicit `curve` field — never infer from signature length.

## Platform keychains

Private keys (both curves) are stored in platform-specific keychains managed by `auths-core`:

| Platform | Backend |
|----------|---------|
| macOS | Security Framework (Keychain) |
| Linux | Secret Service (libsecret) |
| Windows | Windows Credential Manager |
| Fallback | File-based (feature: `keychain-file-fallback`) |

Keys are retrieved by alias at signing time, decrypted in memory, and the `SecureSeed` wrapper ensures they are zeroed on drop.

## OpenSSH key support

The `openssh_pub_to_raw_ed25519` function (`auths-crypto/src/ssh.rs`) parses OpenSSH Ed25519 public key lines:

```
"ssh-ed25519 AAAA… comment" --> 32-byte raw Ed25519 public key
```

This enables importing existing SSH keys for device identification. Ed25519-only for now — OpenSSH P-256 (`ecdsa-sha2-nistp256`) support can be added when needed.

## Error types

The `CryptoError` enum covers cryptographic failure modes:

| Variant | Meaning |
|---------|---------|
| `InvalidSignature` | Signature did not verify |
| `InvalidKeyLength` | Public key length did not match the declared curve |
| `InvalidPrivateKey` | Private key material is malformed |
| `UnsupportedCurve` | Curve tag present but not supported by this provider |
| `OperationFailed` | Backend error (ring / p256 / WebCrypto) |
| `UnsupportedTarget` | Operation not available on current compilation target |

## Future curves

The curve-tagging rule is forward-looking. Likely next entries:

- **secp256k1** — Bitcoin / Ethereum identity. Compressed verkeys are 33 bytes (colliding with P-256). Length dispatch would silently misroute these to the P-256 verifier; wire-format curve tagging prevents the misroute.
- **Ed448** — Higher-security EdDSA variant. 57-byte verkeys and 114-byte signatures; no length collisions with current curves, but the rule still applies.
- **BLS12-381** — Aggregatable signatures for multi-device quorums. 48-byte G1 pubkeys; distinct lengths but aggregation semantics require first-class curve tagging.

When any of these land:

1. Add a new `CurveType` variant.
2. Assign it a CESR prefix (check the CESR spec for the canonical code), a multicodec varint (check the multicodec table), and a sibling-field string.
3. Extend `KeriPublicKey::parse`, `DecodedDidKey::decode`, and the FFI `curve` enum.
4. **Do not** add a new arm to `CurveType::from_public_key_len_fallback` unless the new curve's byte width is genuinely unique; prefer leaving length dispatch behind forever.

## Curve Tagging Inventory

This table is the source of truth for which wire boundaries carry a curve tag and how. If you add a new wire format, add a row.

| Wire boundary | Tagging scheme | Tag location |
|---------------|----------------|--------------|
| KERI event verkey (`k[]`, `n[]`) | CESR prefix | Per-key string (`D…` / `1AAI…`) |
| KERI event signature attachment | CESR indexed-siger group | `-A##` counter + per-siger CESR prefix |
| Device DID (`did:key:z…`) | Multicodec varint | Inside base58-decoded bytes |
| Identity DID (`did:keri:…`) | Indirect (via KEL inception event) | Inception event `k[0]` |
| Pairing protocol `device_signing_pubkey` | CESR prefix | Whole field value |
| Node FFI `sign_bytes_raw(private_key_hex, msg, curve)` | Explicit `curve` field | Sibling param |
| Node FFI action-envelope verify | Explicit `curve` field | Sibling param |
| On-disk `known_identities.json` pinned entries | Curve field on the JSON record | `curve` key |
