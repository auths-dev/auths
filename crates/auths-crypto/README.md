# auths-crypto

**Layer 0** — the cryptographic foundation of the workspace. A curve-agnostic
provider abstraction (sign / verify / keygen / AEAD / KDF), key parsing, `did:key`
encoding, and PKCS#8 handling, kept dependency-light so everything above can build
on it. Nothing in Layer 0 may depend on `auths-keri`; almost every other crate
depends on this one.

The default curve is **P-256**. Ed25519 is a fully-supported peer.

## Curves & the P-256 default

**Why P-256 is the default:** the **iOS Secure Enclave only supports ECDSA
P-256** (signing + P-256 ECDH) — it cannot hold an Ed25519 key in hardware. A
hardware-backed, non-extractable key on an iPhone *requires* P-256; an Ed25519 key
on iOS would be a software CryptoKit/Keychain key, losing the device-binding
guarantee. P-256 is what makes **mobile device pairing** and **laptop-loss
recovery via mobile** work. Ed25519 is supported as a peer for KERI compatibility.

**Curve tagging is load-bearing — never length-dispatch.** Every byte string that
represents a public key, seed, or signature on a wire or on disk MUST carry its
curve tag in-band. 32 bytes is ambiguous (Ed25519 vs X25519); 33 bytes is
ambiguous (P-256 vs secp256k1). This crate expresses the tag three ways:

- **CESR** verkey codes — `D…` (Ed25519), `1AA…` (P-256). See
  `key_ops::TypedSignerKey::cesr_encoded_pubkey` (byte-identical to keripy via
  `cesride`).
- **`did:key` multicodec** — Ed25519 `0xED` → `z6Mk…`; P-256 `0x1200`
  (`[0x80, 0x24]`) → `zDn…`. See `did_key::did_key_decode`.
- **Explicit `curve` field** — for FFI/JSON wire formats; default when absent is
  P-256.

`CurveType::from_public_key_len_fallback` exists only for ingestion boundaries
where the tag was already lost upstream — every call site must justify it and is
tracked for migration. Full spec: `docs/architecture/cryptography.md`.

> Note on adjacent curve roles (not this crate's keys): a transparency-log
> *checkpoint* signature is the log operator's key — Sigstore Rekor uses
> **ECDSA-P256**; a *witness cosignature* is **Ed25519** by the C2SP
> `tlog-cosignature` spec (externally mandated, in-band tagged). Neither is an
> Auths identity/device key — only the device key (P-256, Secure Enclave) is.

## What's in the crate

| Module | Provides |
|---|---|
| `provider` | The `CryptoProvider` trait (curve-agnostic `sign`/`verify`/keygen, AEAD/KDF/MAC), `CurveType`, length constants (`{ED25519,P256}_{PUBLIC_KEY,SIGNATURE}_LEN`), `SecureSeed`, `default_provider()` |
| `key_ops` | `TypedSignerKey` — the curve-tagged signer that replaces every historic `(SecureSeed, CurveType)` pair; `TypedSeed`, `ParsedKey`, `parse_key_material` |
| `did_key` | `did:key` ↔ raw key: `DecodedDidKey`, `did_key_decode`, `did_key_to_p256`, `ed25519_pubkey_to_did_keri` |
| `key_material` | Ed25519 PKCS#8 v2 build/parse, seed parsing |
| `pkcs8` | `Pkcs8Der` curve-tagged container |
| `hash256` | `Hash256` (SHA-256 newtype) |
| `secret` / `key_material` | `Secret`, zeroizing seed handling |
| `ssh` | OpenSSH public-key → raw key parsing |

## Providers & build profiles

The `CryptoProvider` trait has one implementation per build profile; pick via
features. They are not stacked — exactly one is active.

| Feature | Provider | Backend / notes |
|---|---|---|
| `native` *(default)* | `RingCryptoProvider` | `ring` + RustCrypto `p256`; ChaCha20-Poly1305 AEAD, HKDF/HMAC-SHA-256 |
| `wasm` | `WebCryptoProvider` | Browser `SubtleCrypto` (`js-sys`/`web-sys`); native deps excluded on `wasm32` |
| `fips` | `AwsLcProvider` | AWS-LC-FIPS (FIPS 140-3). Needs CMake + Go + C toolchain. **Mutually exclusive** with `cnsa`/`wasm` (`compile_error!` guards) |
| `cnsa` | `CnsaProvider` | CNSA 2.0: P-384 ECDSA/ECDH, SHA-384, AES-256-GCM. **Rejects** P-256 / ChaCha20 / SHA-256 at the provider boundary. Mutually exclusive with `fips` |

`p256` is pinned to `=0.13.2` deliberately: it exports SEC1-compressed (33-byte)
public keys that CESR requires and `ring` cannot produce.

## Position in the architecture

```
Layer 0: auths-crypto   (THIS CRATE — curve-agnostic primitives, did:key, PKCS#8)
            ▲
            └── depended on by: auths-keri, auths-verifier, auths-core, auths-id,
                auths-sdk, auths-transparency, auths-infra-*, auths-cli, … (≈18 crates)
```

Dependency direction is strictly upward — `auths-crypto` depends only on
RustCrypto / `ring` / `aws-lc-rs` / `cesride` / `serde`, never on a higher layer.

## Usage

```rust,ignore
use auths_crypto::{default_provider, CurveType};

// Curve-agnostic entry points: domain code never matches CurveType itself.
// The seed carries its curve tag; verify takes the curve explicitly.
let provider = default_provider();
let (seed, pubkey) = provider.generate_typed_keypair(CurveType::P256).await?;
let sig = provider.sign_typed(&seed, message).await?;
provider.verify_typed(CurveType::P256, &pubkey, message, &sig).await?;
```

```rust,ignore
use auths_crypto::{did_key_decode, DecodedDidKey, key_ops::TypedSignerKey};

// did:key auto-detects the curve from its multicodec prefix.
match did_key_decode("did:key:zDn...")? {
    DecodedDidKey::P256(pk)    => { /* 33-byte SEC1-compressed */ }
    DecodedDidKey::Ed25519(pk) => { /* 32-byte */ }
}

// One curve-tagged signer instead of passing (seed, curve) pairs around.
let signer = TypedSignerKey::from_pkcs8(&pkcs8_der)?;
let verkey = signer.cesr_encoded_pubkey(); // "D…" (Ed25519) or "1AA…" (P-256)
```

Build the FIPS or CNSA profile from the crate directory (the workspace resolver
rejects per-crate `--features` from the root):

```bash
cd crates/auths-crypto && cargo build --no-default-features --features fips
cd crates/auths-crypto && cargo build --no-default-features --features cnsa
```
