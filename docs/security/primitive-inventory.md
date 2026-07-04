# Cryptographic primitive inventory

**Authoritative table of every cryptographic primitive in the Auths workspace,
with the exact crate and pinned version providing it.** Referenced by
`SECURITY.md`. This file is drift-guarded: `scripts/check_primitive_inventory.py`
asserts every version in the pin table below matches the corresponding
`Cargo.toml` pin, and CI runs it (see `.github/workflows/`). A primitive added
or a pin bumped without updating this table fails the check.

Format-normative crypto crates are **exact-pinned** (`=x.y.z`) because a silent
minor bump can change wire bytes and invalidate every existing signature; the
bump procedure is in `docs/security/dependency-policy.md`.

## Providers

Concrete backends selected at compile time (`auths-crypto`):

| Provider | Feature | Primitives |
|---|---|---|
| `RingCryptoProvider` | default | Ed25519, SHA-2, HKDF/HMAC, system RNG |
| `AwsLcProvider` | `fips` | FIPS 140-3 backend (aws-lc-rs) |
| `CnsaProvider` | `cnsa` | P-384, AES-256-GCM, SHA-384 (rejects P-256/ChaCha/SHA-256) |
| `WebCryptoProvider` | wasm | browser SubtleCrypto + pure-Rust verify |

## Pin table (machine-checked)

Each row is `<crate> = <version>` as pinned in `Cargo.toml`. The checker parses
this table; keep the `crate` / `version` columns exact.

### Signatures

| Primitive | crate | version |
|---|---|---|
| Ed25519 (RFC 8032), native | ring | 0.17.14 |
| Ed25519, pure-Rust verify (WASM leaf, pairing) | ed25519-dalek | 2 |
| ECDSA P-256 (RFC 6979 deterministic) | p256 | 0.13.2 |
| secp256k1 Schnorr (BIP-340, optional) | k256 | 0.13 |

Post-quantum signatures (ML-DSA / FIPS 204) are **not yet in the tree** — tracked
as PRD PQ-2/PQ-3. Update this section when they land.

### Hashing

| Primitive | crate | version |
|---|---|---|
| SHA-256 / SHA-384 / SHA-512 | sha2 | 0.10.9 |
| BLAKE3 (SAIDs, pre-rotation commitments, policy hashing) | blake3 | 1.8.4 |

### Key derivation & MAC

| Primitive | crate | version |
|---|---|---|
| Argon2id (at-rest key encryption) | argon2 | 0.5.3 |
| HKDF-SHA256/384 | hkdf | 0.12.4 |
| HMAC-SHA256/384 | hmac | 0.12.1 |

### AEAD

| Primitive | crate | version |
|---|---|---|
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | chacha20poly1305 | 0.10.1 |
| AES-256-GCM | aes-gcm | 0.10.3 |

### Key agreement

| Primitive | crate | version |
|---|---|---|
| X25519 ECDH (pairing) | x25519-dalek | 2 |
| ML-KEM-768 (PQ-hybrid pairing, optional, **UNAUDITED**, off by default) | ml-kem | 0.2 |

### Encoding & hygiene

| Primitive | crate | version |
|---|---|---|
| CESR qb64 key encoding | cesride | 0.6 |
| JSON canonicalization (signing input) | json-canon | 0.1.3 |
| Constant-time comparison | subtle | 2.6.1 |
| Zeroization of secrets | zeroize | 1.8.2 |
| X.509 / TLS cert generation (optional) | rcgen | 0.14 |
| SSH key formats | ssh-key | 0.6.7 |
| PKCS#8 key encoding | pkcs8 | 0.10 |

### Randomness

CSPRNG only — `ring::rand::SystemRandom` (native), `p256`/`ed25519-dalek` over
`OsRng`, `getrandom` 0.4.1 (WASM). `thread_rng`/`rand::random` are lint-banned
workspace-wide (`clippy.toml`). See `docs/security/rng-policy.md`.

### FIPS backend

| Primitive | crate | version |
|---|---|---|
| FIPS 140-3 validated crypto (optional) | aws-lc-rs | 1.16 |
