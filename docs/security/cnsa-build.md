# CNSA 2.0 Build (`--features cnsa`)

Guide for building `auths` with every cryptographic primitive routed through
CNSA 2.0-compliant algorithms: P-384 ECDSA/ECDH, SHA-384, HMAC-SHA-384,
HKDF-SHA-384, AES-256-GCM.

**Status:** CryptoProvider trait impl landed in fn-128.T4. KEL-emission
semantics (P-384 CESR and did:key multicodec prefixes) are tracked as a
follow-up — CNSA builds today can **verify** P-384 signatures but cannot yet
**emit** P-384 KEL events with curve-tagged wire formats.

---

## What CNSA mode rejects

At the `CryptoProvider` boundary, `CnsaProvider` returns
`CryptoError::OperationFailed` (or `UnsupportedTarget`) for:

| Primitive              | Rejected in CNSA | CNSA-approved replacement |
|------------------------|------------------|----------------------------|
| ECDSA / ECDH P-256     | ✗                | P-384                      |
| SHA-256                | ✗ (via MAC/KDF)  | SHA-384                    |
| HMAC-SHA-256           | ✗                | HMAC-SHA-384               |
| HKDF-SHA-256           | ✗                | HKDF-SHA-384               |
| ChaCha20-Poly1305      | ✗                | AES-256-GCM                |
| AES-128-GCM            | ✗                | AES-256-GCM                |
| RSA (any variant)      | ✗                | P-384 ECDSA                |

Ed25519 is **not** on CNSA 2.0's approved list but remains available in the
workspace for legacy KERI compat and SSH imports — both out-of-band from
any NSS data path. Policy that requires strict CNSA compliance rejects
Ed25519 one layer up (SDK / org policy), not at the provider surface.

## Mutual exclusion with FIPS

`--features cnsa` and `--features fips` are mutually exclusive. The
`compile_error!` guard at `crates/auths-crypto/src/provider.rs` blocks any
build that tries to enable both. The choice is per-deployment: FIPS binaries
carry an AWS-LC-FIPS validated module; CNSA binaries enforce the stronger
algorithm floor but use RustCrypto (pure Rust).

Future: an `aws-lc-rs fips + CNSA subset` provider that selects a FIPS-
validated module AND the CNSA-approved algorithms within it. Not shipped
in fn-128; track under fn-128 follow-ups.

## Local build

```bash
cd auths
cargo build --workspace --features cnsa
cargo nextest run --workspace --features cnsa
cargo clippy --workspace --features cnsa --all-targets -- -D warnings
```

No external toolchain requirements beyond the standard Rust workspace
(unlike FIPS, which requires CMake + Go for aws-lc-rs).

## Verifying CNSA rejections

```bash
# Build with CNSA
cargo test -p auths-crypto --features cnsa cnsa_rejects_p256

# Expected: the P-256 sign/verify paths return typed UnsupportedTarget /
# OperationFailed errors. The test at crates/auths-crypto/tests/cases/kat.rs
# (gated by #[cfg(feature = "cnsa")]) verifies this.
```

## KEL emission status (follow-up)

Today `KeriPublicKey::parse` and `DecodedDidKey::decode` know Ed25519 (`D`
CESR prefix, `z6Mk…` multibase) and P-256 (`1AAI` CESR prefix, `zDna…`
multibase). Adding P-384:

- CESR: `1AAJ` (compressed P-384 pubkey, 49 bytes → base64url).
- `did:key` multicodec: `p384-pub = 0x1201` (varint `0x81 0x24`).
- `DevicePublicKey::try_new` must accept P-384 key lengths (49 compressed, 97 uncompressed).

These extensions are NOT in fn-128.T4 scope. CNSA builds are signature-
verify-only for existing P-256 KELs (which CNSA rejects — see above) and
signature-compute for P-384 keys (which there is no CESR / did:key path for
yet). Net effect: CNSA builds work for HMAC-SHA-384 authentication and
AES-256-GCM transport, but KEL-level identity ops need the P-384 wire-
format work.

**Tracked as:** fn-128 follow-up task (file under §1.1.2 wire-format
extension).

## Witness receipt compatibility

P-256 witness receipts produced against the default build are rejected by
the CnsaProvider at verify time (`OperationFailed("P-256 verify is rejected
under --features cnsa")`). Witness operators adopting CNSA 2.0 must emit
P-384 receipts; document the migration plan in the witness onboarding doc
(`docs/security/witness-diversity.md`, once that file lands in fn-131.T5).

## Residual risks (accepted)

- The P-384 scalar seed (48 bytes) is wrapped in the 32-byte `SecureSeed`
  type at the trait boundary. Callers that need the full 48-byte scalar must
  use a richer typed-seed path; this is marked as a follow-up in the
  `CnsaProvider::p384_generate` doc-comment.
- Pure-Rust `p384` is not FIPS-validated. CNSA compliance (without FIPS) is
  an algorithm-floor commitment, not a module-validation commitment.
  Enterprises that need both FIPS and CNSA together track a future provider
  in the CNSA follow-up pack.
- Ed25519 availability under CNSA. This is a deliberate compat carve-out,
  documented here and at `cnsa_provider.rs` module header.

## References

- `crates/auths-crypto/src/cnsa_provider.rs` — the provider impl.
- `crates/auths-crypto/src/provider.rs` — mutual-exclusion guard.
- `docs/security/nonce-management.md` — AES-256-GCM nonce discipline.
- [CNSA 2.0 Algorithms CSA (May 2025)](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
- [NIST SP 800-56A Rev. 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/nist.sp.800-56Ar3.pdf)
- [NIST SP 800-131A Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
