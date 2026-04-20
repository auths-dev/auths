# Cryptographic Primitive Inventory

Authoritative, auditable table of every cryptographic primitive the `auths/` workspace uses today, the exact library backing it, the resolved version, and the source file where it is invoked.

**Purpose.** This file is the audit baseline for Epic fn-128 (§1.1 crypto hardening). Every subsequent item in §1.1 — FIPS/CNSA provider swap, `#[secret]` marker, RFC 6979 audit, dependency pinning — can be diff'd against this table.

**Scope.** Sign/verify, key agreement, KDF, AEAD, transparency-log hash, canonical JSON, constant-time compare, zeroization wrappers. The workspace has additional non-crypto deps (tokio, axum, reqwest) — those are out of scope for this document.

**Freshness.** Versions below reflect `cargo tree --workspace` on 2026-04-19 against `Cargo.lock` committed at the time. Run `cargo tree --workspace` to re-resolve; the "how to re-verify" section at the bottom gives the exact commands.

---

## 1. Primary primitives

| Primitive | Algorithm / construction | Library | Resolved version | Primary source file |
|---|---|---|---|---|
| Digital signature (identity, device) — verify | ECDSA-P256 | `p256 0.13.2` via `ring 0.17.14` (provider-dispatched) | `p256 0.13.2`, `ring 0.17.14` | `crates/auths-crypto/src/ring_provider.rs:99-114` (`verify_p256`) |
| Digital signature (identity, device) — sign | ECDSA-P256 (RFC 6979 deterministic) | `p256 0.13.2` / `ecdsa 0.16.9` | `p256 0.13.2`, `ecdsa 0.16.9`, `signature 2.2.0` | `crates/auths-crypto/src/ring_provider.rs:48-56` (`RingCryptoProvider::p256_sign`) |
| Digital signature (KERI event) — sign + verify | Ed25519 | `ring 0.17.14` | `ring 0.17.14` | `crates/auths-crypto/src/ring_provider.rs:58-96` (`ed25519_verify`, sync), `:135-202` (trait methods) |
| Key agreement (pairing ECDH) | P-256 ephemeral ECDH | `p256 0.13.2` | `p256 0.13.2` | `crates/auths-pairing-protocol/src/token.rs:63` (`EphemeralSecret::random`), `:122-127` (`complete_exchange`) |
| KDF (SAS, transport key) | HKDF-SHA256 | `hkdf 0.12.4`, `sha2 0.10.9` | `hkdf 0.12.4`, `sha2 0.10.9` | `crates/auths-pairing-protocol/src/sas.rs:48-79` (`derive_sas`), `:151-166` (`derive_transport_key`) |
| AEAD (session transport) | ChaCha20-Poly1305 | `chacha20poly1305 0.10.1` | `chacha20poly1305 0.10.1` | `crates/auths-pairing-protocol/src/sas.rs:85-114` (`TransportKey` + `encrypt`) |
| AEAD (other — at-rest file encryption) | AES-256-GCM | `aes-gcm 0.10.3` | `aes-gcm 0.10.3` | `crates/auths-core/src/storage/encrypted_file.rs` (consumer; not invoked by pairing path) |
| Transparency-log tree hash | SHA-256 (RFC 6962) | `sha2 0.10.9` | `sha2 0.10.9` | `crates/auths-transparency/src/verify.rs:7` (import), `:184` (ECDSA verify via ring constants), witness cosign compare at `:207-210` |
| DID encoding (`did:key` multicodec) | varint + multibase base58btc | `bs58 0.5.1` + hand-rolled varint | `bs58 0.5.1` | `crates/auths-crypto/src/did_key.rs:55` (`ed25519_pubkey_to_did_keri`), `:69-121` (`did_key_to_p256`, `did_key_decode`) |
| KERI DID encoding | CESR (base64url prefixes `D` / `1AAI`) | `base64 0.22.1` + hand-rolled CESR prefix logic | `base64 0.22.1` | `crates/auths-keri/src/keys.rs:89-135` (`KeriPublicKey::parse`), `:165-170` (`cesr_prefix`) |
| Canonical JSON (attestation serialization) | JCS (RFC 8785 subset) | `json-canon 0.1.3` | `json-canon 0.1.3` (exact-pinned at `Cargo.toml:52`) | consumers throughout `auths-id`; pin lives at workspace root |
| Constant-time comparison | `subtle::ConstantTimeEq` | `subtle 2.6.1` | `subtle 2.6.1` | `crates/auths-keri/src/crypto.rs:53-60`, `crates/auths-pairing-daemon/src/token.rs:29-38`, `crates/auths-core/src/trust/pinned.rs:66-67`, `crates/auths-transparency/src/verify.rs:207-210`, `crates/auths-sdk/src/domains/org/service.rs:110-114` |
| Zeroization wrappers | `Zeroize` / `ZeroizeOnDrop` / `Zeroizing<T>` | `zeroize 1.8.2` | `zeroize 1.8.2` (with `serde` + `derive` features) | `crates/auths-crypto/src/provider.rs:86-97` (`SecureSeed`), `crates/auths-crypto/src/key_ops.rs:21-26` (`TypedSeed`), `crates/auths-crypto/src/pkcs8.rs:21` (`Pkcs8Der`), `crates/auths-pairing-protocol/src/sas.rs:85` (`TransportKey`) |
| Randomness (security-sensitive) | `OsRng` (syscall-backed) | `p256::elliptic_curve::rand_core::OsRng` / `rand::rngs::OsRng` / `ring::rand::SystemRandom` | `rand_core 0.6.4`, `ring 0.17.14` | `crates/auths-pairing-protocol/src/token.rs:3,63,71-72`, `crates/auths-pairing-protocol/src/response.rs:3,102`, `crates/auths-pairing-daemon/src/token.rs:54` (`SystemRandom`) |
| Randomness (known hit — pending fix) | `rand::random()` (delegates to `thread_rng` depending on feature flags) | `rand` | — | `crates/auths-pairing-protocol/src/sas.rs:98` — **scheduled replacement in fn-128.T6** |

## 2. Ed25519 and `ed25519-dalek` — clarifying note

The hardening plan's original draft mentioned `ed25519-dalek` as the pin target. **That is not correct for this workspace.** The facts on the ground:

- `auths-crypto`'s Ed25519 sign/verify surface goes through **`ring 0.17.14`**. See `crates/auths-crypto/src/ring_provider.rs:58-96, 135-202`.
- `ed25519-dalek 2.2.0` does appear in the resolved dep tree, but **only transitively through `cesride 0.6.4`**, a KERI protocol library that `auths-keri` depends on. Our own code never constructs `ed25519_dalek::SigningKey` / `VerifyingKey` directly.
- The fn-128.T9 pin list therefore targets `ring` (not `ed25519-dalek`). If a future CNSA/FIPS provider swap retires the ring-backed Ed25519 path, fn-128.T3 (FIPS via `aws-lc-rs`) will route Ed25519 through `aws-lc-rs`, and `cesride`'s transitive `ed25519-dalek` remains for KERI-library-internal use.

## 3. P-384 — clarifying note

`p384 0.13.1` appears in the resolved dep tree, but **only transitively**:

- Via `jsonwebtoken 10.3.0` (P-384 JWK support — `auths-infra-http`, `auths-mcp-server`).
- Via `ssh-key 0.6.7` (SSH key parsing, which may carry P-384 material — `auths-cli`, `auths-core`, et al.).

**No code path in `auths-crypto` signs or verifies with P-384 today.** The fn-128.T4 CNSA feature will introduce a dedicated `CnsaProvider` at `crates/auths-crypto/src/cnsa_provider.rs` that uses `p384` for signing. Until that lands, any `p384` symbol in the tree is consumed only by the two transitive paths above.

## 4. Encoded formats in flight

| Format | Consumer | Source |
|---|---|---|
| CESR prefix `D{base64}` | Ed25519 verkey on KEL events | `crates/auths-keri/src/keys.rs:89-135` |
| CESR prefix `1AAI{base64}` | P-256 compressed verkey on KEL events | same |
| `did:key:z6Mk…` multicodec | Ed25519 device identifier | `crates/auths-crypto/src/did_key.rs:55` |
| `did:key:zDna…` multicodec | P-256 device identifier | `crates/auths-crypto/src/did_key.rs:121` (`did_key_decode`) |
| `did:keri:E{said}` | KERI identity identifier (derived from key) | `crates/auths-keri/src/` (SAID computation) |
| DSSE envelope | Rekor submission payload wrapper | `crates/auths-infra-rekor/src/client.rs:76-114` |
| In-toto v1 Statement | SLSA-consumable attestation body | (planned) `crates/auths-id/src/attestation/intoto.rs` |

## 5. Pending swaps (referenced by later §1.1 items)

| Item | Primitive | Today | Under `fips` | Under `cnsa` | Owner |
|---|---|---|---|---|---|
| 1.1.2 (T3) | ECDSA P-256 sign/verify | `p256` / `ring` | `aws-lc-rs` (FIPS-validated) | — | fn-128.T3 |
| 1.1.2 (T3) | Ed25519 sign/verify | `ring` | `aws-lc-rs` (FIPS-validated) | — | fn-128.T3 |
| 1.1.2 (T4) | ECDSA signatures (CNSA) | `p256` | — | `p384` (P-384/SHA-384) | fn-128.T4 |
| 1.1.2 (T4) | SHA hash width (CNSA) | SHA-256 | — | SHA-384 | fn-128.T4 |
| 1.1.2 (T4) | AEAD (CNSA) | ChaCha20-Poly1305 | — | AES-256-GCM | fn-128.T4 |
| 1.1.4 (T6) | `rand::random()` nonce | `rand::random` | `OsRng` | `OsRng` | fn-128.T6 |
| 1.1.5 (T8) | ECDSA nonce generation | RFC 6979 (default) | RFC 6979 | RFC 6979 | fn-128.T8 |
| 1.1.6 (T9) | Dep pinning | caret ranges | exact `=x.y.z` | exact `=x.y.z` | fn-128.T9 |

## 6. Known concerns / residuals

- **`CryptoProvider` trait is incomplete** — today the trait exposes `verify_p256`, `verify_ed25519`, `sign_ed25519`, `generate_ed25519_keypair`, `ed25519_public_key_from_seed`, but **not** `sign_p256`. P-256 signing is only available as `RingCryptoProvider::p256_sign` (inherent, non-trait). Six call sites construct `p256::ecdsa::SigningKey` directly, bypassing any provider swap:
  - `crates/auths-crypto/src/key_ops.rs:148, 167, 284, 365, 462, 492`
  - `crates/auths-id/src/keri/inception.rs:46`
  Any FIPS/CNSA feature is structurally inert until these are rerouted. fn-128.T2 owns the trait extension.
- **`rand::random()` at `crates/auths-pairing-protocol/src/sas.rs:98`** — single production site; `rand::random` can delegate to `thread_rng` under certain feature combinations. Replacement to explicit `OsRng` is owned by fn-128.T6, landing atomically with the clippy deny rule for `rand::thread_rng` / `rand::random`.
- **Caret-range version specifiers** — `p256 = "0.13"`, `chacha20poly1305 = "0.10"`, `sha2 = "0.10"`, `hkdf = "0.12"`, `ecdsa = "0.16"`, `signature = "2"` are caret ranges in their respective crate `Cargo.toml`s. A minor bump could change DER encoding, AEAD overhead, or trait dispatch and silently invalidate existing signatures. Exact-pinning is owned by fn-128.T9.
- **No `cargo-deny` configuration** — no CI gate for RUSTSEC advisories, license allowlist, duplicate versions, or source restriction. Owned by fn-128.T9.
- **Rekor trust-root key is zeroed placeholder** — `crates/auths-transparency/src/lib.rs:190-215` has `log_public_key: [0u8; 32]` for the Sigstore Rekor default config. Owned by fn-131.T6 (epic fn-131).

## 7. How to re-verify this document

```bash
# Re-resolve versions
cd /Users/bordumb/workspace/repositories/auths-base/auths
cargo tree --workspace --prefix none 2>&1 \
  | grep -E "^(ring|hkdf|sha2|chacha20poly1305|ed25519-dalek|p256|ecdsa|p384|aes-gcm|json-canon|subtle|zeroize|signature) v" \
  | sort -u

# Confirm Ed25519 does not flow through ed25519-dalek in our first-party code
grep -rn "ed25519_dalek" crates/auths-crypto/src/ crates/auths-keri/src/
# Expected: zero matches.

# Confirm the rand::random() hit remains
grep -n "rand::random\(\)" crates/auths-pairing-protocol/src/
# Expected (until fn-128.T6 lands): sas.rs:98.

# Confirm no new direct SigningKey::sign sites appear
grep -rn "p256::ecdsa::SigningKey\|SigningKey::sign(" crates/ \
  | grep -v test | grep -v tests/
```

## 8. References

- `CLAUDE.md` — project conventions: wire-format curve tagging (§"Wire-format Curve Tagging"), clock injection, `thiserror`/`anyhow` translation boundary.
- `SECURITY.md` — zeroize discipline and memory-hygiene rules.
- `.flow/specs/fn-128.md` — epic spec.
- `.flow/tasks/fn-128.1.md` — this task.
- Follow-up §1.1 items: `.flow/tasks/fn-128.{2,3,4,5,6,7,8,9}.md`.
- External: NIST SP 800-131A Rev. 2, SP 800-56A Rev. 3, SP 800-90A/B/C; FIPS 140-3; NSA CNSA 2.0 (May 2025); RFC 6979; RFC 6962; RFC 8785.
