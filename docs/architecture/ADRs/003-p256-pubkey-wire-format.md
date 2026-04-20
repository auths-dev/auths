# ADR 003: P-256 public-key wire format

**Status:** Accepted
**Date:** 2026-04-20
**Scope:** Mobile FFI ↔ pairing daemon wire protocol for P-256 public keys

## Context

iOS Secure Enclave exposes a P-256 public key via `SecKeyCopyExternalRepresentation`, which returns ANSI X9.63 **uncompressed SEC1** bytes: `0x04 || X(32) || Y(32)` = 65 bytes. For interoperability with ASN.1-aware consumers, iOS code typically wraps this in an SPKI DER envelope (`wrapP256RawInSPKI` on the mobile side).

The daemon stores P-256 public keys as `KeriPublicKey::P256([u8; 33])` — **compressed SEC1** (`0x02` or `0x03` || X(32)) per `crates/auths-keri/src/keys.rs:70-75`. The CESR parser `KeriPublicKey::parse` at `crates/auths-keri/src/keys.rs:89-135` rejects any other length for P-256 via:

```rust
if bytes.len() != 33 {
    return Err(KeriDecodeError::InvalidLength {
        expected: 33,
        actual: bytes.len(),
    });
}
```

The mobile side's 65-byte uncompressed (or SPKI DER) form will not parse at the daemon without a conversion step. The question is: which side converts, and where.

## Decision

**The mobile side compresses P-256 public keys to 33-byte SEC1 before handing them to the FFI.** The daemon accepts only 33-byte compressed P-256 public keys on the wire; 65-byte uncompressed payloads and SPKI DER envelopes are rejected with an explicit length/format error.

Swift-side compression is already implemented at `SecureEnclaveService.compressP256` (line ≈268 in the mobile repo), using the standard `y_is_odd ? 0x03 : 0x02` discriminator followed by the 32-byte X coordinate.

## Alternatives considered

### Alternative A — Daemon accepts uncompressed (65-byte) P-256

`auths-keri` extends `KeriPublicKey::parse` (or a sibling entry point) to accept either 33 or 65 bytes, compressing internally before storage.

**Rejected because:**
- Adds branching at the CESR parse boundary, which is precisely the site the wire-format-curve-tagging rule in CLAUDE.md §4 exists to keep narrow.
- `KeriPublicKey::P256` is typed as `[u8; 33]`. Accepting 65 bytes means either changing the enum shape (breaks every call site) or compressing before constructing, which hides the wire ambiguity inside the parser.
- An uncompressed point implicitly asserts Y is known; compressing throws Y away and derives it on use. Accepting both forms means verifiers must trust that the submitted Y is the true Y — wrong Y would yield a valid-looking compressed point on verification because both (X, Y) and (X, -Y) lie on the curve but only one has the submitted Y. Today this is a non-issue because nothing uses the Y; tomorrow it is a latent correctness hazard.

### Alternative B — Daemon accepts SPKI DER

Accept the full SPKI envelope (`SubjectPublicKeyInfo` ASN.1 structure from RFC 5280 / RFC 5480), pulling the raw point via `VerifyingKey::from_public_key_der`.

**Rejected because:**
- Same ASN.1-surface concern as ADR 002: expanding the verifier's parse surface into ASN.1 adds risk for no protocol benefit.
- SPKI carries an OID identifying the curve. The daemon already knows the curve from the sibling `curve` field in `PairingResponse`. The OID is redundant and, if it conflicts with the sibling, creates another "which do we trust" failure mode.

### Alternative C — Wire format is CESR (`1AAI{base64url}`)

The KERI protocol already has a wire form for P-256 verkeys: `1AAI` prefix + base64url of the compressed 33 bytes. Use that instead of a raw byte string.

**Partially adopted:** this is already how identity-level keys flow through the KEL path (`KeriPublicKey::parse` is the authoritative parser). For the session-level pairing wire, the JSON schema in `crates/auths-pairing-protocol/src/response.rs:20-33` encodes pubkeys as base64url-no-pad of the raw compressed bytes (33 bytes pre-encode) with the curve carried in a sibling `curve: CurveTag` field. This ADR preserves that layout. Migrating the pairing wire to `1AAI`-prefixed CESR is a possible future simplification but out of scope.

## Consequences

### Sites that honor this decision

- `crates/auths-pairing-daemon/src/handlers.rs` — `decode_device_pubkey` dispatches on the sibling `curve` field (not byte length) and validates length as a post-routing check. 33-byte compressed P-256 is the only accepted form; 65-byte uncompressed routes to `InvalidPubkeyLength` (400), not `UnauthorizedSig` (401).
- `crates/auths-keri/src/keys.rs:70-135` — `KeriPublicKey::P256` and `KeriPublicKey::parse` stay as-is (33 B only).
- `crates/auths-mobile-ffi/src/pairing_context.rs` and `auth_challenge_context.rs` — FFI builders accept `device_signing_pubkey_der: Vec<u8>` and normalize on input:
  - 33 bytes with leading `0x02`/`0x03` → use as-is.
  - 65 bytes with leading `0x04` → compress to 33 bytes.
  - SPKI DER → parse via `VerifyingKey::from_public_key_der`, compress to 33.
  - Else → `MobileError::InvalidKeyData`.

  Mobile-side best practice is to compress before calling; the FFI is tolerant because compressing on the host avoids a round-trip through Swift for the common iOS case.
- `crates/auths-pairing-protocol/src/response.rs:20-33` — `device_signing_pubkey` encoding in `PairingResponse` is base64url-no-pad(33-byte compressed SEC1) for P-256.
- `crates/auths-pairing-protocol/src/subkey_chain.rs` — `bootstrap_pubkey` and the implicit subkey pubkey in the binding message both use 33-byte compressed SEC1.
- `docs/api-spec.yaml` — pubkey documented as `base64url-no-pad(compressed SEC1, 33 bytes)` for P-256.

### Tests that exercise this decision

- `crates/auths-pairing-daemon/src/handlers.rs` unit tests in `decode_device_pubkey_tests`: 65-byte payload with `curve: P256` routes as P-256 (curve-field dispatch), then fails validation with `InvalidPubkeyLength` — not `InvalidSignature`.
- FFI unit tests in `crates/auths-mobile-ffi/src/pairing_context.rs`: submit each of (33-byte compressed, 65-byte uncompressed, SPKI DER) to the builder; verify either success (with compression applied) or explicit `InvalidKeyData` error.
- End-to-end test in `crates/auths-pairing-daemon/tests/cases/p256_end_to_end.rs`: simulates the iOS Secure Enclave export flow (65-byte → compress → 33-byte) and verifies round-trip through the daemon.

### Non-consequences

- Point-at-infinity / non-curve-points: `p256::ecdsa::VerifyingKey::from_sec1_bytes` validates curve membership. No additional check required in the FFI — an invalid compressed point surfaces as a parse error at the daemon, correctly routed to `InvalidPubkey`.
- Ed25519 wire format: unchanged (32-byte raw).
- Identity-level (KEL) P-256 keys: already flow as CESR `1AAI` and are untouched by this ADR.

## References

- [SEC1 v2.0](https://www.secg.org/sec1-v2.pdf) §2.3.3 (uncompressed), §2.3.4 (compressed).
- [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) — curve OIDs for SPKI.
- [Apple `SecKeyCopyExternalRepresentation`](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)).
- `crates/auths-keri/src/keys.rs:70-135` — current P-256 handling.
- `crates/auths-pairing-daemon/src/handlers.rs` — `decode_device_pubkey` (dispatches on the sibling `curve` field, validates length post-routing).
