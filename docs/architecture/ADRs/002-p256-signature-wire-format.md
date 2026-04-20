# ADR 002: P-256 ECDSA signature wire format

**Status:** Accepted
**Date:** 2026-04-20
**Scope:** Mobile FFI ↔ pairing daemon wire protocol for P-256 ECDSA signatures

## Context

The mobile team's iOS Secure Enclave produces P-256 ECDSA signatures via `SecKeyCreateSignature` with algorithm `.ecdsaSignatureMessageX962SHA256`. That algorithm emits an **ASN.1 DER-encoded X9.62 signature**: `SEQUENCE { r INTEGER, s INTEGER }` per [RFC 3279 §2.2.3](https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3).

The daemon verifier in `auths-keri` at `crates/auths-keri/src/keys.rs:180-200` uses:

```rust
let sig = Signature::from_slice(signature)
    .map_err(|e| format!("P-256 signature parse failed: {e}"))?;
```

`p256::ecdsa::Signature::from_slice` accepts **fixed-size raw r‖s (64 bytes)** per the [p256 crate docs](https://docs.rs/p256/latest/p256/ecdsa/type.Signature.html). It does not accept DER. DER input requires `Signature::from_der`.

One side must convert, and the conversion must be specified.

## Decision

**The wire format is raw r‖s (64 bytes, big-endian).** The mobile side converts from iOS SE's DER output to raw r‖s before handing the signature to the FFI assemblers (`assemble_pairing_response_body`, `assemble_auth_challenge_response`). The daemon keeps `Signature::from_slice` and does not gain a DER code path.

## Alternatives considered

### Alternative A — Daemon accepts DER; mobile sends DER verbatim

The daemon adds a fallback branch in `KeriPublicKey::verify_signature` that calls `Signature::from_der` when the input looks like an ASN.1 SEQUENCE. Mobile sends SE's DER output unchanged.

**Rejected because:**
- Adds an ASN.1 parser to `auths-keri`, which is a Layer 0.5 crate whose dependency surface is load-bearing for the WASM verifier. `p256`'s DER path pulls in additional code (length decoding, integer normalization, optional low-S enforcement) that the verifier has so far avoided.
- Accepting both DER and raw at the same API surface opens the door to length-ambiguity attacks (64-byte raw `0x30 0x3e ... ` happens to look like a short DER SEQUENCE — malleability risk).
- Other auths-keri call sites already assume raw r‖s; adding DER here would create inconsistency across the curve-agnostic verification path.

### Alternative B — Daemon accepts both via `curve` tag + explicit `signature_encoding` sibling field

A JSON-level discriminator field (`"signature_encoding": "der" | "raw"`) makes intent explicit.

**Rejected because:**
- Doubles the wire-format test matrix.
- Provides no security benefit: either format must be parsed safely, and the daemon must still pick one canonical internal representation.
- Conflicts with the CLAUDE.md principle of minimizing wire-format ambiguity. The curve tag already tells us P-256; adding a second discriminator is redundant.

### Alternative C — Mobile uses CryptoKit `P256.Signing.ECDSASignature.rawRepresentation`

CryptoKit exposes `P256.Signing.ECDSASignature.rawRepresentation` which is exactly the 64-byte r‖s form. If mobile chooses CryptoKit over raw Security framework, the DER→raw step is trivial.

**Partially adopted:** if the mobile side is already using CryptoKit for its ECDSA types it can call `.rawRepresentation` directly. If using `SecKeyCreateSignature` directly, the DER→raw conversion is a short routine (parse `SEQUENCE`, extract two `INTEGER`s, zero-pad each to 32 bytes, concatenate). Either path lands the same 64 bytes on the wire.

## Consequences

### Code sites that honor this decision

- `crates/auths-keri/src/keys.rs:180-200` — `verify_signature` stays on `Signature::from_slice`. No change.
- `crates/auths-mobile-ffi/src/pairing_context.rs` and `auth_challenge_context.rs` — FFI assemblers accept `signature: Vec<u8>`. The FFI body converts DER → raw via `p256::ecdsa::Signature::from_der(..).to_bytes()` before injecting into the response body, **or** the mobile side supplies raw r‖s directly and the FFI fast-paths the 64-byte case. Both are valid; the FFI accepts either shape to avoid coupling the Swift side to DER-vs-raw sequencing.
- `crates/auths-pairing-daemon/src/auth.rs:239-266` — `verify_sig` unchanged. The daemon sees raw r‖s on the wire as today.
- `crates/auths-pairing-protocol/src/response.rs` — `PairingResponse.signature` stays as a base64url-no-pad-encoded **64-byte** string for P-256; Ed25519 remains 64-byte raw. No schema change needed.

### Tests that exercise this decision

- End-to-end test in `crates/auths-pairing-daemon/tests/cases/p256_end_to_end.rs`: produces raw r‖s, submits, asserts acceptance; also asserts DER submitted directly to the daemon is rejected with a parse error (not `InvalidSignature`).
- FFI unit tests in `crates/auths-mobile-ffi/src/pairing_context.rs` and `auth_challenge_context.rs`: submit DER-shaped bytes to the assembler; verify the emitted body carries raw r‖s.

### Sites that honor this decision

- `crates/auths-mobile-ffi/src/pairing_context.rs` — pairing-response assembler calls `Signature::from_der(...).to_bytes()` if the caller passes DER, else passes raw through.
- `crates/auths-mobile-ffi/src/auth_challenge_context.rs` — auth-challenge assembler mirrors the same normalization.
- `docs/api-spec.yaml` — documents signature as `base64url-no-pad(raw r‖s, 64 bytes)` for P-256.
- `crates/auths-pairing-protocol/src/subkey_chain.rs` — `subkey_binding_signature` uses the same raw r‖s encoding.

### Non-consequences

- Low-S / malleability: `p256::ecdsa::Signature::from_slice` does not enforce low-S. If malleability matters (it does for signatures anchored in transparency logs), the daemon must normalize via `Signature::normalize_s()` before treating two wire-distinct signatures as equivalent. Out of scope for this ADR; tracked separately.
- Secure Enclave DER → raw conversion in Swift: mobile-side concern, documented in `$MOBILE/docs/adr/001-ios-key-custody.md`.

## References

- [RFC 3279 §2.2.3](https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3) — `Ecdsa-Sig-Value` ASN.1 definition.
- [Apple `ecdsaSignatureMessageX962SHA256`](https://developer.apple.com/documentation/security/seckeyalgorithm/ecdsasignaturemessagex962sha256) — produces DER X9.62.
- [p256 crate `Signature`](https://docs.rs/p256/latest/p256/ecdsa/type.Signature.html) — `from_slice` = raw r‖s; `from_der` = DER.
- `crates/auths-keri/src/keys.rs:180-200` — current `verify_signature`.
