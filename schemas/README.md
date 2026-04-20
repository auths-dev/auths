# `schemas/`

JSON Schemas for wire-format structures the auths protocol commits to
across implementations. These files are **canonical** in this repo.
Downstream consumers (the mobile app, third-party clients, fuzz
harnesses, codegen tooling) mirror them.

## Files

| File | Purpose | Mirror |
|---|---|---|
| `attestation-v1.json` | Attestation envelope schema — dual-signed identity + device attestation. | Optional; `auths-verifier` consumes the Rust types directly. |
| `identity-bundle-v1.json` | Identity-bundle export format. | Optional. |
| `keri-icp-v1.json` | KERI inception-event schema. | Mobile KAT + any third-party KEL consumer. |
| `secure-envelope-kat.schema.json` | Known-Answer Test schema for the pairing `SecureEnvelope` AEAD wrapping. | **Required** — mobile mirrors the associated KAT file. See below. |

## SecureEnvelope KAT — canonical vs mirror

The *schema* is here: `schemas/secure-envelope-kat.schema.json` with
`$id = https://schemas.auths.dev/secure-envelope-kat-v1.json`.

The *vectors* are here: `crates/auths-pairing-protocol/tests/vectors/secure_envelope.json`.

The Rust-side drift guard (`kat_vectors_match_current_envelope_output`
in `secure_envelope_vectors.rs`) ensures the vectors match the current
envelope implementation byte-for-byte.

The *mobile mirror* lives at `$MOBILE/shared/secure-envelope-vectors.json`
and MUST:

1. Carry a top-level `"$schema"` field pointing at the canonical `$id`
   URL (`https://schemas.auths.dev/secure-envelope-kat-v1.json`). Mobile
   unit tests should validate the mirrored vectors against the schema
   — the vectors are test material; the schema is the contract.
2. Be byte-for-byte identical to the canonical file *except* for the
   added `$schema` property. A coordinated PR on both repos keeps them
   in lockstep.

### Update protocol

When the envelope implementation changes in a way that alters the KAT:

1. Regenerate the canonical vectors:
   ```
   AUTHS_REGEN_VECTORS=1 cargo nextest run -p auths-pairing-protocol secure_envelope_vectors
   ```
2. Verify the updated schema still covers the shape — if the envelope's
   AAD layout / nonce construction / `envelope_info` changed, bump the
   schema's `version` and update `envelope_info`'s `const`.
3. Open coordinated PRs on this repo **and** `$MOBILE` to land:
   - Updated `crates/auths-pairing-protocol/tests/vectors/secure_envelope.json` (canonical).
   - Updated `$MOBILE/shared/secure-envelope-vectors.json` (mirror, with `$schema` preserved).
4. Bump the schema's `version` *and* the `version` field in every
   vector's metadata if the wire format changed; keep both in sync.

## Validation

To validate vector files against the schema locally:

```
npx ajv-cli validate -s schemas/secure-envelope-kat.schema.json -d crates/auths-pairing-protocol/tests/vectors/secure_envelope.json
```

The Rust-side generator test in `secure_envelope_vectors.rs` does not
currently import a JSON Schema validator — the schema check is an
external tooling step. Adding a `jsonschema`-crate-backed Rust check
is a reasonable future improvement.
