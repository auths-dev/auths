# Action Envelope

Specification for signed action envelopes — lightweight, application-level signed payloads for use cases like API authorization, AI agent tool calls, and chat message signing.

## Overview

An action envelope wraps an arbitrary JSON payload with an identity binding and Ed25519 signature. Unlike [attestations](attestation-schema.md), which bind an identity to a device with dual signatures, action envelopes represent a single signed action by an identity.

## Envelope Structure

```json
{
  "version": "1.0",
  "type": "tool_call",
  "identity": "did:keri:EBf7Y2pAnRd2cf6rbP7hbUkJvWMz3RRJPpL...",
  "payload": {
    "action": "read_file",
    "path": "/etc/config.json"
  },
  "timestamp": "2025-06-01T12:34:56Z",
  "signature": "a1b2c3d4e5f6..."
}
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | `string` | Yes | Envelope format version (currently `"1.0"`) |
| `type` | `string` | Yes | Application-defined action type (e.g. `"tool_call"`, `"api_request"`, `"chat_message"`) |
| `identity` | `string` | Yes | Signer's identity DID (`did:keri:E...`) |
| `payload` | `object` | Yes | Arbitrary JSON object — contents are application-defined |
| `timestamp` | `string` | Yes | RFC 3339 timestamp of when the action was signed |
| `signature` | `string` | Yes | Hex-encoded Ed25519 signature over the canonical signing input |

All fields are required. The `payload` object itself may contain any valid JSON, but the field must be present (use `{}` for actions with no data).

## Canonical Signing Input

The signing input is produced by:

1. Constructing the envelope JSON with all fields **except** `signature`
2. Canonicalizing with `json_canon::to_string()`
3. The resulting byte string is the signing input

```rust
// Pseudocode
let signing_data = json_canon::to_string(&json!({
    "version": envelope.version,
    "type": envelope.type,
    "identity": envelope.identity,
    "payload": envelope.payload,
    "timestamp": envelope.timestamp,
}))?;
let signature = keypair.sign(signing_data.as_bytes());
```

This follows the same canonicalization pattern used by attestations (`CanonicalAttestationData` in `auths-verifier/src/core.rs`), where signature fields are excluded from the canonical form before signing.

### Why `json-canon`?

[RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) defines JSON Canonicalization Scheme. The `json-canon` crate implements this standard, producing deterministic output by:

- Sorting object keys lexicographically
- Removing insignificant whitespace
- Using minimal numeric representation

The `version` field is included in the signing input so that a `"1.0"` envelope cannot be replayed as a future version.

## Verification Procedure

To verify an action envelope:

1. **Parse** the envelope JSON
2. **Check version** — reject unknown versions
3. **Validate timestamp** — reject envelopes outside acceptable clock skew (application-defined; recommended: 5 minutes)
4. **Resolve identity** — look up the current public key for `identity` via KERI key state or attestation chain
5. **Reconstruct signing input** — build the canonical JSON from all fields except `signature`
6. **Verify signature** — Ed25519 verify the signing input bytes against the resolved public key

```rust
fn verify_action_envelope(
    envelope: &ActionEnvelope,
    public_key: &[u8; 32],
) -> Result<(), VerifyError> {
    // 1. Check version
    if envelope.version != "1.0" {
        return Err(VerifyError::UnsupportedVersion);
    }

    // 2. Reconstruct signing input (all fields except signature)
    let signing_input = json_canon::to_string(&json!({
        "version": envelope.version,
        "type": envelope.r#type,
        "identity": envelope.identity,
        "payload": envelope.payload,
        "timestamp": envelope.timestamp,
    }))?;

    // 3. Verify Ed25519 signature
    let key = UnparsedPublicKey::new(&ED25519, public_key);
    key.verify(signing_input.as_bytes(), &envelope.signature_bytes())?;

    Ok(())
}
```

Timestamp validation and identity resolution are the caller's responsibility — they depend on application context (acceptable skew, DID resolution method, key state source).

## Relationship to Attestations

Action envelopes and attestations serve different purposes:

| | Attestation | Action Envelope |
|---|---|---|
| **Purpose** | Bind identity to device (long-lived credential) | Sign a single action (ephemeral) |
| **Signatures** | Dual-signed (identity + device) | Single-signed (identity) |
| **Structure** | Fixed fields (`issuer`, `subject`, `device_public_key`, etc.) | Flexible `payload` |
| **Verification** | `verify_attestation()` / `verify_chain()` | `verify_action_envelope()` (separate function) |
| **Storage** | Git refs (`refs/auths/devices/...`) | Application-defined (not stored in identity repo) |

Action envelopes use the same cryptographic primitives (Ed25519, `json-canon`) but are structurally incompatible with attestations. A dedicated `verify_action_envelope()` function is required — `verify_attestation()` expects `Attestation` struct fields and will reject action envelopes.

## DSSE Consideration

[DSSE (Dead Simple Signing Envelope)](https://github.com/secure-systems-lab/dsse) is an alternative envelope format used by in-toto and SLSA. We chose a custom format because:

- **Consistency**: Auths already uses `json-canon` canonicalization across 10+ modules (attestations, KERI events, chat signatures). DSSE uses PAE (Pre-Authentication Encoding) with a different byte layout.
- **Simplicity**: The envelope is plain JSON end-to-end. DSSE base64-encodes the payload, adding encode/decode steps.
- **Ed25519-only**: Auths does not need algorithm negotiation. Omitting an `alg` field avoids the class of vulnerabilities where an attacker specifies `"alg": "none"` (a known JWS/JWT attack vector).

If future interoperability with SLSA or in-toto supply chain tools is needed, a DSSE wrapper can be added as a translation layer without changing the core signing format.

## Versioning Strategy

- The current version is `"1.0"`
- The `version` field is a string to allow semver-style minor versions (e.g. `"1.1"`)
- **Minor version bump** (e.g. `1.0` → `1.1`): New optional fields added. Old verifiers ignore unknown fields. Old envelopes remain valid.
- **Major version bump** (e.g. `1.0` → `2.0`): Structural changes. Verifiers must explicitly support the new version. Old envelopes remain verifiable under `"1.0"` rules.
- Verifiers should reject envelopes with unrecognized major versions
- The `version` is included in the signing input, so version downgrade attacks are not possible

## Example: AI Agent Tool Call

```json
{
  "version": "1.0",
  "type": "tool_call",
  "identity": "did:keri:EBf7Y2pAnRd2cf6rbP7hbUkJvWMz3RRJPpL...",
  "payload": {
    "tool": "execute_sql",
    "args": {
      "query": "SELECT * FROM users WHERE active = true",
      "database": "production"
    },
    "nonce": "x8f2k9"
  },
  "timestamp": "2025-06-01T12:34:56Z",
  "signature": "a1b2c3d4e5f6789..."
}
```

The server verifies the envelope, resolves the identity's current key, checks the signature, and confirms the identity is authorized for the `execute_sql` tool on the `production` database.
