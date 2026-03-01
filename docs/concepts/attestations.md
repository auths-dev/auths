# Attestations

An attestation is a signed JSON document that binds a device to an identity.

!!! note "You don't need to care about this unless..."
    You're building a verifier, debugging a failed verification, or designing a custom integration. For day-to-day commit signing, `auths device link` and `auths verify-commit` handle attestations for you. This page is for when you need to understand what's happening under the hood.

## Structure

```json
{
  "version": 1,
  "rid": "unique-request-id",
  "issuer": "did:keri:EBf...",
  "subject": "did:key:z6Mk...",
  "device_public_key": "aabbccdd...",
  "identity_signature": "1122334455...",
  "device_signature": "6677889900...",
  "capabilities": ["sign-commit"],
  "expires_at": "2025-06-01T00:00:00Z",
  "revoked": false,
  "note": "Laptop key"
}
```

### Key fields

| Field | Description |
|-------|-------------|
| `issuer` | The identity DID (`did:keri:E...`) that authorized this device |
| `subject` | The device DID (`did:key:z6Mk...`) being authorized |
| `device_public_key` | Raw Ed25519 public key of the device (hex) |
| `identity_signature` | Signature by the identity key over the canonical payload |
| `device_signature` | Signature by the device key over the same canonical payload |
| `capabilities` | What the device is allowed to do |
| `expires_at` | Optional expiration timestamp |
| `revoked` | Whether this attestation has been revoked |

## Dual signing

Both the identity and the device sign the attestation. This creates a two-way binding:

- The **identity signature** proves: "I authorize this device"
- The **device signature** proves: "I acknowledge this link"

The signed payload is a **canonical JSON** representation of the attestation data (excluding the signatures themselves), produced by `json-canon` for deterministic serialization.

## What's signed vs. what's not

**Signed** (included in the canonical payload):

- version, rid, issuer, subject
- device_public_key
- capabilities, expires_at
- note, revoked

**Not signed** (computed, not part of payload):

- identity_signature
- device_signature

## Storage

Attestations are stored as Git refs:

```
refs/auths/devices/nodes/<device-did>/signatures
```

Each attestation is a JSON blob committed to the device's ref. The commit history of the ref records the attestation lifecycle (link, extend, revoke).

## Verification

To verify an attestation, you need:

1. The attestation JSON
2. The issuer's public key (32 bytes, Ed25519)

The verifier:

1. Checks the `revoked` flag
2. Checks `expires_at` against current time
3. Reconstructs the canonical payload
4. Verifies `identity_signature` against the issuer's public key
5. Verifies `device_signature` against the `device_public_key` in the attestation

If all checks pass, the attestation is valid.

## Chain verification

For multi-level delegation (identity -> device -> sub-device), attestations form a chain. `verify_chain()` walks the chain from root to leaf, verifying each link and ensuring the `subject` of one attestation matches the `issuer` of the next.
