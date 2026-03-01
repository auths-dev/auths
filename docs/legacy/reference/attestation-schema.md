# Attestation Schema

JSON schema for Auths attestation objects.

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | `integer` | Yes | Schema version (currently `1`) |
| `rid` | `string` | Yes | Unique request identifier |
| `issuer` | `string` | Yes | Identity DID (`did:keri:E...`) |
| `subject` | `string` | Yes | Device DID (`did:key:z6Mk...`) |
| `device_public_key` | `string` | Yes | Device Ed25519 public key (hex, 64 chars) |
| `identity_signature` | `string` | Yes | Identity signature over canonical payload (hex) |
| `device_signature` | `string` | Yes | Device signature over canonical payload (hex) |
| `capabilities` | `string[]` | No | Granted capabilities |
| `expires_at` | `string` | No | ISO 8601 expiration timestamp |
| `revoked_at` | `string (ISO 8601) \| null` | No | Revocation timestamp, or `null` if not revoked |
| `note` | `string` | No | Human-readable description |

## Example

```json
{
  "version": 1,
  "rid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "issuer": "did:keri:EBf7Y2pAnRd2cf6rbP7hbUkJvWMz3RRJPpL...",
  "subject": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "device_public_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  "identity_signature": "1122334455667788...",
  "device_signature": "9900aabbccddeeff...",
  "capabilities": ["sign-commit"],
  "expires_at": "2025-06-01T00:00:00Z",
  "revoked_at": null,
  "note": "Work Laptop"
}
```

## Canonical payload

The signed payload is a canonical JSON representation of all fields **except** `identity_signature` and `device_signature`. Canonical JSON is produced by `json-canon`, which:

- Sorts object keys lexicographically
- Removes insignificant whitespace
- Uses minimal numeric representation
- Produces deterministic output

This ensures the same attestation data always produces the same byte sequence for signing.

## Versioning

The `version` field allows schema evolution. Consumers should check the version before processing. Version `1` is the current schema.

Future versions may add fields. Fields added as `Option` (nullable) are backward-compatible with existing parsers using `serde(default)`.

## Storage format

Attestations are stored as JSON blobs in Git commits:

```
refs/auths/devices/nodes/<sanitized-device-did>/signatures
  └─ commit
       └─ tree
            └─ attestation.json (blob)
```

The commit history of the ref records the attestation lifecycle.
