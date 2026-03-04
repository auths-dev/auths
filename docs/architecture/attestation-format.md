# Attestation Format

JSON structure, canonicalization, dual signatures, capabilities, and expiration.

## What is an Attestation

An attestation is a signed JSON document that binds a device to an identity. It says: "Identity X authorizes Device Y to act on its behalf." Both the identity key and the device key sign the attestation, creating a two-way cryptographic binding.

Attestations are the authorization layer of Auths. The identity model (KERI) establishes *who you are*. Attestations establish *what your devices can do*.

## JSON Structure

The `Attestation` struct is defined in `auths-verifier/src/core.rs`:

```json
{
  "version": 1,
  "rid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "issuer": "did:keri:EBf7Y2pAnRd2cf6rbP7hbUkJvWMz3RRJPpL...",
  "subject": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "device_public_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  "identity_signature": "1122334455667788...",
  "device_signature": "9900aabbccddeeff...",
  "capabilities": ["sign_commit"],
  "expires_at": "2025-06-01T00:00:00Z",
  "revoked_at": null,
  "timestamp": "2025-01-15T12:00:00Z",
  "note": "Work Laptop",
  "role": "admin",
  "signer_type": "Human"
}
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | `u32` | Yes | Schema version (currently `1`) |
| `rid` | `string` | Yes | Unique record identifier (UUID v4) |
| `issuer` | `string` | Yes | Identity DID of the issuer (`did:keri:E...` or `did:key:z...`) |
| `subject` | `string` | Yes | Device DID being authorized (`did:key:z6Mk...`) |
| `device_public_key` | `hex string` | Yes | Raw Ed25519 public key of the device (32 bytes, hex-encoded) |
| `identity_signature` | `hex string` | Conditional | Ed25519 signature by the identity key over canonical payload (hex-encoded). Empty for device-only attestations. |
| `device_signature` | `hex string` | Yes | Ed25519 signature by the device key over canonical payload (hex-encoded) |
| `timestamp` | `ISO 8601 | null` | No | Creation timestamp |
| `expires_at` | `ISO 8601 | null` | No | Expiration timestamp |
| `revoked_at` | `ISO 8601 | null` | No | Revocation timestamp |
| `note` | `string | null` | No | Human-readable description |
| `payload` | `JSON | null` | No | Arbitrary JSON payload |
| `role` | `string | null` | No | Organization role (e.g., `"admin"`, `"member"`, `"readonly"`) |
| `capabilities` | `string[]` | No | Granted capabilities (defaults to empty) |
| `delegated_by` | `string | null` | No | DID of the attestation that delegated authority |
| `signer_type` | `enum | null` | No | Entity type: `"Human"`, `"Agent"`, or `"Workload"` |

Fields marked with `skip_serializing_if` are omitted from JSON when empty or null, ensuring backward compatibility.

### Signer Types: Human, Agent, Workload

The `signer_type` field distinguishes the entity class behind an attestation, enabling policy engines and verifiers to apply different authorization rules based on whether a human, an AI agent, or an automated workload performed an action.

| Type | When to use | Example |
|------|-------------|---------|
| `Human` | A person operating interactively — developer signing commits, admin issuing attestations | Developer on a laptop |
| `Agent` | An AI agent or autonomous software acting with delegated authority from a human or parent agent | Claude Code, a security scanning agent, an MCP-connected AI assistant |
| `Workload` | An automated process with a fixed, predictable scope — CI runners, build systems, cron jobs | GitHub Actions runner, Jenkins pipeline |

Policy engines can use `signer_type` to enforce rules such as: "only `Human` signers may approve production deployments" or "attestations from `Agent` signers require a `delegated_by` chain back to a `Human`."

**Example: Agent attestation with delegation**

```json
{
  "version": 1,
  "rid": "f8a1b2c3-d4e5-6789-abcd-ef0123456789",
  "issuer": "did:keri:EHumanOperator...",
  "subject": "did:key:z6MkAgentDevice...",
  "device_public_key": "aabb...",
  "identity_signature": "1122...",
  "device_signature": "9900...",
  "capabilities": ["sign:commit", "deploy:staging"],
  "expires_at": "2026-03-05T00:00:00Z",
  "signer_type": "Agent",
  "delegated_by": "did:keri:EHumanOperator..."
}
```

This attestation says: "Human operator `EHumanOperator` authorized agent device `z6MkAgentDevice` to sign commits and deploy to staging, valid for 24 hours." The `signer_type: Agent` tells downstream systems this action originated from an autonomous agent, and the `delegated_by` field provides the accountability chain back to the human.

## Canonical Payload

Signatures are computed over a **canonical JSON** representation of the attestation data, **excluding** `identity_signature` and `device_signature`. This is produced by the `CanonicalAttestationData` struct:

```rust
pub struct CanonicalAttestationData<'a> {
    pub version: u32,
    pub rid: &'a str,
    pub issuer: &'a IdentityDID,
    pub subject: &'a DeviceDID,
    pub device_public_key: &'a [u8],  // hex-encoded in JSON via serde
    pub payload: &'a Option<Value>,
    pub timestamp: &'a Option<DateTime<Utc>>,
    pub expires_at: &'a Option<DateTime<Utc>>,
    pub revoked_at: &'a Option<DateTime<Utc>>,
    pub note: &'a Option<String>,
    pub role: Option<&'a str>,
    pub capabilities: Option<&'a Vec<Capability>>,
    pub delegated_by: Option<&'a IdentityDID>,
    pub signer_type: Option<&'a SignerType>,
}
```

Canonical JSON is produced by the `json-canon` crate, which:

- Sorts object keys lexicographically
- Removes insignificant whitespace
- Uses minimal numeric representation
- Produces deterministic, reproducible output

This ensures the same attestation data always produces the same byte sequence for signing, regardless of field ordering in the original JSON.

## Dual Signatures

Each attestation carries two Ed25519 signatures:

1. **Identity signature** (`identity_signature`): Signed by the identity's current key (from the KERI KEL). This proves the identity authorized the device.

2. **Device signature** (`device_signature`): Signed by the device's own Ed25519 key. This proves the device consented to the binding.

Both signatures cover the same canonical payload. The signing process:

```
attestation_data (without signatures)
    |
    v
json_canon::to_string(CanonicalAttestationData)
    |
    v
canonical_bytes
    |
    +--> identity_key.sign(canonical_bytes) --> identity_signature
    |
    +--> device_key.sign(canonical_bytes)   --> device_signature
```

For **device-only attestations** (where no identity key is available), the `identity_signature` field is left empty. The attestation is still valid for verification purposes when only device-level trust is needed.

## Capabilities

Capabilities are the atomic unit of authorization. An attestation can grant one or more capabilities:

### Well-Known Capabilities

| Capability | Description |
|-----------|-------------|
| `sign_commit` | Permission to sign Git commits |
| `sign_release` | Permission to sign releases/tarballs |
| `manage_members` | Permission to add/remove organization members |
| `rotate_keys` | Permission to rotate keys for an identity |

### Custom Capabilities

Custom capabilities follow these rules:

- Non-empty, maximum 64 characters
- Only alphanumeric characters, colons (`:`), hyphens (`-`), and underscores (`_`)
- Cannot use the reserved `auths:` namespace prefix
- Automatically normalized to lowercase

```json
"capabilities": ["sign_commit", "acme:deploy", "org:team:action"]
```

The `Capability` type validates these constraints at parse time and serializes as a plain string in JSON.

## Expiration and Revocation

### Expiration

The `expires_at` field sets a hard deadline. After this timestamp, the attestation is no longer valid. Verifiers must check this field against the current time.

Expired attestations can be **extended** by creating a new attestation with an updated `expires_at` and fresh dual signatures.

### Revocation

The `revoked_at` field records when an attestation was revoked. Once set, the attestation is permanently invalid. Revocation is also anchored in the KEL via a revocation seal in an interaction event.

## Verified Attestation

The `VerifiedAttestation` newtype wrapper enforces at compile time that an attestation's signatures have been verified:

```rust
pub struct VerifiedAttestation(Attestation);
```

This type:

- Can only be constructed by verification functions or the `dangerous_from_unchecked` escape hatch
- Does **not** implement `Deserialize`, preventing bypass via deserialization
- Derefs to `&Attestation` for read access

## Storage Format

Attestations are stored as JSON blobs in Git commits:

```
refs/auths/devices/nodes/<sanitized-device-did>/signatures
  |
  v
  commit
    \-- tree
          \-- attestation.json (Attestation JSON blob)
```

The commit history of the ref records the attestation lifecycle: creation, extensions, and revocations each appear as new commits.

Attestation digests can be anchored in the KERI KEL via seals in interaction events:

```json
{ "d": "EAttestDigest...", "type": "device-attestation" }
```

This creates a verifiable link from the identity's event history to the attestation, providing an additional layer of integrity.

## Versioning

The `version` field allows schema evolution. Version `1` is the current schema. Future versions may add fields using `Option` types with `serde(default)` for backward compatibility.

## Size Limits

| Input | Maximum |
|-------|---------|
| Single attestation JSON | 64 KiB |
| JSON batch (chains, receipts, witness keys) | 1 MiB |
