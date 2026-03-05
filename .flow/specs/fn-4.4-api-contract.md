# Cross-Repo API Contract: Identity Endpoints

This document defines the JSON schemas and endpoint contracts that any HTTP node
(e.g. radicle-httpd) must implement to support client-side identity verification
via the `@auths/verifier` WASM module.

These schemas are derived from the Rust types in `auths-verifier`. Any consuming
API must produce JSON that `parse_kel_json()` and `serde_json::from_str::<Attestation>()`
accept without modification.

---

## 1. GET /v1/identity/:did/kel

Retrieve the Key Event Log for a KERI identity.

### Request
- `:did` — A KERI identity DID (e.g. `did:keri:EXq5...`)

### Response (200 OK)
Content-Type: `application/json`

JSON array of KEL events, ordered chronologically (inception first). The array
must be directly parseable by `parse_kel_json()` (see `auths-verifier/src/keri.rs:720`).

```json
[
  {
    "icp": {
      "v": "KERI10JSON",
      "d": "EAbcdef...",
      "i": "EAbcdef...",
      "s": "0",
      "kt": "1",
      "k": ["DBase64urlEncodedPublicKey..."],
      "nt": "1",
      "n": ["ENextKeyCommitmentHash..."],
      "bt": "0",
      "b": [],
      "a": [],
      "x": "Base64urlEncodedEd25519Signature..."
    }
  },
  {
    "ixn": {
      "v": "KERI10JSON",
      "d": "EIxnSaid...",
      "i": "EAbcdef...",
      "s": "1",
      "p": "EAbcdef...",
      "a": [
        { "d": "ESealDigest...", "type": "device-attestation" }
      ],
      "x": "Base64urlSignature..."
    }
  },
  {
    "rot": {
      "v": "KERI10JSON",
      "d": "ERotSaid...",
      "i": "EAbcdef...",
      "s": "2",
      "p": "EIxnSaid...",
      "kt": "1",
      "k": ["DNewPublicKey..."],
      "nt": "1",
      "n": ["ENewNextCommitment..."],
      "bt": "0",
      "b": [],
      "a": [],
      "x": "Base64urlSignature..."
    }
  }
]
```

### Event Type Envelope

Events are tagged using serde's externally-tagged enum representation:
- `{"icp": {...}}` — Inception event
- `{"rot": {...}}` — Rotation event
- `{"ixn": {...}}` — Interaction event

### Field Reference

Source: `auths-verifier/src/keri.rs` — `IcpEvent`, `RotEvent`, `IxnEvent`

| Field | Type     | Description |
|-------|----------|-------------|
| `v`   | string   | KERI version string (e.g. `"KERI10JSON"`) |
| `d`   | string   | Self-Addressing Identifier (SAID) — Blake3 hash, E-prefixed base64url |
| `i`   | string   | KERI prefix (same as `d` for inception) |
| `s`   | string   | Sequence number as string (e.g. `"0"`, `"1"`) |
| `p`   | string   | Previous event SAID (rot/ixn only) |
| `kt`  | string   | Signing key threshold |
| `k`   | string[] | Current signing keys — D-prefixed base64url Ed25519 |
| `nt`  | string   | Next-key commitment threshold |
| `n`   | string[] | Next-key commitments — E-prefixed Blake3 hashes |
| `bt`  | string   | Witness threshold |
| `b`   | string[] | Witness identifiers |
| `a`   | Seal[]   | Anchored seals (see below) |
| `x`   | string   | Ed25519 signature over canonical event — base64url (no padding) |

### Seal Object

```json
{ "d": "ESealDigest...", "type": "device-attestation" }
```

| Field  | Type   | Description |
|--------|--------|-------------|
| `d`    | string | SAID of the anchored data (Blake3, E-prefixed base64url) |
| `type` | string | Semantic label (e.g. `"device-attestation"`) |

### Git Ref Path

The KEL is stored as a commit chain at: **`refs/keri/kel`**

(Defined in `auths-radicle/src/refs.rs:45` as `KERI_KEL_REF`)

### Error Responses

| Status | Meaning |
|--------|---------|
| 404    | Identity not found (no KEL for this prefix) |
| 400    | Invalid DID format |

---

## 2. GET /v1/identity/:did/attestations

Retrieve attestations linking a device to its controlling identity.

### Request
- `:did` — A device DID (e.g. `did:key:z6Mk...`) or identity DID (`did:keri:E...`)

### Response (200 OK)
Content-Type: `application/json`

JSON array of attestations. Each object must be directly deserializable as
`auths-verifier::core::Attestation` (see `auths-verifier/src/core.rs:332`).

```json
[
  {
    "version": 1,
    "rid": "refs/keys/z6MkDevice.../signatures/did-keri",
    "issuer": "did:keri:EAbcdef...",
    "subject": "did:key:z6MkDevice...",
    "device_public_key": "aabbccdd...64hex",
    "identity_signature": "eeff0011...128hex",
    "device_signature": "22334455...128hex",
    "expires_at": "2026-06-01T00:00:00Z",
    "timestamp": "2026-01-15T10:30:00Z",
    "capabilities": ["sign_commit", "sign_release"]
  }
]
```

### Field Reference

Source: `auths-verifier/src/core.rs:332-380`

| Field                | Type       | Encoding | Description |
|----------------------|------------|----------|-------------|
| `version`            | number     | —        | Schema version (currently `1`) |
| `rid`                | string     | —        | Record identifier (Git ref path) |
| `issuer`             | string     | —        | Identity DID (`did:keri:E...`) |
| `subject`            | string     | —        | Device DID (`did:key:z6Mk...`) |
| `device_public_key`  | string     | hex      | Raw Ed25519 public key, 64 hex chars |
| `identity_signature` | string     | hex      | Ed25519 signature, 128 hex chars (may be empty) |
| `device_signature`   | string     | hex      | Ed25519 signature, 128 hex chars |
| `revoked_at`         | string?    | RFC 3339 | Revocation timestamp (omit if not revoked) |
| `expires_at`         | string?    | RFC 3339 | Expiration timestamp (omit if no expiry) |
| `timestamp`          | string?    | RFC 3339 | Creation timestamp |
| `note`               | string?    | —        | Optional human-readable note |
| `payload`            | object?    | —        | Optional arbitrary JSON |
| `role`               | string?    | —        | Role for org membership (e.g. `"admin"`) |
| `capabilities`       | string[]   | —        | Capability strings (e.g. `"sign_commit"`) |
| `delegated_by`       | string?    | —        | DID of delegating attestation |
| `signer_type`        | string?    | —        | Entity type (`"human"`, `"agent"`, `"workload"`) |

**Critical encoding note**: `device_public_key`, `identity_signature`, and
`device_signature` use **hex encoding** (`serde(with = "hex::serde")`), NOT
base64. Any mismatch will cause silent verification failure.

### Git Ref Paths

Attestation blobs are stored under:
- `refs/keys/<device-nid>/signatures/did-key` — device signature blob
- `refs/keys/<device-nid>/signatures/did-keri` — identity signature blob

(Defined in `auths-radicle/src/refs.rs:58-99`)

### Error Responses

| Status | Meaning |
|--------|---------|
| 404    | No attestations found for this DID |
| 400    | Invalid DID format |

---

## 3. GET /v1/users/:did (Extended)

Retrieve user profile with identity controller information.

### Request
- `:did` — Any DID: `did:key:z6Mk...` or `did:keri:E...`

### Response (200 OK)
Content-Type: `application/json`

```json
{
  "did": "did:key:z6MkDevice...",
  "controller_did": "did:keri:EAbcdef...",
  "is_keri": false,
  "devices": [
    {
      "did": "did:key:z6MkDevice...",
      "status": "active"
    },
    {
      "did": "did:key:z6MkOther...",
      "status": "revoked"
    }
  ]
}
```

### Field Reference

| Field            | Type         | Description |
|------------------|--------------|-------------|
| `did`            | string       | The requested DID |
| `controller_did` | string\|null | The controlling `did:keri` identity, null if none |
| `is_keri`        | boolean      | Whether the requested DID is a KERI identity |
| `devices`        | DeviceInfo[] | List of linked devices (empty if no KERI link) |

### DeviceInfo

| Field    | Type   | Description |
|----------|--------|-------------|
| `did`    | string | Device DID (`did:key:z6Mk...`) |
| `status` | string | `"active"` or `"revoked"` |

### Lookup Behavior

- If `:did` is a `did:key`: look up its controlling `did:keri` via attestation refs.
  Use `find_identity_for_device()` from the bridge trait.
- If `:did` is a `did:keri`: return it directly with its device list.
- If no KERI link exists: return `controller_did: null`, `devices: []`.

### Error Responses

| Status | Meaning |
|--------|---------|
| 404    | DID not found on this node |
| 400    | Invalid DID format |

---

## Open Questions for Implementing Nodes

1. **Scope of `find_identity_for_device`**: Is it global (across all repos on the node) or per-project (scoped to a `repo_id`)? The plan's endpoint has no repo_id param, suggesting global.

2. **Revocation propagation**: How does a revocation from `auths device revoke` (which updates local refs) reach the serving node? Push? Gossip? Manual sync?

3. **Profile metadata**: Neither KERI events nor attestations carry name/bio/avatar. Where does this data live? Possible options:
   - In the `payload` field of the attestation
   - In a separate `refs/keri/profile` ref
   - In the existing `RadicleIdentityDocument` payload

4. **Caching/staleness**: Should the API include cache headers (`ETag`, `Last-Modified`) for KEL endpoints? The KEL is append-only, so conditional requests could use the latest SAID.

5. **Pagination**: For identities with many attestations, should the `/attestations` endpoint support pagination?
