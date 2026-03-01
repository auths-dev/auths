# Artifact API

## POST /v1/artifacts/publish

Publish a signed artifact attestation to the public registry.

### Request Body

```json
{
  "attestation": {
    "version": 1,
    "rid": "unique-attestation-rid",
    "issuer": "did:keri:E...",
    "subject": "did:key:z6Mk...",
    "device_public_key": "hex-encoded-ed25519-pubkey",
    "identity_signature": "hex-encoded-sig",
    "device_signature": "hex-encoded-sig",
    "payload": {
      "artifact_type": "file",
      "digest": {
        "algorithm": "sha256",
        "hex": "abc123..."
      },
      "name": "npm:react",
      "size": 12345
    }
  }
}
```

### Payload Schema (ArtifactMetadata)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `artifact_type` | string | yes | Type of artifact (e.g., "file", "container") |
| `digest.algorithm` | string | yes | Hash algorithm (e.g., "sha256") |
| `digest.hex` | string | yes | Hex-encoded hash of the artifact |
| `name` | string | no | Package name (e.g., "npm:react") |
| `size` | integer | no | Artifact size in bytes |

### Normalization

- `package_name` is lowercased before storage
- `digest.hex` is decoded to raw bytes for BYTEA storage
- The database enforces `CHECK (package_name = LOWER(package_name))`

### Responses

| Status | Description |
|--------|-------------|
| 201 | Attestation published successfully |
| 400 | Invalid request body |
| 409 | Duplicate attestation (same RID) |
| 422 | Missing/malformed payload or signature verification failed |

## GET /v1/artifacts

Query artifact attestations with mandatory pagination.

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `package` | string | one of package/signer/digest | Package name filter |
| `signer` | string | one of package/signer/digest | Signer DID filter |
| `digest` | string | one of package/signer/digest | Artifact digest hex filter |
| `cursor` | string | no | Opaque pagination cursor |
| `limit` | integer | no | Page size (default 50, max 200) |

At least one filter parameter is required.

### Pagination

Results are ordered by `published_at DESC` (most recent first), with `attestation_rid` as a tie-breaker.

The `cursor` value is opaque to clients (base64-encoded composite). Do not construct cursors manually — use the `next_cursor` value from the previous response.

When `next_cursor` is `null`, there are no more results.

### Response

```json
{
  "artifacts": [
    {
      "attestation_rid": "rid-123",
      "package_name": "npm:react",
      "digest_algo": "sha256",
      "digest_hex": "abc123...",
      "signer_did": "did:keri:E...",
      "device_did": "did:key:z6Mk...",
      "published_at": "2026-01-15T10:30:00Z"
    }
  ],
  "next_cursor": "base64-encoded-cursor-or-null"
}
```

### Namespace Squatting Caveat

Currently any authenticated DID can publish an attestation for any package name. Artifact attestations are **claims**, not authoritative mappings. Consumers should verify the signer DID matches the expected maintainer. Future versions will implement verification paths that cryptographically tie the publishing DID to the artifact's repository.
