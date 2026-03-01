# Revocation Design

How Auths handles attestation revocation: threat model, data model, verification, and future directions.

## Current Model

### Signed `revoked_at` Field

Revocation status is embedded directly in the attestation's signed canonical body as:

```
revoked_at: Option<DateTime<Utc>>   // ISO 8601, or null
```

Because `revoked_at` is included in the canonical JSON that both the identity key and device key sign over, any post-hoc tampering (stripping, injecting, or changing the timestamp) invalidates both signatures. This is the core tamper-resistance guarantee.

### Revocation Flow

1. The identity holder calls `create_signed_revocation()` (`auths-id/src/attestation/revoke.rs`).
2. A `CanonicalRevocationData` struct is built containing the `revoked_at` timestamp and signed by the identity key only (the device does not counter-sign revocations).
3. The resulting `Attestation` object has `revoked_at: Some(timestamp)` and an empty `device_signature`.
4. The revocation attestation is stored as a Git commit in the `refs/auths/` ref hierarchy, preserving full history.

### Verification

Verification (`auths-verifier/src/verify.rs`) checks revocation at two levels:

- **`verify_with_keys_at()`** (time-aware): If `revoked_at <= reference_time`, the attestation is rejected with `"Attestation revoked"`. This supports both current-time and historical-time verification.
- **`verify_single_attestation()`** (chain walk): Calls `att.is_revoked()` (which checks `revoked_at.is_some()`) before verifying signatures. A revoked intermediate link halts the chain with `VerificationStatus::Revoked`.

### Git Storage

Revocation attestations are stored alongside normal attestations in:

```
refs/auths/devices/nodes/<sanitized-device-did>/signatures
```

The commit history of this ref records the full attestation lifecycle: creation, any updates, and revocation. Git's immutable commit DAG provides an audit trail.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Tamper-proof revocation | `revoked_at` is inside the signed envelope; any modification breaks Ed25519 signatures |
| Non-repudiation | The identity key signs the revocation; only the key holder can revoke |
| Audit trail | Git commit history records when revocation was stored |
| Time-aware verification | `verify_at_time()` evaluates revocation relative to a caller-supplied timestamp |

## Enterprise Considerations

For deployments that need real-time revocation checking without cloning Git repos:

### Registry-Based Revocation Endpoint

A future extension could expose an HTTP endpoint that serves revocation status:

```
GET /v1/revocations/{did}/{rid}
-> { "revoked": true, "revoked_at": "2026-01-15T00:00:00Z" }
```

This would be backed by the same Git storage but indexed for O(1) lookup (similar to `auths-index`). The signed attestation itself remains the source of truth; the endpoint is a read-through cache.

### CRL/OCSP Analogy

The current model is analogous to "stapled" revocation (like OCSP stapling in TLS): the revocation proof travels with the attestation. A registry endpoint would add a "pull" model for clients that cannot access the Git repository directly.

## Limitations

- **Offline revocation propagation**: Revocation only takes effect when the consuming party fetches the updated attestation from Git. There is no push notification mechanism.
- **Single-signer revocation**: Only the identity key can revoke. There is no multi-party revocation ceremony (though this could be built on top of the `ThresholdPolicy` infrastructure).
- **No un-revocation**: Once `revoked_at` is set and signed, a new attestation must be issued rather than "un-revoking" the old one.
