# ADR 0001: Threshold Signatures for High-Value Operations

## Status

Proposed

## Context

### Problem Statement

High-value operations in Auths require stronger security guarantees than single-key signatures provide:

- **Release signing**: A compromised developer key could sign malicious releases
- **Key rotation**: An attacker with one key could rotate out legitimate administrators
- **Member management**: Adding malicious admins undermines org security

These attack scenarios are prevented by requiring M-of-N approval (threshold signatures), where multiple authorized parties must cooperate to complete an operation.

### Requirements

1. Must work with existing Ed25519 key infrastructure
2. Should minimize round-trips for signing ceremonies
3. Must support asynchronous participation (signers in different timezones)
4. Key shares must remain secret (not stored in Git)
5. Policy metadata (M, N, authorized signers) must be auditable

## Decision

### Protocol: FROST (Flexible Round-Optimized Schnorr Threshold Signatures)

We will use **FROST** as specified in [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/) with the `frost-ed25519` crate from ZcashFoundation.

**Rationale:**

| Protocol | Rounds | Ed25519 | Crate Maturity | Notes |
|----------|--------|---------|----------------|-------|
| FROST | 2 | Native | High (ZcashFoundation) | Chosen |
| TSS-ECDSA | 6+ | No (secp256k1) | Medium | Key type mismatch |
| BLS Threshold | 1 | No (BLS12-381) | Medium | Different curve |
| Multi-sig | 1 | Yes | N/A | Not true threshold* |

*Multi-sig requires all participants to sign individually, revealing which N signed. FROST produces a single signature indistinguishable from a regular Ed25519 signature.

### Key Generation: PedPop Distributed Key Generation (DKG)

We will use **PedPop DKG** rather than trusted dealer key generation.

**Trusted Dealer:**
- One party generates the full key and distributes shares
- Single point of failure during generation
- Simpler to implement

**PedPop DKG (Chosen):**
- No single party ever sees the full private key
- Requires N-1 round-trips during key generation
- Better security properties for adversarial environments
- The `frost-ed25519` crate supports this natively

### Ceremony Coordination

Signing ceremonies require coordinating M participants:

1. **Coordinator** initiates ceremony with message hash and ceremony ID
2. Participants generate and share **commitments** (round 1)
3. Participants generate and share **signature shares** (round 2)
4. Coordinator aggregates shares into final signature

For async support, we will use a **WebSocket-based ceremony server**:

```
wss://auths.example/ceremony/{ceremony_id}
```

Participants can join, submit commitments/shares, and receive updates. The ceremony timeout (configurable, default 24h) allows participants in different timezones.

### CLI Interface

```bash
# Set up threshold policy for an org
auths org set-threshold \
  --org did:keri:abc123 \
  --m 2 \
  --n 3 \
  --signers did:key:alice,did:key:bob,did:key:carol \
  --scope sign-release

# Initiate a threshold signing ceremony
auths threshold sign \
  --policy-id release-signing-v1 \
  --message-file release.tar.gz

# Participate in a ceremony
auths threshold participate \
  --ceremony-id abc123 \
  --signer-alias my-share
```

### Storage

| Data | Location | Notes |
|------|----------|-------|
| ThresholdPolicy | `refs/auths/policies/threshold/<policy_id>` | Public, auditable |
| Key shares | Platform keychain / HSM | Secret, per-participant |
| Ceremony state | Ephemeral (ceremony server) | Deleted after completion |

## Consequences

### Positive

1. **Single signature output**: Verifiers don't need threshold-aware logic
2. **No key reconstruction**: Even during signing, full key never exists
3. **Flexible policies**: Different M-of-N for different operations
4. **Audit trail**: ThresholdPolicy in Git refs shows who approved what

### Negative

1. **Ceremony complexity**: Requires coordination server for async
2. **Share management**: Participants must secure their shares
3. **Recovery complexity**: Lost shares below threshold = key loss

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Ceremony timeout before M signers | Configurable timeout, retry capability |
| Share loss | Recommend N > M+1 for redundancy |
| Coordinator malice | Coordinator cannot forge signatures; can only delay |

## Future Work (Deferred)

The following are explicitly out of scope for this ADR and will be addressed in future epics:

1. **Ceremony server implementation**: WebSocket server for coordination
2. **Share backup/recovery**: Encrypted share backup mechanisms
3. **Hardware key support**: HSM integration for share storage
4. **Proactive share refresh**: Periodically rotating shares without changing public key
5. **Threshold key recovery**: Social recovery mechanisms

## References

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/)
- [frost-ed25519 crate](https://crates.io/crates/frost-ed25519)
- [ZcashFoundation/frost repository](https://github.com/ZcashFoundation/frost)
- [PedPop: Pedersen-based DKG](https://eprint.iacr.org/2020/540)
