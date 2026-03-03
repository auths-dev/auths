# RIP-X: Multi-Device Identity for Radicle

## Status

Draft

## Abstract

This proposal introduces `did:keri` as a delegate type in Radicle identity documents, enabling a single user to operate across multiple devices (laptop, desktop, CI server) under one cryptographic identity. Device keys are linked to a KERI controller identity via 2-way attestations stored as Git refs. Existing `did:key`-only projects continue to work unchanged.

## Motivation

Radicle currently identifies users by a single Ed25519 keypair (`did:key:z6Mk...`). This creates friction:

- **Device loss**: Losing the private key means losing the identity permanently.
- **Multi-machine workflows**: Developers working on laptop + desktop must maintain separate identities or copy keys manually.
- **CI/CD**: Automated signing requires distributing the user's private key to CI environments.
- **Key rotation**: No mechanism to rotate a compromised key without changing the identity.

KERI (Key Event Receipt Infrastructure) solves this by separating the *identity* from the *keys*. A KERI identity is an append-only log of key events (inception, rotation, interaction) that establishes which keys are currently authorized. Multiple device keys can be attested as authorized signers under one KERI identity.

## Specification

### Delegate Types

Identity documents gain a new delegate type:

```json
{
  "delegates": [
    "did:key:z6Mk...",
    "did:keri:EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"
  ],
  "threshold": 2
}
```

- `did:key:z6Mk...` — Legacy single-key delegate. Radicle verifies Ed25519 signatures directly.
- `did:keri:E...` — KERI identity delegate. The bridge resolves which `did:key` devices are currently authorized by replaying the Key Event Log.

### Identity Repository Layout

Each KERI identity is stored in a dedicated Radicle repository (RID). The layout:

```
<identity-rid>
└─ refs
   ├─ keri
   │  └─ kel                              # KEL commit chain (tip = latest event)
   └─ keys
      └─ <nid>                            # Node ID (z6Mk...)
         └─ signatures
            ├─ did-key                     # Device's Ed25519 signature blob
            └─ did-keri                    # Identity's Ed25519 signature blob
```

Ref path constants (from `auths-radicle/src/refs.rs`):

| Constant | Value |
|---|---|
| `KERI_KEL_REF` | `refs/keri/kel` |
| `KEYS_PREFIX` | `refs/keys` |
| `SIGNATURES_DIR` | `signatures` |
| `DID_KEY_BLOB` | `did-key` |
| `DID_KERI_BLOB` | `did-keri` |

### Project Namespace Layout

Projects reference KERI identities via namespace refs:

```
<project-rid>
└─ refs
   └─ namespaces
      └─ did-keri-<prefix>
         └─ refs
            └─ rad
               └─ id                      # Blob containing identity repo RID
```

The `did:keri:EXq5...` DID is converted to a ref-safe component by replacing `:` with `-` (e.g., `did-keri-EXq5...`).

### Key Event Log (KEL)

The KEL is a linear chain of Git commits at `refs/keri/kel`. Each commit contains a single blob `event.json` with a KERI event:

**Inception Event** (sequence 0):
```json
{
  "t": "icp",
  "v": "KERI10JSON",
  "d": "<SAID>",
  "i": "<prefix>",
  "s": "0",
  "kt": "1",
  "k": ["D<base64url-pubkey>"],
  "nt": "1",
  "n": ["E<blake3-next-commitment>"],
  "bt": "0",
  "b": [],
  "a": [],
  "x": "<base64url-signature>"
}
```

**Rotation Event** (sequence > 0):
```json
{
  "t": "rot",
  "v": "KERI10JSON",
  "d": "<SAID>",
  "i": "<prefix>",
  "s": "<sequence>",
  "p": "<previous-SAID>",
  "kt": "1",
  "k": ["D<new-base64url-pubkey>"],
  "nt": "1",
  "n": ["E<new-commitment>"],
  "bt": "0",
  "b": [],
  "a": [],
  "x": "<base64url-signature>"
}
```

Key encoding: Ed25519 public keys use the CESR `D` prefix followed by base64url-no-pad encoding of the 32-byte key. Next-key commitments use Blake3 hashes.

Validation rules (enforced by `validate_kel()`):
1. First event MUST be inception (`t: "icp"`)
2. Each event's SAID (`d`) is verified against the canonical JSON
3. Each event is signed by the appropriate key (inception: declared key; rotation: new key)
4. Rotation keys must satisfy the previous event's next-key commitment
5. Sequence numbers are monotonically increasing (0, 1, 2, ...)
6. Chain linkage: each event's `p` field matches the previous event's `d`
7. No merge commits in the KEL chain (linear history only)

### Attestation Format

Device attestations use a 2-blob format stored under `refs/keys/<nid>/signatures/`:

**Canonical payload** (JCS RFC 8785):
```json
{"did":"did:keri:E...","rid":"<repo-id>"}
```

The payload is serialized using JSON Canonicalization Scheme (RFC 8785) to produce deterministic byte sequences for signing.

**`did-key` blob**: 64-byte Ed25519 signature where the *device* key signs the canonical payload.

**`did-keri` blob**: 64-byte Ed25519 signature where the *identity* (controller) key signs the canonical payload.

Both signatures must verify for the attestation to be valid. This 2-way binding proves:
1. The identity controller authorized this device (identity signature)
2. The device consented to be bound (device signature)

### Threshold Counting (Person Rule)

When counting verified delegates against a threshold:

> Multiple signatures made by the set of keys of a Person SHALL be counted as only one vote.

Implementation:
1. Verify each signer through the bridge pipeline
2. Group results by **identity DID** (not device DID):
   - `did:keri:` signers → grouped by their controller identity DID
   - `did:key:` signers (legacy) → each device is its own identity
3. Count unique identity DIDs with at least one `Verified` result
4. Compare count against threshold

Example with threshold 2:

| Signer | Identity | Verified | Votes |
|---|---|---|---|
| `did:key:zAlice` (legacy) | `did:key:zAlice` | Yes | 1 |
| `did:keri:EBob/device1` | `did:keri:EBob` | Yes | 1 (shared) |
| `did:keri:EBob/device2` | `did:keri:EBob` | Yes | 0 (deduped) |
| **Total** | | | **2** (meets threshold) |

## Verification Pipeline

When Radicle fetches a repository and encounters a `did:keri` delegate, the bridge executes:

1. **DID Translation**: Ed25519 signer key → `did:key:z6Mk...`
2. **Identity Lookup**: `find_identity_for_device(device_did, repo_id)` — checks if attestation refs exist under `refs/keys/<nid>/signatures/`
3. **Key State Load**: Replay KEL at `refs/keri/kel` to derive current `KeyState`
4. **Binding Integrity**: If `min_kel_seq` is set, reject if KEL sequence is below the binding minimum (hard reject, never downgraded)
5. **Staleness Detection**: Compare local KEL tip against gossip-known remote tip. Stale state → Quarantine (Enforce mode) or Warn (Observe mode)
6. **Attestation Load**: Read 2-blob signatures from `refs/keys/<nid>/signatures/{did-key, did-keri}`
7. **Policy Evaluation**: Check revocation status and expiry via compiled policy rules
8. **Capability Check**: If the request requires a specific capability, verify the attestation grants it

The pipeline is fail-closed: any unhandled error produces `Rejected`, never `Verified`.

### Enforcement Modes

- **Enforce**: Full verification required. Missing identity → Quarantine. Stale state → Quarantine. Revoked → Rejected.
- **Observe**: Same verification, but `Rejected` and `Quarantine` are downgraded to `Warn`. Exception: `min_kel_seq` violations are always hard rejections (tamper indicator).

## Lifecycle Operations

### Identity Creation

1. Generate Ed25519 keypair (current) and pre-rotation keypair (next)
2. Create inception event with:
   - Current key in CESR format (`D` + base64url)
   - Blake3 commitment to next public key
3. Sign and store as first commit at `refs/keri/kel`
4. The inception SAID becomes the KERI prefix (used in `did:keri:<prefix>`)

### Device Linking

1. New device generates its own `did:key`
2. Controller signs canonical payload `{"did":"did:keri:E...","rid":"<rid>"}` with identity key
3. Device signs same payload with device key
4. Both signatures stored as blobs under `refs/keys/<nid>/signatures/`

### Key Rotation

1. Load current KEL and validate
2. Create rotation event with the pre-committed next key
3. Generate new pre-rotation commitment
4. Sign rotation event with new key (satisfies commitment)
5. Append to KEL commit chain
6. All existing attestations remain valid (bound to identity, not key)

### Revocation

Mark a device attestation as revoked in the attestation record. Subsequent fetches by peers will reject signatures from that NID. KEL-level revocation (abandoning the identity) is achieved by setting an empty next-commitment.

## Migration

### Backward Compatibility

- Projects with only `did:key` delegates are unaffected
- Mixed delegate sets (`did:key` + `did:keri`) work correctly
- Nodes that don't understand `did:keri` will ignore those delegates and count only `did:key` delegates against the threshold
- No changes to the wire protocol or gossip format

### Upgrade Path

1. User creates KERI identity (`rad auth` or `auths init`)
2. User adds `did:keri:E...` as a delegate to their projects
3. Existing `did:key` delegate can remain for backward compatibility
4. Once all peers support `did:keri`, the legacy delegate can be removed

## Security Considerations

### Duplicity Detection

KERI's append-only log prevents equivocation: if two conflicting events exist at the same sequence number, the identity is compromised and should be treated as untrusted. The `validate_kel()` function enforces strict sequence ordering and chain linkage.

### Replay Prevention

Each KEL event includes a SAID (Self-Addressing Identifier) computed over its canonical form. Events are chained via the `p` (previous) field. Inserting, removing, or reordering events breaks the chain and is detected during validation.

### Staleness Handling

Gossip-informed tip comparison detects when a peer's local copy of an identity repo is behind the network. In Enforce mode, stale state triggers Quarantine (requiring the peer to fetch the latest identity repo before accepting the signature). This prevents accepting signatures from keys that have been rotated away.

### Shallow Clones

Nodes MUST fetch the complete KEL from inception. Shallow clones of the identity repo are insufficient because validation requires replaying all events from the beginning to verify the chain integrity.

### Pre-Rotation Security

KERI's pre-rotation mechanism ensures that even if the current signing key is compromised, the attacker cannot rotate to a key of their choosing — the next key must satisfy the Blake3 commitment made in the previous event. This provides post-compromise recovery.
