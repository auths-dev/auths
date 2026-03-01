# Trust Model

Auths enables cryptographic verification without a central authority. This page explains how trust is established, maintained, and verified -- and where the security boundaries are.

## Verification without a central authority

Traditional identity systems rely on a central authority (a CA, an identity provider, a blockchain) to vouch for the binding between an identity and a key. Auths takes a different approach: **the identity is the event log itself**.

Trust in Auths is rooted in three properties:

1. **Self-addressing identifiers**: The identity prefix is the Blake3 hash of the inception event. The identifier is cryptographically bound to its content. No authority assigns it.
2. **Pre-rotation commitments**: Each event commits to the next rotation key. Only the holder of the pre-committed key can perform a valid rotation.
3. **Hash-chained event log**: Each event references the previous event's SAID, forming a tamper-evident chain that can be independently verified.

A verifier does not need to contact a server or look up a registry. Given the Key Event Log and the relevant attestations, verification is a pure computation.

## Inception events: the root of trust

The inception event is the foundation of all trust in an Auths identity. It establishes:

- The **identity prefix** (`i` field) -- derived from the event's own SAID
- The **initial signing key** (`k` field) -- Ed25519 public key with `D` derivation code prefix
- The **next-key commitment** (`n` field) -- Blake3 hash of the next rotation key with `E` prefix
- The **witness configuration** (`bt`/`b` fields) -- threshold and list of witnesses

Because the prefix equals the SAID of the inception event, any modification to the inception event would change the prefix. This makes the inception event immutable by construction: altering it produces a different identity, not a corrupted one.

```
Inception event (icp, sequence 0):

  ┌─────────────────────────────────────────┐
  │  d: E<blake3-hash>  ← SAID             │
  │  i: E<blake3-hash>  ← same as d        │
  │  k: [D<pubkey>]     ← current key      │
  │  n: [E<hash>]       ← next-key commit  │
  │  x: <signature>     ← signed by k      │
  └─────────────────────────────────────────┘
       │
       └─── This hash IS the identity.
            Change anything, get a different identity.
```

## Key Event Logs: tamper-evident history

The Key Event Log (KEL) is a sequence of signed events stored at `refs/did/keri/<prefix>/kel`. Each event after inception includes a `p` field referencing the SAID of the previous event, creating a hash chain.

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ icp (seq 0)  │     │ rot (seq 1)  │     │ ixn (seq 2)  │
│ d: ESAID_0   │────>│ p: ESAID_0   │────>│ p: ESAID_1   │
│ k: [D<key1>] │     │ d: ESAID_1   │     │ d: ESAID_2   │
│ n: [E<hash>] │     │ k: [D<key2>] │     │ a: [{seal}]  │
│ x: <sig1>    │     │ n: [E<hash>] │     │ x: <sig3>    │
└──────────────┘     │ x: <sig2>    │     └──────────────┘
                     └──────────────┘
```

### Validation rules

KEL validation (`validate_kel`) enforces these invariants:

| Rule | Check | Error on violation |
|------|-------|--------------------|
| First event must be inception | `events[0]` is `icp` | `NotInception` |
| Sequence numbers are monotonic | `s` = 0, 1, 2, ... | `InvalidSequence` |
| SAID matches content | Blake3 hash of canonical JSON = `d` field | `InvalidSaid` |
| Chain is linked | `p` field = previous event's `d` field | `BrokenChain` |
| Pre-rotation commitment holds | New key matches previous `n` commitment | `CommitmentMismatch` |
| Signature is valid | Ed25519 signature over canonical event JSON | `SignatureFailed` |

Validation is a **pure function**: it takes a slice of events and returns a `KeyState` or an error. No filesystem, network, or platform access. This makes it suitable for property-based testing and embedding in any environment.

### KeyState: the resolved view

Replaying the KEL produces a `KeyState` -- the current cryptographic state of the identity:

```rust
KeyState {
    prefix: Prefix,          // The did:keri prefix
    current_keys: Vec<String>, // Active signing key(s)
    next_commitment: Vec<String>, // Next-key commitment(s)
    sequence: u64,            // Current sequence number
    last_event_said: Said,    // SAID of the last event
    is_abandoned: bool,       // True if next commitment is empty
}
```

The `KeyState` tells you which key is currently authorized to sign, whether the identity can still be rotated, and what the latest event in the log is.

## Pre-rotation: defense against key compromise

Pre-rotation is the most important security property in the trust model. At every point in the KEL, the identity has committed to which key will be used *next*. This commitment is a Blake3 hash of the next public key.

```
Timeline of compromise scenarios:

Without pre-rotation:
  Attacker steals key_A → rotates to attacker_key → identity hijacked

With pre-rotation:
  Attacker steals key_A → cannot rotate (doesn't have key_B)
  Legitimate owner uses key_B → rotates to key_B, commits to key_C
  Attacker's window is limited to the period before rotation
```

The commitment is verified during KEL validation: the new key's public bytes are hashed with Blake3 and compared to the previous event's `n` field. A mismatch produces `CommitmentMismatch` -- a hard validation error.

## Attestation verification

Attestations are verified independently of the KEL. The `auths-verifier` crate provides two levels:

### Single attestation (`verify_with_keys`)

Verifies one attestation against known public keys:

- Is the `identity_signature` valid over the canonical attestation data?
- Is the `device_signature` valid over the canonical attestation data?
- Is the attestation expired? (`expires_at` checked with 5-minute clock skew tolerance)
- Is the attestation revoked? (`revoked_at` field present)

### Chain verification (`verify_chain`)

Verifies a chain of attestations from root identity to leaf device:

- Does each link's `subject` match the next link's `issuer`?
- Are all individual signatures valid?
- Is the chain unbroken?

Both functions are pure: no network, no filesystem, no platform dependency. This is why `auths-verifier` can run in web browsers (WASM), CI pipelines, mobile apps (FFI), and edge functions.

## Seals: anchoring data in the KEL

Seals create a cryptographic link between the KEL and external data. An interaction event (`ixn`) can include seals in its `a` field:

```json
{
  "d": "<SAID-digest>",
  "type": "device-attestation"
}
```

The seal contains the SAID (Blake3 hash) of the anchored data and a type indicator. Seal types include:

| Seal type | Purpose |
|-----------|---------|
| `device-attestation` | Links a device attestation to the KEL |
| `revocation` | Links a revocation event to the KEL |
| `delegation` | Links a capability delegation to the KEL |

Anchoring attestations in the KEL makes them part of the tamper-evident history. A verifier can check that an attestation's digest matches a seal in the KEL, proving it was authorized by the identity at a specific point in time.

## How witnesses work

Witnesses provide **split-view attack detection**. A split-view attack occurs when a malicious node shows different versions of a KEL to different peers:

```
Without witnesses:
  Attacker shows KEL_A to Peer 1 (key1 is current)
  Attacker shows KEL_B to Peer 2 (key2 is current)
  Both peers think they have the correct view.

With witnesses:
  Peer 1 asks witness: "What is the head of identity E123?"
  Witness: "I see event ESAID_abc"
  Peer 1: "My local copy shows ESAID_def"
  → Split-view detected.
```

### Witness receipts

When a witness observes a KEL event, it issues a **receipt** -- a signed acknowledgment following the KERI `rct` (non-transferable receipt) format:

```json
{
  "v": "KERI10JSON000000_",
  "t": "rct",
  "d": "<receipt-SAID>",
  "i": "did:key:z6MkWitness...",
  "s": 5,
  "a": "<event-SAID-being-receipted>",
  "sig": "<Ed25519-signature-hex>"
}
```

Receipts are stored at `refs/did/keri/<prefix>/receipts/<event-said>` and can be verified by checking the witness's signature over the event SAID.

### Witness thresholds

Witnesses support threshold-based security. The inception (or rotation) event declares a witness threshold (`bt`) and witness list (`b`). For an event to be considered sufficiently witnessed, it must have receipts from at least `bt` witnesses.

### Limitations

Witnesses are **not Byzantine fault tolerant**:

- A single witness can be compromised or collude with an attacker
- Multiple witnesses (quorum) reduce risk but do not eliminate it
- Witnesses must be trusted to some degree

For full BFT guarantees, transparency logs or blockchain anchoring would be needed. Auths provides witness infrastructure as an optional layer for ecosystems where split-view attacks are a concern.

### Default: disabled

By default, witness checking is disabled (`NoOpWitness`). This is appropriate for:

- Private repositories
- Single-user setups
- Systems with existing consistency mechanisms (e.g., Radicle gossip protocol)

Enable witness checks for public ecosystems where split-view detection matters.

## What verification does NOT do

It is important to understand the boundaries of Auths verification:

| What it does | What it does not do |
|-------------|-------------------|
| Verifies cryptographic signatures | Resolve DIDs over a network |
| Checks attestation expiration and revocation | Contact a revocation server |
| Validates KEL chain integrity | Determine if the issuer *should* be trusted |
| Verifies pre-rotation commitments | Fetch attestations from Git |

The verifier answers: *"Are these signatures mathematically valid?"* The caller decides: *"Do I trust this root identity?"* Trust in the root is established out-of-band -- by pinning a known identity, by receiving it through a trusted channel, or by organizational policy.

## Trust boundaries summary

```
┌─────────────────────────────────────────────────────────┐
│                    Out-of-band trust                     │
│  "I trust did:keri:E... because my organization         │
│   published it, or I verified it in person."            │
├─────────────────────────────────────────────────────────┤
│                  KEL verification                        │
│  Inception → Rotation → Rotation → ...                  │
│  Each event: SAID, chain link, pre-rotation, signature  │
├─────────────────────────────────────────────────────────┤
│               Attestation verification                   │
│  Identity ──attestation──> Device                        │
│  Dual signatures, expiration, revocation check           │
├─────────────────────────────────────────────────────────┤
│              Witness layer (optional)                    │
│  Receipts from k-of-n witnesses                          │
│  Split-view detection, not BFT                           │
└─────────────────────────────────────────────────────────┘
```

Trust flows from the top down: you trust a root identity (out-of-band), the KEL proves the key history is intact, attestations prove devices are authorized, and witnesses provide additional assurance against equivocation.
