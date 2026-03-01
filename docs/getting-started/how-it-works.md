# How It Works

Auths is a decentralized identity system for developers. It enables cryptographic commit signing with Git-native storage using KERI-inspired identity principles. No central server or blockchain -- just Git and cryptography.

This page explains the core ideas in about five minutes.

## Identity = keypair + event log

In Auths, your identity is not a username, not an email address, and not a single key. It is a **keypair combined with a cryptographic event log** that records every key lifecycle operation.

When you create an identity, two things happen:

1. An **Ed25519 keypair** is generated for signing
2. An **inception event** is written to a Key Event Log (KEL)

The inception event is the genesis of your identity. Its content is hashed with Blake3 to produce a Self-Addressing Identifier (SAID), which becomes your permanent identity prefix. Your full identity is expressed as a DID:

```
did:keri:EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148
         └──────────────────────────────────────────┘
         Blake3 hash of the inception event (Base64url)
```

Because the identifier is derived from the event content itself (self-addressing), it is cryptographically bound to the keys and commitments declared at inception. No registry or authority assigns it.

## Two kinds of DID

Auths uses two DID methods for different purposes:

| DID method | Format | Purpose |
|------------|--------|---------|
| `did:keri` | `did:keri:E...` | Your permanent identity. Derived from the KERI inception event's SAID. Survives key rotation. |
| `did:key` | `did:key:z6Mk...` | A device identifier. Derived from an Ed25519 public key using multicodec encoding. Tied to a single keypair. |

Your identity (`did:keri`) is stable. Your devices (`did:key`) come and go. Attestations bind the two together.

## Git as storage

All identity data is stored as Git refs in a bare repository at `~/.auths`. There is no database, no cloud service, no blockchain.

| Data | Git ref pattern | Format |
|------|-----------------|--------|
| Identity document | `refs/auths/identity` | JSON blob |
| Key Event Log (KEL) | `refs/did/keri/<prefix>/kel` | JSON events |
| Device attestations | `refs/auths/devices/nodes/<device-did>/signatures` | JSON blob |
| Witness receipts | `refs/did/keri/<prefix>/receipts/<event-said>` | JSON blob |

Git provides the properties that matter:

- **Content-addressable**: Every object is identified by its hash
- **Append-only history**: Commits cannot be silently altered
- **Replication**: Push and pull to share identity data
- **Offline-first**: No network required for local operations

## KERI inspiration

Auths implements a subset of [KERI](https://keri.one) (Key Event Receipt Infrastructure). The key ideas borrowed from KERI are:

**Self-addressing identifiers.** The identity prefix is the Blake3 hash of its own inception event. The identifier is the content, and the content is the identifier. This removes any need for an external registry.

**Pre-rotation.** At inception, a commitment to the *next* rotation key is embedded in the event. Only the holder of that pre-committed key can perform a valid rotation. Even if the current signing key is compromised, an attacker cannot rotate to their own key.

**Key Event Log.** All key lifecycle operations -- inception, rotation, interaction -- are recorded as a hash-chained sequence of events. Each event references the previous event's SAID, forming a tamper-evident log.

**Event types.** Auths implements three KERI event types:

| Event | Tag | Purpose |
|-------|-----|---------|
| Inception | `icp` | Creates the identity, declares initial key and next-key commitment |
| Rotation | `rot` | Rotates to the pre-committed key, declares a new next-key commitment |
| Interaction | `ixn` | Anchors external data (like attestations) in the KEL without changing keys |

## What an inception event looks like

Here is the structure of an actual inception event, taken from the `IcpEvent` type in the source code:

```json
{
  "v": "KERI10JSON",
  "t": "icp",
  "d": "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148",
  "i": "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148",
  "s": "0",
  "kt": "1",
  "k": ["D<base64url-encoded-ed25519-public-key>"],
  "nt": "1",
  "n": ["E<blake3-hash-of-next-public-key>"],
  "bt": "0",
  "b": [],
  "x": "<base64url-encoded-ed25519-signature>"
}
```

Key fields:

- `d` and `i` are identical at inception -- both are the SAID (the prefix)
- `k` contains the current signing key, prefixed with `D` (Ed25519 derivation code)
- `n` contains the next-key commitment, prefixed with `E` (Blake3 derivation code)
- `x` is the Ed25519 signature over the canonical event JSON
- `s` is the sequence number (`"0"` for inception)

## Attestations bind identities to devices

An attestation is a signed JSON document that says: *"Identity X authorizes Device Y."* Both the identity key and the device key sign the attestation, creating a dual-signed binding.

```json
{
  "version": 1,
  "rid": "attestation-record-id",
  "issuer": "did:keri:E...",
  "subject": "did:key:z6Mk...",
  "device_public_key": "<hex-encoded-32-byte-ed25519-key>",
  "identity_signature": "<hex-encoded-signature>",
  "device_signature": "<hex-encoded-signature>",
  "capabilities": ["sign_commit", "sign_release"],
  "expires_at": "2027-01-01T00:00:00Z",
  "timestamp": "2026-03-01T00:00:00Z"
}
```

The attestation data is canonicalized using [JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) (via `json-canon`) before signing, ensuring deterministic signature verification regardless of field ordering.

## Verification is local

To verify that a commit was signed by an authorized device, you need:

1. The attestation JSON (containing both signatures)
2. The issuer's public key

No network call. No server. No blockchain lookup. Verification is a pure function: data in, result out. This is why the `auths-verifier` crate has no dependency on `git2`, no network I/O, and no platform-specific code -- it is designed to run anywhere, including in web browsers via WASM.

## The payoff

This architecture gives you:

- A **single, stable identity** (`did:keri:E...`) that works across every device you own
- **Key rotation** that does not break historical signatures
- **Offline verification** with nothing but Git refs and public keys
- **No accounts, no servers, no vendor lock-in** -- just cryptography and Git
