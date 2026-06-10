# How It Works

Auths is a decentralized identity system for developers. It enables cryptographic
commit signing with Git-native storage. No central server or blockchain — just Git and
cryptography.

This page explains the core ideas in about five minutes.

## The plain-language version

Your identity is a **tamper-evident logbook of your keys**. The fingerprint of the
logbook's first page *is* your identity — nobody assigns it, and nobody can forge a
different logbook with the same fingerprint. Every key change (a new device, a
rotation, a revocation) is a new page, signed and chained to the page before it.

Anyone holding a copy of the logbook can check, with pure math and no server:

- which key is yours **right now**
- which keys were yours **at any point in the past**
- that nobody inserted, removed, or altered a page

Everything below is the mechanics of that logbook.

## Identity = keypair + event log

In Auths, your identity is not a username, not an email address, and not a single key.
It is a **keypair combined with a cryptographic event log** that records every key
lifecycle operation.

When you create an identity, two things happen:

1. A **P-256 keypair** is generated for signing (the default — chosen because phone
   secure hardware like the iPhone's Secure Enclave is P-256-only; Ed25519 is also
   supported)
2. An **inception event** is written to a Key Event Log (KEL) — the logbook's first page

The inception event is the genesis of your identity. Its content is hashed to produce a
Self-Addressing Identifier (SAID), which becomes your permanent identity prefix. Your
full identity is expressed as a DID:

```
did:keri:EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148
         └──────────────────────────────────────────┘
         hash of the inception event (Base64url)
```

Because the identifier is derived from the event content itself (self-addressing), it
is cryptographically bound to the keys and commitments declared at inception. No
registry or authority assigns it.

## Two kinds of DID

Auths uses two DID methods for different purposes:

| DID method | Example | Purpose |
|------------|---------|---------|
| `did:keri` | `did:keri:E...` | An identity backed by an event log. Your root identity — and each delegated device or agent — has one. Survives key rotation. |
| `did:key` | `did:key:zDna...` (P-256) or `did:key:z6Mk...` (Ed25519) | A raw key identifier: the public key *is* the identifier. Used where a bare key needs a name. Not rotatable. |

Your root identity and your delegated devices are `did:keri` (rotatable, with history).
A `did:key` appears where a single key is the whole story.

## Git as storage

All identity data is stored as Git refs in a bare repository at `~/.auths`. There is no
database, no cloud service, no blockchain.

| Data | Git ref pattern |
|------|-----------------|
| Identity document | `refs/auths/identity` |
| Key Event Logs (yours + delegated devices/agents) | `refs/did/keri/<prefix>/kel` |
| Witness receipts (optional) | `refs/did/keri/<prefix>/receipts/<event-said>` |

Git provides the properties that matter:

- **Content-addressable**: Every object is identified by its hash
- **Append-only history**: Commits cannot be silently altered
- **Replication**: Push and pull to share identity data
- **Offline-first**: No network required for local operations

## Devices and agents are delegated identities

When you add a second device (or an agent), it doesn't get a copy of your key — it gets
**its own key and its own event log**, whose first page says "delegated by
`did:keri:<your-root>`". Your root identity then anchors that delegation in *its* log.

The result is a two-way cryptographic link a verifier can replay: the device claims its
delegator, and the delegator's log confirms the claim. Revoking the device is another
anchored event — no certificate revocation lists, no central registry to update.
Delegations can be **scoped** (e.g. an agent that may only `sign_commit`) and
**time-limited**.

This is how commit verification works end-to-end: each commit carries two trailers,
`Auths-Id` (the root) and `Auths-Device` (the signer). The verifier replays both logs
and checks the signature against the signer's current key — see the
[Trust Model](trust-model.md).

??? info "The KERI details — event types and wire format"

    Auths implements a subset of [KERI](https://keri.one) (Key Event Receipt
    Infrastructure). The borrowed ideas:

    **Self-addressing identifiers.** The identity prefix is the hash of its own
    inception event. The identifier is the content, and the content is the identifier.

    **Pre-rotation.** At inception, a commitment (hash) to the *next* rotation key is
    embedded in the event. Only the holder of that pre-committed key can perform a
    valid rotation — a stolen current key cannot rotate the identity.

    **Key Event Log.** All key lifecycle operations are recorded as a hash-chained
    sequence of events; each references the previous event's SAID.

    | Event | Tag | Purpose |
    |-------|-----|---------|
    | Inception | `icp` | Creates an identity; declares the initial key and next-key commitment |
    | Delegated inception | `dip` | Creates a device/agent identity, naming its delegator |
    | Rotation | `rot` | Rotates to the pre-committed key; declares a new commitment |
    | Interaction | `ixn` | Anchors external data (delegations, attestations) without changing keys |

    The structure of an inception event (see `IcpEvent` in
    [`crates/auths-keri/src/events.rs`](https://github.com/auths-dev/auths/blob/main/crates/auths-keri/src/events.rs)):

    ```json
    {
      "v": "KERI10JSON0000fb_",
      "t": "icp",
      "d": "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148",
      "i": "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148",
      "s": "0",
      "kt": "1",
      "k": ["1AAJ<base64url-encoded-P-256-public-key>"],
      "nt": "1",
      "n": ["E<hash-of-next-public-key>"],
      "bt": "0",
      "b": []
    }
    ```

    Key fields:

    - `d` and `i` are identical at inception — both are the SAID (the prefix)
    - `k` holds the current signing key with its CESR derivation code (`1AAJ` = P-256
      transferable, `D` = Ed25519)
    - `n` holds the next-key commitment
    - `s` is the sequence number (`"0"` for inception)

    **Signatures are not inside the event JSON.** They travel *beside* it as CESR
    attachments (indexed signatures over the canonical event bytes). The event you see
    above is exactly what gets hashed for the SAID; the signature rides alongside.

## Verification is local

To verify a commit or artifact, a verifier needs the signer's event log and the
signature — nothing else. No network call. No server. No blockchain lookup.
Verification is a pure function: data in, result out. This is why the `auths-verifier`
crate has no dependency on `git2`, no network I/O, and no platform-specific code — it
runs anywhere, including in web browsers via WASM.

## The payoff

- A **single, stable identity** (`did:keri:E...`) that works across every device you own
- **Key rotation** that does not break historical signatures
- **Scoped, revocable delegation** for devices, CI, and agents
- **Offline verification** with nothing but Git refs and public keys
- **No accounts, no servers, no vendor lock-in** — just cryptography and Git
