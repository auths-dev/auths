# Key Rotation

Key rotation lets you replace your signing key while keeping the same identity DID.

## Why rotate?

- Scheduled key hygiene (periodic replacement)
- Suspected compromise of current key
- Cryptographic algorithm upgrade (future)

## How it works

Auths uses **KERI pre-rotation**. When your identity is created, two keypairs are generated:

1. **Current key** -- used for signing now
2. **Next key** -- a pre-committed rotation key

The identity DID is derived from the current key, but a hash of the next key's public key is included in the inception event. This creates a commitment: only the holder of the next key can perform a valid rotation.

```
Inception Event
  current_key: pk_A
  next_key_hash: hash(pk_B)    ← pre-commitment

Rotation Event
  prev_key: pk_A
  current_key: pk_B            ← matches pre-commitment
  next_key_hash: hash(pk_C)    ← new pre-commitment
```

## What stays the same

- Your `did:keri:E...` identifier
- Your attestation history
- Historical signature validity (old signatures verify against the key state at signing time)

## What changes

- The active signing key
- The Key Event Log (KEL) gains a rotation entry

## Using rotation

```bash
# Rotate using the current key alias
auths id rotate --alias my-key

# Or specify a custom alias for the new key
auths id rotate --alias my-key --next-key-alias my-key-v2
```

After rotation:

- The new key is stored in your keychain
- The old key is retained (for verifying historical signatures)
- The KEL records the rotation event

## Key Event Log (KEL)

The KEL is a sequence of signed events stored at `refs/keri/kel`:

1. **Inception** -- Creates the identity, commits to the first rotation key
2. **Rotation** -- Replaces the active key, commits to the next rotation key
3. **Interaction** -- Non-key-changing events (anchoring data to the log)

Each event is signed by the current key and references the previous event, forming a hash-linked chain.

## Security properties

- **Pre-commitment** prevents key hijacking: even if the current key is compromised, the attacker cannot rotate to their own key (they don't have the pre-committed next key)
- **Forward security**: Rotating keys limits the window of compromise
- **Non-repudiation**: The KEL provides a tamper-evident history of key changes
