# Identity Curves

Auths supports two elliptic curves for identity keys: **P-256** (default) and **Ed25519**.

## Why P-256 Is the Default

P-256 is the curve the broader signing ecosystem has converged on. Rekor uses ECDSA P-256 for checkpoint signatures. Sigstore's Fulcio CA issues P-256 certificates. The Web PKI defaults to P-256. By choosing P-256, auths shares cryptographic primitives with the infrastructure it depends on.

When Apple Secure Enclave support ships (future), P-256 identities will be promotable to hardware-backed storage without changing the identity.

## Creating an Identity

```bash
# Default: P-256
auths init

# Explicitly P-256
auths init --curve p256

# Ed25519 (for compatibility with existing KERI deployments)
auths init --curve ed25519
```

## Which Curve to Pick

| Scenario | Recommended | Why |
|---|---|---|
| New user, any platform | P-256 (default) | Ecosystem alignment, future Secure Enclave |
| Existing KERI deployment | Ed25519 | Interop with existing identifiers |
| Cross-platform portability | Either | Both work everywhere in software |

## Key Properties

- The curve is per-identity, recorded in the inception event's CESR derivation code
- The curve cannot change across key rotation (enforced by the validator)
- Both curves produce valid KERI identities verifiable by other implementations
- P-256 keys are 33 bytes (compressed SEC1), Ed25519 keys are 32 bytes
- Both use 64-byte signatures (P-256: raw r||s, Ed25519: standard)

## KERI Identifiers

- P-256 identity: `did:keri:1AAJ...` (CESR code `1AAJ`)
- Ed25519 identity: `did:keri:D...` (CESR code `D`)
- P-256 device: `did:key:zDn...` (multicodec `[0x80, 0x24]`)
- Ed25519 device: `did:key:z6Mk...` (multicodec `[0xED, 0x01]`)
