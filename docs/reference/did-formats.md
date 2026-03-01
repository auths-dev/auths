# DID Formats

Auths uses two DID methods.

## `did:keri` (Identity DID)

```
did:keri:EBf7Y2pAnRd2cf6rbP7hbUkJvWMz3RRJPpL...
```

| Component | Value |
|-----------|-------|
| Method | `keri` |
| Prefix | `E` (Ed25519) |
| Encoding | Base64 of the Ed25519 public key |
| Purpose | Stable identity identifier |
| Rotatable | Yes (key changes, DID stays via KEL) |

**Derivation**: Take the Ed25519 public key (32 bytes), Base64-encode it, prepend `E` (KERI derivation code for Ed25519), prepend `did:keri:`.

## `did:key` (Device DID)

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

| Component | Value |
|-----------|-------|
| Method | `key` |
| Prefix | `z` (Base58btc) |
| Multicodec | `0xED01` (Ed25519 public key) |
| Encoding | Base58btc of multicodec-prefixed public key |
| Purpose | Device identifier |
| Rotatable | No (the DID *is* the key) |

**Derivation**: Take the Ed25519 public key (32 bytes), prepend the multicodec bytes `[0xED, 0x01]` (34 bytes total), Base58btc-encode, prepend `z`, prepend `did:key:`.

## Resolving a `did:key` to a public key

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
         │
         └─ Base58btc decode → [0xED, 0x01, <32 bytes>]
                                              └─ Ed25519 public key
```

Steps:

1. Strip `did:key:z` prefix
2. Base58btc-decode the remainder
3. Verify first two bytes are `[0xED, 0x01]`
4. Remaining 32 bytes are the Ed25519 public key

## Comparison

| | `did:keri` | `did:key` |
|---|---|---|
| Use | Identity | Device |
| Key rotation | Supported (via KEL) | Not supported |
| Self-resolving | No (needs KEL lookup) | Yes (key is in the DID) |
| Length | Variable | ~56 characters |
