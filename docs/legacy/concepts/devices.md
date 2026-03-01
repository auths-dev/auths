# Devices

A device in Auths is any machine that holds a keypair and acts on behalf of your identity.

## Device DID

Each device is identified by a `did:key` identifier:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

This is derived from the device's Ed25519 public key using the `did:key` method: Base58-encoded with a multicodec prefix (`0xED01` for Ed25519).

The key difference from the identity DID:

| | Identity DID | Device DID |
|---|---|---|
| **Method** | `did:keri` | `did:key` |
| **Derived from** | Root key | Device key |
| **Rotatable** | Yes (key changes, DID stays) | No (DID is the key) |
| **Purpose** | "Who am I" | "What machine am I on" |

## Linking a device

When you link a device to your identity, Auths creates an **attestation** signed by both:

1. The identity key (proving the identity approves this device)
2. The device key (proving the device acknowledges the link)

This two-way binding prevents someone from unilaterally claiming a device belongs to an identity.

## Device lifecycle

```
    ┌──────────┐
    │  Create  │  Generate keypair on device
    └────┬─────┘
         │
    ┌────▼─────┐
    │   Link   │  Sign attestation (identity + device)
    └────┬─────┘
         │
    ┌────▼─────┐
    │  Active  │  Device can sign as the identity
    └────┬─────┘
         │
    ┌────▼─────┐          ┌──────────┐
    │  Extend  │────or───▶│  Revoke  │
    └──────────┘          └──────────┘
```

- **Link**: Creates the initial attestation with an optional expiration
- **Active**: The device is authorized and its attestation is valid
- **Extend**: Renew the attestation before it expires
- **Revoke**: Permanently disable the device (e.g., device lost or stolen)

## Where device keys live

Device keys are stored in the platform keychain, same as identity keys. Each key has a **local alias** (e.g., `laptop-key`, `phone-key`) used to reference it in CLI commands.

## Multiple devices, one identity

This is Auths's core value proposition:

```bash
# Laptop signs a commit
git commit -S -m "feature: add login"
# Signed by did:keri:E... via did:key:z6MkLaptop...

# Phone signs a commit
git commit -S -m "fix: typo"
# Signed by did:keri:E... via did:key:z6MkPhone...
```

Both commits are signed by the **same identity** but different **devices**. A verifier can confirm both are authorized by checking the attestation chain.
