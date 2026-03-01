# Multi-Device Setup

Two ways to add a device to your identity:

| Approach | Command | What it does |
|----------|---------|--------------|
| **Pairing** (recommended) | `auths pair` | QR code / short code exchange. Handles key agreement and attestation automatically. |
| **Manual Linking** | `auths device link` | Import a key seed, derive the DID, and create the attestation yourself. No registry needed. |

!!! tip "Use `auths pair` for most setups"
    Pairing is the fastest path -- one command on each device, no manual key handling. See [Pairing (QR Code)](pairing.md).

    Choose [Manual Linking](linking.md) when you need full control over key material or can't run a registry server.

## Next steps

- [Pairing (QR Code)](pairing.md) -- recommended for most users
- [Manual Linking](linking.md) -- lower-level, full control
