# Manual Linking

!!! note "Looking for the easy path?"
    For most users, [`auths pair`](pairing.md) is simpler -- it handles key exchange and attestation creation automatically via QR code or short code. Use this page when you need full control over key material or can't run a registry server.

Link multiple devices to a single identity. All devices sign as the same `did:keri` identity.

## Prerequisites

- Identity already initialized (see [Single Device](../single-device.md))
- A device key seed or keypair on the new device

## 1. Import the device key

On the new device, import a key seed:

```bash
CONTROLLER_DID=$(auths id show | grep 'Controller DID:' | awk -F': ' '{print $2}')

auths key import \
  --alias laptop-key \
  --seed-file ~/device_key.seed \
  --controller-did "$CONTROLLER_DID"
```

Verify:

```bash
auths key list
# Expected: - my-key, - laptop-key
```

## 2. Derive the device DID

```bash
DEVICE_DID=$(auths util derive-did --seed-hex $(xxd -p -c 256 ~/device_key.seed) | awk '{print $3}')
echo $DEVICE_DID
```

## 3. Link the device

```bash
auths device link \
  --identity-key-alias my-key \
  --device-key-alias laptop-key \
  --device-did "$DEVICE_DID" \
  --note "Work Laptop" \
  --expires-in-days 90
```

You'll be prompted for passphrases:

1. Device key passphrase
2. Identity key passphrase
3. Device key passphrase (for the device signature)

## 4. Verify the link

```bash
auths id show-devices
```

```
Linked devices:
  did:key:z6Mk...
    Status: Active
    Note: Work Laptop
    Expires: 2025-06-01T00:00:00Z
```

## 5. Use the device

Configure Git on the new device:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:laptop-key"
git config --global commit.gpgSign true
```

Commits from this device will be signed by the same identity.

## Extending attestations

Before an attestation expires, renew it:

```bash
auths device extend \
  --identity-key-alias my-key \
  --device-did "$DEVICE_DID" \
  --expires-in-days 90
```

## Revoking a device

If a device is lost or compromised:

```bash
auths device revoke \
  --identity-key-alias my-key \
  --device-did "$DEVICE_DID" \
  --note "Laptop retired"
```

Verify:

```bash
auths id show-devices                    # Device should be gone
auths id show-devices --include-revoked  # Device shows as revoked
```

## Deleting local keys

After revoking, remove the keys from the keychain:

```bash
auths key delete --alias laptop-key
```
