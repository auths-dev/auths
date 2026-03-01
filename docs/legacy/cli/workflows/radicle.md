# Radicle Workflow

Use Auths with Radicle-compatible Git storage layout.

## Overview

Radicle uses a different Git ref structure than Auths's default. By passing layout flags, Auths can store identity and attestation data in Radicle-compatible refs.

| Default layout | Radicle layout |
|----------------|----------------|
| `refs/auths/identity` | `refs/rad/id` |
| `identity.json` | `radicle-identity.json` |
| `refs/auths/devices/nodes` | `refs/rad/multidevice/nodes` |
| `attestation.json` | `link-attestation.json` |

## 1. Initialize with Radicle layout

Create metadata:

```bash
cat > ~/radicle_meta.json << 'EOF'
{
  "xyz.radicle.agent": {"alias": "my_rad_alias", "controller": ""},
  "profile": {"name": "Radicle User"}
}
EOF
```

Initialize:

```bash
RAD_REPO_PATH="$HOME/my_radicle_identity_repo"

auths id init-did \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/rad/multidevice/nodes" \
  --attestation-blob "link-attestation.json" \
  --metadata-file ~/radicle_meta.json \
  --local-key-alias radicle_id_key
```

## 2. Verify (with layout flags)

All subsequent commands must include the layout flags:

```bash
auths id show \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/rad/multidevice/nodes" \
  --attestation-blob "link-attestation.json"
```

## 3. Link a device

```bash
CONTROLLER_DID=$(auths id show \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/rad/multidevice/nodes" \
  --attestation-blob "link-attestation.json" \
  | grep 'Controller DID:' | awk -F': ' '{print $2}')

auths key import --alias rad_device_key --seed-file ~/rad_device.seed --controller-did "$CONTROLLER_DID"

DEVICE_DID=$(auths util derive-did --seed-hex $(xxd -p -c 256 ~/rad_device.seed) | awk '{print $3}')

auths device link \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/rad/multidevice/nodes" \
  --attestation-blob "link-attestation.json" \
  --identity-key-alias radicle_id_key \
  --device-key-alias rad_device_key \
  --device-did "$DEVICE_DID" \
  --note "Radicle Laptop Key"
```

## 4. Verify the link

```bash
auths id show-devices \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/rad/multidevice/nodes" \
  --attestation-blob "link-attestation.json"
```

!!! tip "Shell alias"
    To avoid typing layout flags every time, create a shell alias:
    ```bash
    alias auths-rad='auths --repo "$RAD_REPO_PATH" --identity-ref "refs/rad/id" --identity-blob "radicle-identity.json" --attestation-prefix "refs/rad/multidevice/nodes" --attestation-blob "link-attestation.json"'
    ```
    Then: `auths-rad id show`
