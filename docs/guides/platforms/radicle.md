# Radicle Integration

Use Auths with [Radicle](https://radicle.xyz) for sovereign code forge identity. The `auths-radicle` crate provides an adapter layer that bridges Radicle's peer-to-peer Git collaboration with Auths' policy-based authorization, without introducing any new signature formats.

## Architecture

The integration follows a **zero new crypto** principle:

- **Radicle handles all cryptographic signature verification** (Ed25519).
- **Auths provides authorization** through its policy engine (is this key allowed to sign for this identity?).
- The `auths-radicle` adapter bridges the two.

Radicle identifies peers with `did:key:z6Mk...` identifiers (Ed25519 multicodec format). The adapter maps these to Auths device DIDs and evaluates device attestations against the Auths policy engine.

### Verification flow

1. Radicle verifies the Ed25519 signature on a commit (cryptographic proof).
2. The adapter converts the signer's public key to a `did:key` device DID.
3. The adapter loads the identity and device attestation from storage.
4. The Auths policy engine evaluates the attestation (not revoked, not expired).
5. The result is mapped: `Allow` becomes `Verified`, `Deny` becomes `Rejected`, `Indeterminate` becomes `Warn`.

## Storage layout

Radicle uses a different Git ref structure than the default Auths layout. Auths supports this through layout presets:

| Default Auths layout | Radicle layout |
|---|---|
| `refs/auths/identity` | `refs/rad/id` |
| `identity.json` | `radicle-identity.json` |
| `refs/auths/devices/nodes` | `refs/keys` |
| `attestation.json` | `link-attestation.json` |

## Setup

### 1. Create an identity with the Radicle preset

First, create a metadata file for your Radicle identity:

```bash
cat > ~/radicle_meta.json << 'EOF'
{
  "xyz.radicle.agent": {"alias": "my_rad_alias", "controller": ""},
  "profile": {"name": "Radicle User"}
}
EOF
```

Then initialize your identity using the `--preset radicle` flag, which automatically applies the Radicle storage layout:

```bash
RAD_REPO_PATH="$HOME/my_radicle_identity_repo"

auths id create \
  --metadata-file ~/radicle_meta.json \
  --local-key-alias radicle_id_key \
  --preset radicle
```

The `--preset radicle` flag sets the identity ref to `refs/rad/id`, the identity blob to `radicle-identity.json`, the attestation prefix to `refs/keys`, and the attestation blob to `link-attestation.json`.

### 2. View identity details

You can also pass layout flags explicitly instead of using the preset. All subsequent commands need the layout flags to read from the correct refs:

```bash
auths id show \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/keys" \
  --attestation-blob "link-attestation.json"
```

### 3. Link a device

Import a device key and link it to your Radicle identity:

```bash
CONTROLLER_DID=$(auths id show \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/keys" \
  --attestation-blob "link-attestation.json" \
  | grep 'Controller DID:' | awk -F': ' '{print $2}')

auths key import \
  --alias rad_device_key \
  --seed-file ~/rad_device.seed \
  --controller-did "$CONTROLLER_DID"
```

Then link the device:

```bash
auths device link \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/keys" \
  --attestation-blob "link-attestation.json" \
  --identity-key-alias radicle_id_key \
  --device-key-alias rad_device_key \
  --device-did "$DEVICE_DID" \
  --note "Radicle Laptop Key"
```

### 4. Verify linked devices

```bash
auths device list \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/keys" \
  --attestation-blob "link-attestation.json"
```

## Shell alias

To avoid repeating layout flags on every command, create a shell alias:

```bash
alias auths-rad='auths \
  --repo "$RAD_REPO_PATH" \
  --identity-ref "refs/rad/id" \
  --identity-blob "radicle-identity.json" \
  --attestation-prefix "refs/keys" \
  --attestation-blob "link-attestation.json"'
```

Then use it as:

```bash
auths-rad id show
auths-rad device list
```

## Threshold identities

Radicle supports threshold identities (e.g., 2-of-3 delegates must sign). The `auths-radicle` crate provides `verify_multiple_signers` and `meets_threshold` functions for evaluating multi-signer commits against Auths policy:

```rust
use auths_radicle::{DefaultBridge, verify_multiple_signers, meets_threshold};

let bridge = DefaultBridge::with_storage(storage);

let signer_keys: Vec<[u8; 32]> = /* collect from Radicle commit */;
let results = verify_multiple_signers(&bridge, &signer_keys, "repo-id", now);

if meets_threshold(&results, identity.document.threshold as usize) {
    println!("Commit authorized by threshold quorum");
}
```

## Radicle identity documents

The adapter reads Radicle identity documents from `refs/rad/id`. These documents contain a list of delegate DIDs and a threshold:

```json
{
  "delegates": [
    "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"
  ],
  "threshold": 1,
  "payload": {
    "name": "my-project"
  }
}
```

The adapter extracts the Ed25519 public key from each delegate's `did:key` (base58btc-encoded with the `0xED01` multicodec prefix) and uses it for policy evaluation.
