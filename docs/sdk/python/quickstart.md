# Python SDK Quickstart

Get from `pip install` to verified attestation in under 2 minutes.

## Install

```bash
pip install auths
```

Requires Python 3.8+. Native Ed25519 via Rust — no OpenSSL dependency.

## Verify an attestation (no client needed)

The most common use case: you have a `.auths.json` file and want to check if it's valid.

```python
from auths import verify_attestation

with open("release.tar.gz.auths.json") as f:
    attestation_json = f.read()

result = verify_attestation(attestation_json, issuer_public_key_hex)
print(result.valid)  # True
print(result.error)  # None
```

## Verify an attestation chain

Check that a device was authorized by an identity, with full delegation chain verification:

```python
from auths import verify_chain

report = verify_chain(
    [att1_json, att2_json],  # ordered: root → leaf
    root_public_key_hex
)

for link in report.chain:
    mark = "✓" if link.valid else "✗"
    print(f"  {mark} {link.issuer} → {link.subject}")
```

## Create an identity and link a device

```python
from auths import Auths

client = Auths()
identity = client.identities.create(label="laptop")

device = client.devices.link(
    identity.did,
    capabilities=["sign", "verify"],
    expires_in=7_776_000,
)
print(f"Identity: {identity.did}")
print(f"Device:   {device.did}")
```

## Sign and verify artifacts

```python
signed = client.sign_artifact(
    "release.tar.gz",
    identity_did=identity.did,
    expires_in=31_536_000,
)
print(f"RID:    {signed.rid}")
print(f"Digest: {signed.digest}")
# -> release.tar.gz.auths.json created
```

## Sign and verify actions (API auth)

The same identity that signs artifacts can authenticate API requests:

```python
# Sign an action envelope
envelope = client.sign_action(
    action_type="api_call",
    payload_json='{"endpoint": "/resource"}',
    identity_did=identity.did,
)

# Verify it (server-side, stateless — one function call)
result = client.verify_action(envelope, identity.public_key)
print(result.valid)  # True
```

## Verify Git commits

```python
from auths.git import verify_commit_range

results = verify_commit_range(
    commit_range="HEAD~5..HEAD",
    identity_bundle="bundle.json",
)

for commit in results.commits:
    mark = "✓" if commit.is_valid else "✗"
    print(f"  {mark} {commit.commit_sha[:8]} — {commit.error or 'signed'}")
print(results.summary)
```

## Build a policy

```python
from auths import PolicyBuilder

policy = (
    PolicyBuilder()
    .not_revoked()
    .not_expired()
    .require_capability("deploy:production")
    .require_issuer(identity.did)
    .build()
)
```

## Ephemeral identities (testing & demos)

No keychain or filesystem needed — generate a throwaway identity in-memory:

```python
from auths._native import generate_inmemory_keypair, sign_bytes_raw

keypair = generate_inmemory_keypair()
print(keypair.did)             # did:key:z6Mk...
print(keypair.public_key_hex)  # 64-char hex

signature = sign_bytes_raw(keypair.private_key_hex, b"hello")
```

## Error handling

```python
from auths import AuthsError, VerificationError, KeychainError

try:
    client.sign_commit(data, identity_did="did:keri:nonexistent")
except KeychainError as e:
    print(f"Keychain issue ({e.code}): {e.message}")
except AuthsError as e:
    print(f"Auths error ({e.code}): {e.message}")
```

All errors inherit from `AuthsError`. See [Error Reference](errors.md) for the full hierarchy.

## Next steps

| Guide | Description |
|-------|-------------|
| [API Reference](api/client.md) | Full class and function documentation |
| [Identity & Devices](api/identities.md) | Create identities, link devices, rotate keys |
| [Artifact Signing](api/signing.md) | Sign releases for CI/CD |
| [Policy Engine](api/policy.md) | Enforce signing policies programmatically |
| [Organizations](api/orgs.md) | Create orgs and manage members |
| [Errors](errors.md) | Error hierarchy and codes |
