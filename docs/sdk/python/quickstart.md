# Python SDK Quickstart

## Install

```bash
pip install auths
```

## Create an identity and sign a commit

```python
from auths import Auths

client = Auths()
identity = client.identities.create(label="laptop")

# Sign commit data (returns SSHSIG PEM)
result = client.sign_commit(commit_bytes, identity_did=identity.did)
print(result.signature_pem[:60] + "...")
```

## Link a device

```python
device = client.devices.link(
    identity.did,
    capabilities=["sign", "verify"],
    expires_in=7_776_000,
)
print(f"Device: {device.did}")
```

## Verify a single attestation

```python
attestations = client.attestations.list(device_did=device.did)
att = attestations[0]

result = client.verify(att.json, issuer_key=identity.public_key)
print(f"Valid: {result.valid}")
```

## Verify a chain

```python
chain = [att.json for att in attestations]
report = client.verify_chain(chain, root_key=identity.public_key)
print(f"Chain valid: {report.is_valid()}")
```

## Verify git commits

```python
from auths import verify_commit_range

result = verify_commit_range("origin/main..HEAD")
for commit in result.commits:
    status = "pass" if commit.is_valid else f"FAIL ({commit.error_code})"
    print(f"  {commit.commit_sha[:8]} {status}")
print(result.summary)
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

## Sign an artifact

```python
signed = client.sign_artifact(
    "release.tar.gz",
    identity_did=identity.did,
    expires_in=31_536_000,
)
print(f"RID: {signed.rid}")
print(f"Digest: {signed.digest}")
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

## Next steps

- [API Reference](api/client.md) — full class and function documentation
- [Devices](api/devices.md) — device linking, extension, and revocation
- [Organizations](api/orgs.md) — create orgs and manage members
- [JWT](api/jwt.md) — verify OIDC bridge tokens
- [Errors](errors.md) — error hierarchy and codes
