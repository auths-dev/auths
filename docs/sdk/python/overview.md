# Python SDK Overview

Full-featured Python SDK for Auths decentralized identity, backed by Rust via PyO3. Create identities, sign commits and artifacts, verify attestation chains, and manage organizations — all from Python.

## Installation

```bash
pip install auths
```

Pre-built wheels for Linux, macOS, and Windows (Python 3.8+ via ABI3). No Rust toolchain required.

For JWT token verification, install the optional dependency:

```bash
pip install auths[jwt]
```

## Quick taste

```python
from auths import Auths

client = Auths()
identity = client.identities.create(label="laptop")
result = client.sign_commit(commit_bytes, identity_did=identity.did)
print(result.signature_pem)
```

## What you can do

| Feature | Service | API Reference |
|---------|---------|---------------|
| Create and rotate identities | `client.identities` | [Identities](api/identities.md) |
| Link, extend, and revoke devices | `client.devices` | [Devices](api/devices.md) |
| Query attestation chains | `client.attestations` | [Attestations](api/attestations.md) |
| Sign commits and artifacts | `client.sign_commit()`, `client.sign_artifact()` | [Client](api/client.md), [Signing](api/signing.md) |
| Verify attestations and chains | `client.verify()`, `client.verify_chain()` | [Client](api/client.md), [Verification](api/verification.md) |
| Build authorization policies | `PolicyBuilder` | [Policy](api/policy.md) |
| Manage organizations | `client.orgs` | [Organizations](api/orgs.md) |
| Verify OIDC bridge tokens | `AuthsJWKSClient` | [JWT](api/jwt.md) |
| Authenticate CI agents | `AgentAuth` | [Agent Auth](api/agent.md) |
| Verify git commit ranges | `verify_commit_range()` | [Git](api/git.md) |

## Architecture

The Python SDK is a thin wrapper over the Rust `auths-sdk` crate via PyO3. All cryptographic operations happen in Rust — the Python layer provides Pythonic dataclasses, error types, and service objects.

```text
Python (auths.*)  →  PyO3 bridge (auths._native)  →  Rust (auths-sdk)
```

## Next steps

- [Quickstart](quickstart.md) — end-to-end walkthrough
- [API Reference](api/client.md) — full class and function docs
- [Errors](errors.md) — error hierarchy and codes
