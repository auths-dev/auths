# Auths Python SDK

Decentralized identity for developers and AI agents. Sign, verify, and manage cryptographic identities with Git-native storage.

## Install

```bash
pip install auths-python
```

## Quick start

```python
from auths import Auths

auths = Auths()

# Verify an attestation
result = auths.verify(attestation_json=data, issuer_key=public_key_hex)
print(result.valid)  # True

# Sign bytes
signature = auths.sign(b"hello world", private_key=secret_key_hex)
```

## Identity management

```python
from auths import Auths

auths = Auths(repo_path="~/.auths")

# Create a cryptographic identity
identity = auths.identities.create(label="laptop")
print(identity.did)  # did:keri:EBfd...

# Provision an agent (for CI, MCP servers, etc.)
agent = auths.identities.provision_agent(
    identity.did,
    name="deploy-bot",
    capabilities=["sign"],
)

# Sign using the keychain-stored identity key
sig = auths.sign_as(b"hello world", identity=identity.did)

# Link and manage devices
device = auths.devices.link(identity_did=identity.did, capabilities=["sign"])
auths.devices.revoke(device.did, identity_did=identity.did, note="replaced")
```

## Git commit verification

```python
from auths.git import verify_commit_range

result = verify_commit_range("HEAD~5..HEAD")
for commit in result.commits:
    print(f"{commit.commit_sha}: {'valid' if commit.is_valid else commit.error}")
```

## Capability-aware verification

```python
# Verify an attestation grants a specific capability
result = auths.verify(attestation_json=data, issuer_key=key, required_capability="sign_commit")

# Verify an entire chain grants a capability
report = auths.verify_chain(chain, root_key, required_capability="deploy")
```

## Agent auth for MCP / AI frameworks

```python
from auths.agent import AgentAuth

auth = AgentAuth(
    bridge_url="https://bridge.example.com",
    attestation_chain_path=".auths/agent-chain.json",
)
token = auth.get_token(capabilities=["read", "write"])
```

## Error handling

```python
from auths import Auths, VerificationError, NetworkError

auths = Auths()
try:
    result = auths.verify(attestation_json=data, issuer_key=key)
except VerificationError as e:
    print(e.code)     # "expired_attestation"
    print(e.message)  # "Attestation expired at 2024-01-15T..."
except NetworkError as e:
    if e.should_retry:
        pass  # safe to retry
```

All errors inherit from `AuthsError` and carry `.code`, `.message`, and `.context`.

## Configuration

```python
# Auto-discover (uses ~/.auths)
auths = Auths()

# Explicit repo path
auths = Auths(repo_path="/path/to/identity-repo")

# With passphrase (or set AUTHS_PASSPHRASE env var)
auths = Auths(passphrase="my-secret")

# Headless / CI mode
# Set AUTHS_KEYCHAIN_BACKEND=file for environments without a system keychain
```

## API reference

Type stubs are bundled (`py.typed` + `__init__.pyi`). Your editor will show full signatures, docstrings, and return types for all methods.

## License

Apache-2.0
