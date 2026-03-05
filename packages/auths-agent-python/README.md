# auths-agent

Cryptographic agent identity for Python AI frameworks. Exchanges KERI attestation chains for scoped JWTs via the Auths OIDC bridge, giving AI agents verifiable identity when calling MCP tool servers.

## Installation

```bash
pip install auths-agent
```

### Building from source

Requires Rust and [uv](https://docs.astral.sh/uv/):

```bash
uv sync
```

## Usage

```python
from auths_agent import AuthsAgentAuth

auth = AuthsAgentAuth(
    bridge_url="https://oidc.example.com",
    attestation_chain_path="~/.auths-agent/chain.json",
)

# Get a scoped Bearer token for MCP tool access
token = auth.get_token(capabilities=["fs:read", "web:search"])
```

### LangChain

```python
from auths_agent import AuthsAgentAuth

auth = AuthsAgentAuth(
    bridge_url="https://oidc.example.com",
    attestation_chain_path="~/.auths-agent/chain.json",
)

token = auth.get_token(capabilities=["fs:read"])
# Pass token to your MCP tool server client
headers = {"Authorization": f"Bearer {token}"}
```

### CrewAI

```python
from auths_agent import AuthsAgentAuth

auth = AuthsAgentAuth(
    bridge_url="https://oidc.example.com",
    attestation_chain_path="~/.auths-agent/chain.json",
)

headers = {"Authorization": f"Bearer {auth.get_token(['fs:read'])}"}
```

## API

### `AuthsAgentAuth`

```python
AuthsAgentAuth(
    bridge_url: str,
    attestation_chain_path: str,
    root_public_key: str | None = None,
)
```

| Parameter | Description |
|---|---|
| `bridge_url` | OIDC bridge base URL (e.g., `https://oidc.example.com`) |
| `attestation_chain_path` | Path to the JSON attestation chain file |
| `root_public_key` | Hex-encoded Ed25519 public key of the root identity. Extracted from the chain file if not provided. |

### `AuthsAgentAuth.get_token`

```python
get_token(capabilities: list[str] | None = None) -> str
```

Exchanges the attestation chain for a scoped JWT via the OIDC bridge.

| Parameter | Description |
|---|---|
| `capabilities` | Capabilities to request (e.g., `["fs:read"]`). If `None`, all chain-granted capabilities are included. |

**Returns:** JWT access token string.

**Raises:**
- `ConnectionError` — OIDC bridge is unreachable.
- `RuntimeError` — Token exchange failed.
- `ValueError` — Chain file contains invalid JSON.
- `FileNotFoundError` — Chain file does not exist.

## Testing

```bash
uv sync
uv run pytest
```

To run a specific test:

```bash
uv run pytest tests/test_auth.py::test_auth_load_chain
```

The unit tests cover initialization, chain loading and caching, and error handling for invalid or missing chain files. They do not require a running OIDC bridge. For end-to-end tests that exercise the full token exchange flow, see [`tests/e2e/test_mcp_server.py`](../../tests/e2e/test_mcp_server.py) in the repository root.

## How it works

1. The agent's KERI attestation chain is loaded from disk
2. The chain is posted to the OIDC bridge's `/token` endpoint along with the requested capabilities
3. The bridge validates the chain and returns a scoped JWT
4. The JWT is used as a Bearer token when calling MCP tool servers

The native token exchange is implemented in Rust (via PyO3) for performance and to reuse the same cryptographic primitives as the rest of the Auths ecosystem.

## Requirements

- Python >= 3.8
- A running [Auths OIDC bridge](../../crates/auths-oidc-bridge)
- An attestation chain file (created via `auths agent provision`)

## License

Apache-2.0
