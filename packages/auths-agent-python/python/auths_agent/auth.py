"""Auths agent authentication for MCP tool access.

Usage with LangChain:
    from auths_agent import AuthsAgentAuth

    auth = AuthsAgentAuth(
        bridge_url="https://oidc.example.com",
        attestation_chain_path="~/.auths-agent/chain.json",
    )

    # Get Bearer token for MCP tool access
    token = auth.get_token(capabilities=["fs:read", "web:search"])
"""

import json
from pathlib import Path
from typing import List, Optional

from auths_agent._native import get_token as _native_get_token


class AuthsAgentAuth:
    """Auths agent authentication for MCP tool servers.

    Exchanges a KERI attestation chain for a scoped JWT via the OIDC bridge.
    The JWT can then be used as a Bearer token for MCP tool server access.

    Args:
        bridge_url: The OIDC bridge base URL (e.g., "https://oidc.example.com").
        attestation_chain_path: Path to the JSON file containing the attestation chain.
        root_public_key: Hex-encoded Ed25519 public key of the root identity.
            If not provided, it will be extracted from the chain file.
    """

    def __init__(
        self,
        bridge_url: str,
        attestation_chain_path: str,
        root_public_key: Optional[str] = None,
    ):
        self.bridge_url = bridge_url
        self.chain_path = Path(attestation_chain_path).expanduser()
        self._root_public_key = root_public_key
        self._chain_json: Optional[str] = None

    def _load_chain(self) -> str:
        """Load the attestation chain from disk."""
        if self._chain_json is None:
            data = self.chain_path.read_text()
            # Validate it's valid JSON
            json.loads(data)
            self._chain_json = data
        return self._chain_json

    def get_token(self, capabilities: Optional[List[str]] = None) -> str:
        """Get a Bearer token for MCP tool access.

        Args:
            capabilities: List of capabilities to request (e.g., ["fs:read"]).
                If None, all chain-granted capabilities are included.

        Returns:
            The JWT access token string for use as a Bearer token.

        Raises:
            ConnectionError: If the OIDC bridge is unreachable.
            RuntimeError: If the token exchange fails.
            ValueError: If the chain file is invalid.
        """
        chain_json = self._load_chain()
        root_pk = self._root_public_key or ""
        caps = capabilities or []

        return _native_get_token(
            self.bridge_url,
            chain_json,
            root_pk,
            caps,
        )
