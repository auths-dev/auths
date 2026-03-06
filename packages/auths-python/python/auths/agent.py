"""Auths agent authentication for MCP tool access."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from auths._native import get_token as _native_get_token


class AgentAuth:
    """Auths agent authentication for MCP tool servers.

    Exchanges a KERI attestation chain for a scoped JWT via the OIDC bridge.

    Args:
        bridge_url: The OIDC bridge base URL (e.g., "https://oidc.example.com").
        attestation_chain_path: Path to the JSON file containing the attestation chain.
        root_public_key: Hex-encoded Ed25519 public key of the root identity.
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
        if self._chain_json is None:
            data = self.chain_path.read_text()
            json.loads(data)
            self._chain_json = data
        return self._chain_json

    def get_token(self, capabilities: Optional[List[str]] = None) -> str:
        """Get a Bearer token for MCP tool access.

        Args:
            capabilities: List of capabilities to request.

        Returns:
            The JWT access token string.
        """
        chain_json = self._load_chain()
        root_pk = self._root_public_key or ""
        caps = capabilities or []
        return _native_get_token(self.bridge_url, chain_json, root_pk, caps)


AuthsAgentAuth = AgentAuth
