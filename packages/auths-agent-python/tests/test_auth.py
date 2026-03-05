"""Tests for the AuthsAgentAuth class."""

import json
import tempfile
from pathlib import Path

import pytest

from auths_agent.auth import AuthsAgentAuth


def test_auth_init():
    """AuthsAgentAuth should initialize with valid parameters."""
    auth = AuthsAgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path="/tmp/chain.json",
        root_public_key="abcdef1234",
    )
    assert auth.bridge_url == "http://localhost:3300"
    assert auth._root_public_key == "abcdef1234"


def test_auth_load_chain():
    """AuthsAgentAuth should load and cache the chain file."""
    chain_data = [{"issuer": "did:keri:E123", "subject": "did:keri:E456"}]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(chain_data, f)
        chain_path = f.name

    auth = AuthsAgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path=chain_path,
        root_public_key="abcdef1234",
    )
    loaded = auth._load_chain()
    parsed = json.loads(loaded)
    assert parsed == chain_data

    # Should be cached
    assert auth._chain_json is not None

    Path(chain_path).unlink()


def test_auth_invalid_chain():
    """AuthsAgentAuth should raise on invalid JSON chain file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not valid json{{{")
        chain_path = f.name

    auth = AuthsAgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path=chain_path,
    )

    with pytest.raises(json.JSONDecodeError):
        auth._load_chain()

    Path(chain_path).unlink()


def test_auth_missing_chain():
    """AuthsAgentAuth should raise when chain file doesn't exist."""
    auth = AuthsAgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path="/nonexistent/path/chain.json",
    )

    with pytest.raises(FileNotFoundError):
        auth._load_chain()
