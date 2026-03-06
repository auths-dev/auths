"""Tests for the AgentAuth class."""

import json
import tempfile
from pathlib import Path

import pytest

from auths.agent import AgentAuth, AuthsAgentAuth


def test_agent_auth_init():
    auth = AgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path="/tmp/chain.json",
        root_public_key="abcdef1234",
    )
    assert auth.bridge_url == "http://localhost:3300"
    assert auth._root_public_key == "abcdef1234"


def test_agent_auth_load_chain():
    chain_data = [{"issuer": "did:keri:E123", "subject": "did:keri:E456"}]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(chain_data, f)
        chain_path = f.name

    auth = AgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path=chain_path,
        root_public_key="abcdef1234",
    )
    loaded = auth._load_chain()
    parsed = json.loads(loaded)
    assert parsed == chain_data
    assert auth._chain_json is not None
    Path(chain_path).unlink()


def test_agent_auth_invalid_chain():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not valid json{{{")
        chain_path = f.name

    auth = AgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path=chain_path,
    )
    with pytest.raises(json.JSONDecodeError):
        auth._load_chain()
    Path(chain_path).unlink()


def test_agent_auth_missing_chain():
    auth = AgentAuth(
        bridge_url="http://localhost:3300",
        attestation_chain_path="/nonexistent/path/chain.json",
    )
    with pytest.raises(FileNotFoundError):
        auth._load_chain()


def test_backwards_compat_alias():
    assert AuthsAgentAuth is AgentAuth
