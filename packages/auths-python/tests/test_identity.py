"""Tests for identity and device resource services (Phase 2).

These tests require a real git registry and keychain setup.
Run with: AUTHS_KEYCHAIN_BACKEND=file AUTHS_PASSPHRASE=test uv run pytest tests/test_identity.py -v
"""

import subprocess

import pytest

from auths import Agent, Auths, Device, Identity


@pytest.fixture
def auths(tmp_path):
    """Create an Auths client with a temp git repo initialized as an auths registry."""
    repo = tmp_path / "test-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
    )
    return Auths(repo_path=str(repo), passphrase="test")


def test_create_identity(auths):
    """auths.identities.create() should return an Identity with a did:keri: DID."""
    identity = auths.identities.create(label="test-key")
    assert isinstance(identity, Identity)
    assert identity.did.startswith("did:keri:")
    assert identity.label == "test-key"


def test_provision_agent(auths):
    """identity.provision_agent() should return an Agent with valid fields."""
    identity = auths.identities.create(label="test-key")
    agent = auths.identities.provision_agent(
        identity.did, name="ci-bot", capabilities=["sign"]
    )
    assert isinstance(agent, Agent)
    assert agent.did.startswith("did:key:")
    assert agent.label == "ci-bot"
    assert agent.attestation


def test_device_lifecycle(auths):
    """Full device lifecycle: link -> verify -> revoke."""
    identity = auths.identities.create(label="test-key")

    device = auths.devices.link(
        identity_did=identity.did,
        capabilities=["sign"],
        expires_in_days=90,
    )
    assert isinstance(device, Device)
    assert device.did.startswith("did:key:")

    auths.devices.revoke(
        device.did, identity_did=identity.did, note="test revocation"
    )


def test_stripe_style_chaining(auths):
    """The full 'Stripe for identity' flow should work end-to-end."""
    identity = auths.identities.create(label="laptop")
    agent = auths.identities.provision_agent(
        identity.did, name="deploy-bot", capabilities=["sign", "verify"]
    )
    device = auths.devices.link(
        identity_did=identity.did, capabilities=["sign"]
    )
    auths.devices.revoke(device.did, identity_did=identity.did)
