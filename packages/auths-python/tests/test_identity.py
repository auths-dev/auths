"""Tests for identity and device resource services (Phase 2)."""

import pytest

from auths import AgentIdentity, Auths, DelegatedAgent, Device, Identity


@pytest.fixture
def auths(tmp_path):
    """Create an Auths client with a temp directory (registry auto-inits on first use)."""
    repo = tmp_path / "test-repo"
    repo.mkdir()
    return Auths(repo_path=str(repo), passphrase="Test-pass-123")


def test_create_identity(auths):
    """auths.identities.create() should return an Identity with a did:keri: DID."""
    identity = auths.identities.create(label="test-key")
    assert isinstance(identity, Identity)
    assert identity.did.startswith("did:keri:")
    assert identity.label == "test-key"


def test_delegate_agent(auths):
    """identities.delegate_agent() should return a DelegatedAgent with did:key: prefix."""
    identity = auths.identities.create(label="test-key")
    agent = auths.identities.delegate_agent(
        identity.did, name="ci-bot", capabilities=["sign"]
    )
    assert isinstance(agent, DelegatedAgent)
    assert agent.did.startswith("did:key:")
    assert agent._key_alias == "ci-bot-agent"
    assert agent.attestation


def test_create_agent_identity(auths):
    """identities.create_agent() should return an AgentIdentity with did:keri: prefix."""
    agent = auths.identities.create_agent(name="standalone-bot", capabilities=["sign"])
    assert isinstance(agent, AgentIdentity)
    assert agent.did.startswith("did:keri:")
    assert agent._key_alias == "standalone-bot-agent"


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
    agent = auths.identities.delegate_agent(
        identity.did, name="deploy-bot", capabilities=["sign", "verify"]
    )
    device = auths.devices.link(
        identity_did=identity.did, capabilities=["sign"]
    )
    auths.devices.revoke(device.did, identity_did=identity.did)
