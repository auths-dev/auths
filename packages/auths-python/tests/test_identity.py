"""Tests for identity and device resource services (Phase 2)."""

import pytest

from auths import AgentIdentity, Auths, DelegatedAgent, Device, Identity


def test_create_identity(shared_auths_with_identity):
    """auths.identities.create() should return an Identity with a did:keri: DID."""
    _client, identity = shared_auths_with_identity
    assert isinstance(identity, Identity)
    assert identity.did.startswith("did:keri:")
    assert identity.label == "shared-test-key"


def test_delegate_agent(shared_auths_with_identity):
    """identities.delegate_agent() should return a DelegatedAgent with did:key: prefix."""
    auths, identity = shared_auths_with_identity
    agent = auths.identities.delegate_agent(
        identity.did, name="ci-bot", capabilities=["sign"]
    )
    assert isinstance(agent, DelegatedAgent)
    assert agent.did.startswith("did:key:")
    assert agent._key_alias == "ci-bot-agent"
    assert agent.attestation


def test_create_agent_identity(shared_auths_with_identity):
    """identities.create_agent() should return an AgentIdentity with did:keri: prefix."""
    auths, _identity = shared_auths_with_identity
    agent = auths.identities.create_agent(name="standalone-bot", capabilities=["sign"])
    assert isinstance(agent, AgentIdentity)
    assert agent.did.startswith("did:keri:")
    assert agent._key_alias == "standalone-bot-agent"


def test_device_lifecycle(tmp_path):
    """Full device lifecycle: link -> verify -> revoke. Uses fresh client (mutating)."""
    auths = Auths(repo_path=str(tmp_path / "test-repo"), passphrase="Test-pass-123")
    identity = auths.identities.create(label="test-key")

    device = auths.devices.link(
        identity_did=identity.did,
        capabilities=["sign"],
        expires_in=7_776_000,
    )
    assert isinstance(device, Device)
    assert device.did.startswith("did:key:")

    auths.devices.revoke(
        device.did, identity_did=identity.did, note="test revocation"
    )


def test_stripe_style_chaining(tmp_path):
    """The full 'Stripe for identity' flow should work end-to-end. Uses fresh client (mutating)."""
    auths = Auths(repo_path=str(tmp_path / "test-repo"), passphrase="Test-pass-123")
    identity = auths.identities.create(label="laptop")
    agent = auths.identities.delegate_agent(
        identity.did, name="deploy-bot", capabilities=["sign", "verify"]
    )
    device = auths.devices.link(
        identity_did=identity.did, capabilities=["sign"]
    )
    auths.devices.revoke(device.did, identity_did=identity.did)
