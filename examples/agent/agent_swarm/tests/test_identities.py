"""Tests for the swarm identity tree and delegation chain."""

import json
from unittest.mock import patch

from agent_swarm import identities


def test_make_swarm_returns_correct_structure(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        human, orch, agents = identities.make_swarm()
    assert human.name == "Human"
    assert orch.name == "Orchestrator"
    assert len(agents) == 3
    assert [a.name for a in agents] == ["DataAgent", "AnalysisAgent", "NotifyAgent"]


def test_all_dids_are_keri(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        human, orch, agents = identities.make_swarm()
    for identity in [human, orch, *agents]:
        assert identity.did.startswith("did:keri:E"), f"{identity.name}: {identity.did}"


def test_human_has_no_delegation(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        human, _, _ = identities.make_swarm()
    assert human.delegation_token is None
    assert human.delegated_by is None


def test_orchestrator_delegated_by_human(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        human, orch, _ = identities.make_swarm()
    assert orch.delegated_by == human.did
    assert orch.delegation_token is not None


def test_sub_agents_delegated_by_orchestrator(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, orch, agents = identities.make_swarm()
    for agent in agents:
        assert agent.delegated_by == orch.did
        assert agent.delegation_token is not None


def test_delegation_tokens_are_valid_json(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, orch, agents = identities.make_swarm()
    for identity in [orch, *agents]:
        token = json.loads(identity.delegation_token)
        assert token["type"] == "delegation"
        assert token["identity"] == identity.delegated_by


def test_delegation_token_payload_matches_capabilities(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, orch, agents = identities.make_swarm()
    for agent in agents:
        token = json.loads(agent.delegation_token)
        payload = token["payload"]
        assert payload["delegate_to"] == agent.did
        assert payload["capabilities"] == agent.capabilities


def test_delegation_token_signatures_valid(tmp_path):
    from auths import verify_action_envelope

    with patch.object(identities, "DEMO_REPO", tmp_path):
        human, orch, agents = identities.make_swarm()

    result = verify_action_envelope(orch.delegation_token, human.pub_hex)
    assert result.valid, f"orch delegation invalid: {result.error}"

    for agent in agents:
        result = verify_action_envelope(agent.delegation_token, orch.pub_hex)
        assert result.valid, f"{agent.name} delegation invalid: {result.error}"


def test_all_dids_are_unique(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        human, orch, agents = identities.make_swarm()
    all_ids = [human.did, orch.did, *[a.did for a in agents]]
    assert len(all_ids) == len(set(all_ids))
