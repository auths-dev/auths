"""Tests for capability enforcement and action signing."""

import json
from unittest.mock import patch

import pytest

from agent_swarm import identities, signing
from agent_swarm.signing import CapabilityError, require_capability, sign_tool_call


def test_require_capability_passes_for_granted_cap(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
    require_capability(agents[0], "read_data")  # DataAgent — should not raise


def test_require_capability_raises_for_missing_cap(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
    with pytest.raises(CapabilityError, match="lacks 'notify'"):
        require_capability(agents[0], "notify")


def test_sign_tool_call_succeeds_within_scope(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
        envelope_json = sign_tool_call(agents[0], "read_csv", {"path": "f.csv"}, "read_data")
    envelope = json.loads(envelope_json)
    assert envelope["type"] == "tool_call"
    assert envelope["identity"] == agents[0].did


def test_sign_tool_call_blocked_outside_scope(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
        with pytest.raises(CapabilityError):
            sign_tool_call(
                agents[0], "send_notification", {"channel": "team", "message": "hi"}, "notify"
            )


def test_sign_tool_call_embeds_delegation_token(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
        envelope_json = sign_tool_call(agents[0], "read_csv", {"path": "f.csv"}, "read_data")
    envelope = json.loads(envelope_json)
    assert "delegation_token" in envelope["payload"]
    assert envelope["payload"]["delegation_token"]["type"] == "delegation"


def test_signed_envelope_verifies(tmp_path):
    from auths import verify_action_envelope

    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
        envelope_json = sign_tool_call(agents[0], "read_csv", {"path": "f.csv"}, "read_data")

    result = verify_action_envelope(envelope_json, agents[0].pub_hex)
    assert result.valid


def test_tampered_envelope_fails_verification(tmp_path):
    from auths import verify_action_envelope

    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
        envelope_json = sign_tool_call(agents[0], "read_csv", {"path": "f.csv"}, "read_data")

    envelope = json.loads(envelope_json)
    envelope["payload"]["tool"] = "drop_database"
    result = verify_action_envelope(json.dumps(envelope), agents[0].pub_hex)
    assert not result.valid


def test_each_agent_confined_to_its_capabilities(tmp_path):
    with patch.object(identities, "DEMO_REPO", tmp_path):
        _, _, agents = identities.make_swarm()
        data_agent, analysis_agent, notify_agent = agents

        # Each agent works within its own scope
        sign_tool_call(data_agent, "read_csv", {"path": "f.csv"}, "read_data")
        sign_tool_call(analysis_agent, "summarize", {"data": "..."}, "analyze")
        sign_tool_call(
            notify_agent, "send_notification", {"channel": "team", "message": "hi"}, "notify"
        )

        # Cross-capability calls are blocked
        with pytest.raises(CapabilityError):
            sign_tool_call(analysis_agent, "read_csv", {"path": "f.csv"}, "read_data")

        with pytest.raises(CapabilityError):
            sign_tool_call(notify_agent, "summarize", {"data": "..."}, "analyze")
