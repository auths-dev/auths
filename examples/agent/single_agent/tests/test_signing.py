"""Tests for signing — produces real did:keri:E... identities."""

import json
from unittest.mock import patch

from single_agent import signing


def test_make_agent_returns_keri_did(tmp_path):
    with patch.object(signing, "DEMO_REPO", tmp_path):
        did, pub_hex, priv_hex = signing.make_agent()
    assert did.startswith("did:keri:E")
    assert len(pub_hex) == 64
    assert len(priv_hex) == 64


def test_sign_tool_call_returns_valid_json(tmp_path):
    with patch.object(signing, "DEMO_REPO", tmp_path):
        did, pub_hex, priv_hex = signing.make_agent()
    envelope_json = signing.sign_tool_call(priv_hex, did, "read_csv", {"path": "data/sales.csv"})
    envelope = json.loads(envelope_json)
    assert envelope["type"] == "tool_call"
    assert envelope["identity"] == did
    assert "signature" in envelope


def test_sign_tool_call_payload_contains_tool_and_args(tmp_path):
    with patch.object(signing, "DEMO_REPO", tmp_path):
        did, _, priv_hex = signing.make_agent()
    args = {"path": "data/sales.csv"}
    envelope_json = signing.sign_tool_call(priv_hex, did, "read_csv", args)
    envelope = json.loads(envelope_json)
    payload = envelope["payload"]
    assert payload["tool"] == "read_csv"
    assert payload["args"] == args


def test_multiple_tool_calls_all_verify(tmp_path):
    """Multiple sign calls must all verify — the in-process key is used, not SDK keychain."""
    from auths import verify_action_envelope

    with patch.object(signing, "DEMO_REPO", tmp_path):
        did, pub_hex, priv_hex = signing.make_agent()

    for tool in ["read_csv", "summarize", "send_notification"]:
        env_json = signing.sign_tool_call(priv_hex, did, tool, {"x": "y"})
        result = verify_action_envelope(env_json, pub_hex)
        assert result.valid, f"{tool} failed: {result.error}"


def test_tampered_envelope_fails_verification(tmp_path):
    from auths import verify_action_envelope

    with patch.object(signing, "DEMO_REPO", tmp_path):
        did, pub_hex, priv_hex = signing.make_agent()

    envelope_json = signing.sign_tool_call(priv_hex, did, "read_csv", {"path": "f.csv"})
    envelope = json.loads(envelope_json)
    envelope["payload"]["tool"] = "delete_database"
    tampered = json.dumps(envelope)

    result = verify_action_envelope(tampered, pub_hex)
    assert not result.valid
