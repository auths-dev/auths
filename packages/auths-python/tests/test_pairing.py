"""Tests for programmatic device pairing service."""
import threading

import pytest

from auths import Auths
from auths._errors import PairingError
from auths.pairing import PairingResult, PairingSession


def test_create_session(tmp_path):
    """Controller can create a pairing session with a running server."""
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="controller")

    session = client.pairing.create_session(
        bind_address="127.0.0.1",
        enable_mdns=False,
        capabilities=["sign:commit"],
    )
    assert len(session.short_code) == 6
    assert session.endpoint.startswith("http://127.0.0.1:")
    assert session.controller_did.startswith("did:keri:")
    assert isinstance(session, PairingSession)
    session.stop()


def test_session_stop_is_idempotent(tmp_path):
    """Stopping a session twice does not raise."""
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="controller")

    session = client.pairing.create_session(
        bind_address="127.0.0.1", enable_mdns=False,
    )
    session.stop()
    session.stop()


def test_session_context_manager(tmp_path):
    """Context manager auto-stops the session."""
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="controller")

    with client.pairing.create_session(
        bind_address="127.0.0.1", enable_mdns=False,
    ) as session:
        assert session.endpoint.startswith("http://")


def test_wait_for_response_timeout(tmp_path):
    """wait_for_response raises on timeout."""
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="controller")

    session = client.pairing.create_session(
        bind_address="127.0.0.1",
        enable_mdns=False,
        timeout_secs=5,
    )

    with pytest.raises((PairingError, RuntimeError)):
        session.wait_for_response(timeout_secs=1)

    session.stop()


def test_pairing_roundtrip(tmp_path):
    """Full pairing flow: controller creates session, device joins."""
    controller_home = tmp_path / "controller"
    controller_home.mkdir()
    device_home = tmp_path / "device"
    device_home.mkdir()

    controller = Auths(
        repo_path=str(controller_home / ".auths"), passphrase="Test-pass-123",
    )
    controller.identities.create(label="controller")

    device = Auths(
        repo_path=str(device_home / ".auths"), passphrase="Test-pass-123",
    )
    device.identities.create(label="device")

    session = controller.pairing.create_session(
        bind_address="127.0.0.1",
        enable_mdns=False,
        capabilities=["sign:commit"],
        timeout_secs=30,
    )

    join_result = [None]
    join_error = [None]

    def device_join():
        try:
            join_result[0] = device.pairing.join(
                session.short_code,
                endpoint=session.endpoint,
                token=session.token,
                device_name="test-device",
            )
        except Exception as e:
            join_error[0] = e

    t = threading.Thread(target=device_join)
    t.start()

    response = session.wait_for_response(timeout_secs=10)
    assert response.device_did.startswith("did:key:")

    result = controller.pairing.complete(session, response)
    assert result.attestation_rid is not None
    assert isinstance(result, PairingResult)

    t.join(timeout=10)
    assert join_error[0] is None
    assert join_result[0] is not None

    session.stop()


def test_pairing_with_scoped_capabilities(tmp_path):
    """Paired device receives only the granted capabilities."""
    controller_home = tmp_path / "controller"
    controller_home.mkdir()
    device_home = tmp_path / "device"
    device_home.mkdir()

    controller = Auths(
        repo_path=str(controller_home / ".auths"), passphrase="Test-pass-123",
    )
    controller.identities.create(label="controller")

    device = Auths(
        repo_path=str(device_home / ".auths"), passphrase="Test-pass-123",
    )
    device.identities.create(label="ci-runner")

    session = controller.pairing.create_session(
        bind_address="127.0.0.1",
        enable_mdns=False,
        capabilities=["sign:artifact"],
        timeout_secs=30,
    )

    def device_join():
        device.pairing.join(
            session.short_code,
            endpoint=session.endpoint,
            token=session.token,
            device_name="ci-runner-01",
        )

    t = threading.Thread(target=device_join)
    t.start()

    response = session.wait_for_response(timeout_secs=10)
    result = controller.pairing.complete(session, response)
    assert result.attestation_rid is not None

    t.join(timeout=10)
    session.stop()
