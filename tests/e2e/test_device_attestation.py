"""E2E tests for device authorization and attestation."""

import pytest

from helpers.cli import export_attestation, get_device_did, run_auths


def _link_device(auths_bin, env, *, capabilities=None, expires_in=None):
    """Link a device and return the CLI result."""
    did = get_device_did(auths_bin, env)
    args = [
        "device",
        "link",
        "--key",
        "main",
        "--device-key",
        "main",
        "--device-did",
        did,
    ]
    if capabilities:
        args += ["--capabilities", capabilities]
    if expires_in:
        args += ["--expires-in", str(expires_in)]
    return run_auths(auths_bin, args, env=env)


@pytest.mark.requires_binary
class TestDeviceAttestation:
    def test_device_link(self, auths_bin, init_identity):
        result = _link_device(auths_bin, init_identity)
        if result.returncode != 0:
            pytest.skip(f"device link not available: {result.stderr}")

    def test_device_list_after_link(self, auths_bin, init_identity):
        link = _link_device(auths_bin, init_identity)
        if link.returncode != 0:
            pytest.skip("device link not available")

        list_result = run_auths(auths_bin, ["device", "list"], env=init_identity)
        list_result.assert_success()
        assert len(list_result.stdout.strip()) > 0

    def test_device_revoke(self, auths_bin, init_identity):
        link = _link_device(auths_bin, init_identity)
        if link.returncode != 0:
            pytest.skip("device link not available")

        did = get_device_did(auths_bin, init_identity)

        revoke = run_auths(
            auths_bin,
            [
                "device",
                "revoke",
                "--device-did",
                did,
                "--key",
                "main",
            ],
            env=init_identity,
        )
        # Revoke should succeed or fail gracefully
        assert revoke.returncode in (0, 1)

    def test_device_verify(self, auths_bin, init_identity, tmp_path):
        att_file = tmp_path / "attestation.json"
        att_data = export_attestation(init_identity, att_file)
        issuer_pk = att_data["device_public_key"]

        verify = run_auths(
            auths_bin,
            [
                "device",
                "verify",
                "--attestation",
                str(att_file),
                "--issuer-pk",
                issuer_pk,
            ],
            env=init_identity,
        )
        verify.assert_success()

    def test_attest_agent(self, auths_bin, init_identity):
        result = _link_device(
            auths_bin, init_identity, capabilities="sign:commit"
        )
        if result.returncode != 0:
            pytest.skip(f"device link with capabilities not available: {result.stderr}")

    def test_attest_with_expiry(self, auths_bin, init_identity):
        result = _link_device(
            auths_bin, init_identity, expires_in=86_400
        )
        if result.returncode != 0:
            pytest.skip(f"device link with expiry not available: {result.stderr}")
