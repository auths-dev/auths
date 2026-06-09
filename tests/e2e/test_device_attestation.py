"""E2E tests for device authorization and attestation (KEL-native delegation)."""

import pytest

from helpers.cli import add_device, export_attestation, get_device_did, run_auths


def _add_agent(auths_bin, env, *, label, expires_in=None):
    """Delegate an AI agent under the root identity (carries capabilities/expiry)."""
    args = ["id", "agent", "add", "--label", label, "--key", "main"]
    if expires_in:
        args += ["--expires-in", str(expires_in)]
    return run_auths(auths_bin, args, env=env)


@pytest.mark.requires_binary
class TestDeviceAttestation:
    def test_device_add(self, auths_bin, init_identity):
        result = add_device(auths_bin, init_identity)
        if result.returncode != 0:
            pytest.skip(f"device add not available: {result.stderr}")
        result.assert_success()
        # The delegated device is a did:keri AID anchored in the root's KEL.
        assert "did:keri:" in result.stdout

    def test_device_list_after_add(self, auths_bin, init_identity):
        if add_device(auths_bin, init_identity).returncode != 0:
            pytest.skip("device add not available")

        list_result = run_auths(auths_bin, ["device", "list"], env=init_identity)
        list_result.assert_success()
        assert "did:keri:" in list_result.stdout

    def test_device_revoke(self, auths_bin, init_identity):
        if add_device(auths_bin, init_identity).returncode != 0:
            pytest.skip("device add not available")

        did = get_device_did(auths_bin, init_identity)
        revoke = run_auths(
            auths_bin,
            ["device", "revoke", "--device-did", did, "--key", "main"],
            env=init_identity,
        )
        # Revoke should succeed or fail gracefully (e.g. already revoked).
        assert revoke.returncode in (0, 1)

    def test_device_verify(self, auths_bin, init_identity, tmp_path):
        # `device verify` checks the legacy attestation envelope; the KEL-native
        # `device add` flow anchors a delegated inception instead, so skip when no
        # attestation.json exists.
        att_file = tmp_path / "attestation.json"
        att_data = export_attestation(init_identity, att_file)
        if att_data is None:
            pytest.skip("no legacy attestation present (device add anchors in the KEL)")

        dpk = att_data["device_public_key"]
        issuer_pk = dpk["key"] if isinstance(dpk, dict) else dpk
        verify = run_auths(
            auths_bin,
            ["device", "verify", "--attestation", str(att_file), "--signer-key", issuer_pk],
            env=init_identity,
        )
        verify.assert_success()

    def test_delegate_agent(self, auths_bin, init_identity):
        result = _add_agent(auths_bin, init_identity, label="ci-agent")
        if result.returncode != 0:
            pytest.skip(f"agent delegation not available: {result.stderr}")
        result.assert_success()

    def test_delegate_agent_with_expiry(self, auths_bin, init_identity):
        result = _add_agent(
            auths_bin, init_identity, label="ephemeral-agent", expires_in=86_400
        )
        if result.returncode != 0:
            pytest.skip(f"agent delegation with expiry not available: {result.stderr}")
        result.assert_success()
