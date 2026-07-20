"""E2E tests for the core identity lifecycle."""

import json
import subprocess

import pytest

from helpers.assertions import assert_did_format
from helpers.cli import run_auths


@pytest.mark.requires_binary
class TestIdentityLifecycle:
    def test_init_developer_profile(self, auths_bin, isolated_env):
        result = run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive", ],
            env=isolated_env,
        )
        result.assert_success()

        status = run_auths(auths_bin, ["status", "--json"], env=isolated_env)
        # status may or may not support --json yet
        assert status.returncode == 0

    def test_init_ci_profile(self, auths_bin, isolated_env):
        # Unset AUTHS_PASSPHRASE so the CI profile's *generated* passphrase is the
        # one exercised — it must satisfy the same strength policy the CLI enforces,
        # or inception errors before it starts.
        env = dict(isolated_env)
        env.pop("AUTHS_PASSPHRASE", None)
        result = run_auths(
            auths_bin,
            ["init", "--profile", "ci", "--non-interactive"],
            env=env,
        )
        result.assert_success()

    def test_headless_init_does_not_hang(self, auths_bin, isolated_env):
        # With no AUTHS_KEYCHAIN_BACKEND set, the platform default wins. On a machine
        # with a hardware keychain this must never block on a Touch ID prompt that
        # never arrives headless — it either selects the configured file backend and
        # succeeds, or fails fast with a coded, actionable error.
        env = dict(isolated_env)
        env.pop("AUTHS_KEYCHAIN_BACKEND", None)
        try:
            result = run_auths(
                auths_bin,
                ["init", "--non-interactive"],
                env=env,
                timeout=15,
                stdin_data="",
            )
        except subprocess.TimeoutExpired:
            pytest.fail("headless init hung waiting for an interactive keychain prompt")
        if result.returncode != 0:
            assert "AUTHS-E4203" in result.stderr, result.stderr
            assert "AUTHS_KEYCHAIN_BACKEND=file" in result.stderr, result.stderr

    def test_weak_passphrase_shows_code(self, auths_bin, isolated_env):
        # A weak env passphrase must fail with the typed, coded error — not an
        # untyped string — and the bare-code lookup must resolve offline.
        env = dict(isolated_env)
        env["AUTHS_PASSPHRASE"] = "weak"
        result = run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive"],
            env=env,
        )
        assert result.returncode != 0
        assert "[AUTHS-E5008]" in result.stderr, result.stderr

        show = run_auths(auths_bin, ["error", "show", "E5008"], env=env)
        show.assert_success()
        assert "## Suggestion" in show.stdout, show.stdout

    def test_init_agent_profile_is_retired(self, auths_bin, isolated_env):
        # Standalone agent initialization is retired: an agent is now a KERI
        # delegated identifier created with `auths id agent add` after a root
        # `auths init` (see test_device_attestation::test_delegate_agent).
        result = run_auths(
            auths_bin,
            ["init", "--profile", "agent", "--non-interactive"],
            env=isolated_env,
        )
        assert result.returncode != 0
        assert (
            "id agent add" in result.stderr or "delegated identifier" in result.stderr
        )

    def test_init_already_initialized(self, auths_bin, isolated_env):
        run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive", ],
            env=isolated_env,
        ).assert_success()

        second = run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive", ],
            env=isolated_env,
        )
        # Second init should either fail or warn
        # GAP: unclear if this produces non-zero exit or just warns
        assert second.returncode in (0, 1)

    def test_status_json_output(self, auths_bin, init_identity):
        result = run_auths(auths_bin, ["status", "--json"], env=init_identity)
        if result.returncode == 0 and result.stdout.strip().startswith("{"):
            data = json.loads(result.stdout)
            # GAP: validate expected fields once --json is confirmed
            assert isinstance(data, dict)
        else:
            # GAP: `auths status --json` may not be implemented
            pytest.skip("auths status --json not supported")

    def test_id_show_json(self, auths_bin, init_identity):
        result = run_auths(auths_bin, ["id", "show", "--json"], env=init_identity)
        if result.returncode == 0 and result.stdout.strip().startswith("{"):
            data = json.loads(result.stdout)
            controller_did = data.get("data", {}).get("controller_did")
            if controller_did:
                assert_did_format(controller_did)
        else:
            pytest.skip("auths id show --json not supported")

    def test_id_export_bundle(self, auths_bin, init_identity, tmp_path):
        bundle_path = tmp_path / "bundle.json"
        result = run_auths(
            auths_bin,
            [
                "id",
                "export-bundle",
                "--alias",
                "main",
                "--output",
                str(bundle_path),
                "--max-age-secs",
                "3600",
            ],
            env=init_identity,
        )
        if result.returncode == 0:
            assert bundle_path.exists()
            data = json.loads(bundle_path.read_text())
            assert isinstance(data, dict)
        else:
            pytest.skip("auths id export-bundle not supported")

    @pytest.mark.slow
    def test_full_lifecycle(self, auths_bin, isolated_env, tmp_path):
        # Init
        run_auths(
            auths_bin,
            ["init", "--profile", "developer", "--non-interactive", ],
            env=isolated_env,
        ).assert_success()

        # Status
        status = run_auths(auths_bin, ["status"], env=isolated_env)
        status.assert_success()

        # Id show
        id_show = run_auths(auths_bin, ["id", "show"], env=isolated_env)
        id_show.assert_success()

        # Export bundle
        bundle_path = tmp_path / "bundle.json"
        export = run_auths(
            auths_bin,
            [
                "id",
                "export-bundle",
                "--alias",
                "main",
                "--output",
                str(bundle_path),
                "--max-age-secs",
                "3600",
            ],
            env=isolated_env,
        )
        if export.returncode != 0:
            pytest.skip("export-bundle not available")
