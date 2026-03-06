"""E2E tests for approval gate CLI commands."""

import pytest

from helpers.cli import run_auths


@pytest.mark.requires_binary
class TestApprovalGates:
    def test_list_empty_approvals(self, auths_bin, isolated_env, init_identity):
        result = run_auths(
            auths_bin,
            ["approval", "list"],
            env=isolated_env,
        )
        result.assert_success()
        assert "No pending approval request" in result.stdout

    def test_grant_unknown_request(self, auths_bin, isolated_env, init_identity):
        result = run_auths(
            auths_bin,
            ["approval", "grant", "--request", "deadbeef" * 8],
            env=isolated_env,
        )
        # Placeholder: currently prints a message and exits 0.
        # When wired to storage, this should return an error for unknown request.
        assert result.returncode == 0

    def test_grant_with_note(self, auths_bin, isolated_env, init_identity):
        result = run_auths(
            auths_bin,
            [
                "approval",
                "grant",
                "--request",
                "abcd1234" * 8,
                "--note",
                "LGTM",
            ],
            env=isolated_env,
        )
        assert result.returncode == 0

    def test_approval_help(self, auths_bin, isolated_env):
        result = run_auths(
            auths_bin,
            ["approval", "--help"],
            env=isolated_env,
        )
        result.assert_success()
        assert "approval" in result.stdout.lower()

    def test_approval_list_help(self, auths_bin, isolated_env):
        result = run_auths(
            auths_bin,
            ["approval", "list", "--help"],
            env=isolated_env,
        )
        result.assert_success()
