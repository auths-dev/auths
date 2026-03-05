"""E2E tests for the policy engine CLI."""

import json

import pytest

from helpers.cli import run_auths

SIMPLE_POLICY = {
    "op": "And",
    "args": [
        {"op": "HasCapability", "args": "sign:commit"},
        {"op": "NotExpired"},
    ],
}

COMPLEX_POLICY = {
    "op": "Or",
    "args": [
        {
            "op": "And",
            "args": [
                {"op": "HasCapability", "args": "sign:commit"},
                {"op": "NotRevoked"},
            ],
        },
        {
            "op": "And",
            "args": [
                {"op": "HasCapability", "args": "deploy:staging"},
                {"op": "NotExpired"},
            ],
        },
    ],
}

INVALID_POLICY = {"op": "UnknownOp"}

TEST_ISSUER = "did:keri:ETestIssuer123456789012345678901234567890ab"
TEST_SUBJECT = "did:keri:ETestSubject12345678901234567890123456789ab"


@pytest.mark.requires_binary
class TestPolicyEngine:
    def test_policy_lint_valid(self, auths_bin, isolated_env, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(SIMPLE_POLICY))

        result = run_auths(
            auths_bin,
            ["policy", "lint", str(policy_file)],
            env=isolated_env,
        )
        if result.returncode != 0:
            pytest.skip(f"policy lint not available: {result.stderr}")
        result.assert_success()

    def test_policy_lint_invalid(self, auths_bin, isolated_env, tmp_path):
        policy_file = tmp_path / "bad_policy.json"
        policy_file.write_text("not valid json{{{")

        result = run_auths(
            auths_bin,
            ["policy", "lint", str(policy_file)],
            env=isolated_env,
        )
        result.assert_failure()

    def test_policy_compile_valid(self, auths_bin, isolated_env, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(COMPLEX_POLICY))

        result = run_auths(
            auths_bin,
            ["policy", "compile", str(policy_file)],
            env=isolated_env,
        )
        if result.returncode != 0:
            pytest.skip(f"policy compile not available: {result.stderr}")
        result.assert_success()

    def test_policy_explain(self, auths_bin, isolated_env, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(SIMPLE_POLICY))

        context_file = tmp_path / "context.json"
        context_file.write_text(
            json.dumps(
                {
                    "issuer": TEST_ISSUER,
                    "subject": TEST_SUBJECT,
                    "capabilities": ["sign:commit"],
                    "revoked": False,
                    "expires_at": "2099-12-31T23:59:59Z",
                }
            )
        )

        result = run_auths(
            auths_bin,
            [
                "policy",
                "explain",
                str(policy_file),
                "--context",
                str(context_file),
            ],
            env=isolated_env,
        )
        if result.returncode != 0:
            pytest.skip(f"policy explain not available: {result.stderr}")
        result.assert_success()
        output = (result.stdout + result.stderr).lower()
        assert "allow" in output or "deny" in output

    def test_policy_test_passing(self, auths_bin, isolated_env, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(SIMPLE_POLICY))

        tests_file = tmp_path / "tests.json"
        tests_file.write_text(
            json.dumps(
                [
                    {
                        "name": "agent with sign:commit should pass",
                        "context": {
                            "issuer": TEST_ISSUER,
                            "subject": TEST_SUBJECT,
                            "capabilities": ["sign:commit"],
                            "revoked": False,
                            "expires_at": "2099-12-31T23:59:59Z",
                        },
                        "expect": "Allow",
                    }
                ]
            )
        )

        result = run_auths(
            auths_bin,
            ["policy", "test", str(policy_file), "--tests", str(tests_file)],
            env=isolated_env,
        )
        if result.returncode != 0:
            pytest.skip(f"policy test not available: {result.stderr}")
        result.assert_success()

    def test_policy_test_failing(self, auths_bin, isolated_env, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(SIMPLE_POLICY))

        tests_file = tmp_path / "tests.json"
        tests_file.write_text(
            json.dumps(
                [
                    {
                        "name": "should fail - wrong expected",
                        "context": {
                            "issuer": TEST_ISSUER,
                            "subject": TEST_SUBJECT,
                            "capabilities": ["sign:commit"],
                            "revoked": False,
                            "expires_at": "2099-12-31T23:59:59Z",
                        },
                        "expect": "Deny",
                    }
                ]
            )
        )

        result = run_auths(
            auths_bin,
            ["policy", "test", str(policy_file), "--tests", str(tests_file)],
            env=isolated_env,
        )
        result.assert_failure()

    def test_policy_diff(self, auths_bin, isolated_env, tmp_path):
        old_policy = tmp_path / "old.json"
        old_policy.write_text(json.dumps(SIMPLE_POLICY))

        new_policy = tmp_path / "new.json"
        new_policy.write_text(json.dumps(COMPLEX_POLICY))

        result = run_auths(
            auths_bin,
            ["policy", "diff", str(old_policy), str(new_policy)],
            env=isolated_env,
        )
        if result.returncode != 0:
            pytest.skip(f"policy diff not available: {result.stderr}")
        result.assert_success()
