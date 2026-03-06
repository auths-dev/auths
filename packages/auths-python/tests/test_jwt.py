"""Tests for JWT validation helper module (fn-25.10)."""

import pytest

from auths.jwt import AuthsClaims


class TestAuthsClaims:

    def _make_claims(self, **overrides):
        defaults = dict(
            sub="did:keri:EHumanIdentity1234567890",
            keri_prefix="EHumanIdentity",
            capabilities=["sign_commit", "read", "deploy"],
            iss="https://bridge.example.com",
            aud="my-service",
            exp=9999999999,
            iat=1700000000,
            jti="tok_abc123",
            signer_type="Human",
            delegated_by=None,
            witness_quorum=None,
            github_actor=None,
            github_repository=None,
        )
        defaults.update(overrides)
        return AuthsClaims(**defaults)

    def test_fields(self):
        c = self._make_claims()
        assert c.sub == "did:keri:EHumanIdentity1234567890"
        assert c.keri_prefix == "EHumanIdentity"
        assert c.capabilities == ["sign_commit", "read", "deploy"]
        assert c.iss == "https://bridge.example.com"
        assert c.aud == "my-service"
        assert c.signer_type == "Human"

    def test_has_capability(self):
        c = self._make_claims()
        assert c.has_capability("sign_commit") is True
        assert c.has_capability("admin") is False

    def test_has_any_capability(self):
        c = self._make_claims()
        assert c.has_any_capability(["admin", "read"]) is True
        assert c.has_any_capability(["admin", "superadmin"]) is False

    def test_has_all_capabilities(self):
        c = self._make_claims()
        assert c.has_all_capabilities(["sign_commit", "read"]) is True
        assert c.has_all_capabilities(["sign_commit", "admin"]) is False

    def test_is_human(self):
        c = self._make_claims(signer_type="Human")
        assert c.is_human is True
        assert c.is_agent is False

    def test_is_agent(self):
        c = self._make_claims(signer_type="Agent")
        assert c.is_agent is True
        assert c.is_human is False

    def test_is_delegated(self):
        c = self._make_claims(delegated_by=None)
        assert c.is_delegated is False
        c2 = self._make_claims(delegated_by="did:keri:EDelegator")
        assert c2.is_delegated is True

    def test_repr(self):
        c = self._make_claims()
        r = repr(c)
        assert "AuthsClaims" in r
        assert "Human" in r

    def test_repr_many_capabilities(self):
        c = self._make_claims(capabilities=["a", "b", "c", "d", "e"])
        r = repr(c)
        assert "+2" in r

    def test_github_fields(self):
        c = self._make_claims(
            github_actor="octocat",
            github_repository="org/repo",
        )
        assert c.github_actor == "octocat"
        assert c.github_repository == "org/repo"


class TestImports:

    def test_claims_importable_from_top_level(self):
        from auths import AuthsClaims
        assert AuthsClaims is not None

    def test_claims_importable_from_module(self):
        from auths.jwt import AuthsClaims
        assert AuthsClaims is not None

    def test_jwks_client_importable(self):
        from auths.jwt import AuthsJWKSClient
        assert AuthsJWKSClient is not None

    def test_verify_token_importable(self):
        from auths.jwt import verify_token
        assert verify_token is not None
