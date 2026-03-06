"""Tests for policy engine FFI (fn-25.8)."""

import json
import pytest

from auths._native import PyCompiledPolicy, PyEvalContext, PyDecision, compile_policy


class TestCompilePolicy:

    def test_compile_simple_true(self):
        policy = compile_policy('{"op":"True"}')
        assert policy is not None

    def test_compile_not_revoked(self):
        policy = compile_policy('{"op":"NotRevoked"}')
        assert policy is not None

    def test_compile_and_expression(self):
        expr = json.dumps({
            "op": "And",
            "args": [{"op": "NotRevoked"}, {"op": "HasCapability", "args": "sign_commit"}],
        })
        policy = compile_policy(expr)
        assert policy is not None

    def test_compile_invalid_json_raises(self):
        with pytest.raises(ValueError, match="compilation failed"):
            compile_policy("not valid json")

    def test_compile_invalid_op_raises(self):
        with pytest.raises(ValueError):
            compile_policy('{"op":"Bogus"}')


class TestEvalContext:

    def test_create_basic(self):
        ctx = PyEvalContext(
            issuer="did:keri:ETestIssuer",
            subject="did:key:zTestSubject",
        )
        assert ctx is not None

    def test_create_with_capabilities(self):
        ctx = PyEvalContext(
            issuer="did:keri:ETestIssuer",
            subject="did:key:zTestSubject",
            capabilities=["sign_commit", "read"],
        )
        assert ctx is not None

    def test_create_with_all_kwargs(self):
        ctx = PyEvalContext(
            issuer="did:keri:ETestIssuer",
            subject="did:key:zTestSubject",
            capabilities=["sign"],
            role="admin",
            revoked=False,
            expires_at="2030-01-01T00:00:00Z",
            repo="org/repo",
            environment="production",
            signer_type="Human",
            delegated_by="did:keri:EDelegate",
            chain_depth=1,
        )
        r = repr(ctx)
        assert "EvalContext" in r

    def test_invalid_issuer_did_raises(self):
        with pytest.raises(ValueError, match="issuer"):
            PyEvalContext(issuer="not-a-did", subject="did:key:zTest")

    def test_invalid_signer_type_raises(self):
        with pytest.raises(ValueError, match="signer_type"):
            PyEvalContext(
                issuer="did:keri:ETest",
                subject="did:key:zTest",
                signer_type="InvalidType",
            )


class TestPolicyCheck:

    def test_allow_true_policy(self):
        policy = compile_policy('{"op":"True"}')
        ctx = PyEvalContext(issuer="did:keri:ETest", subject="did:key:zTest")
        decision = policy.check(ctx)
        assert decision.outcome == "allow"
        assert decision.allowed
        assert not decision.denied
        assert bool(decision) is True

    def test_deny_false_policy(self):
        policy = compile_policy('{"op":"False"}')
        ctx = PyEvalContext(issuer="did:keri:ETest", subject="did:key:zTest")
        decision = policy.check(ctx)
        assert decision.outcome == "deny"
        assert decision.denied
        assert not decision.allowed
        assert bool(decision) is False

    def test_capability_present(self):
        policy = compile_policy('{"op":"HasCapability","args":"sign_commit"}')
        ctx = PyEvalContext(
            issuer="did:keri:ETest",
            subject="did:key:zTest",
            capabilities=["sign_commit"],
        )
        decision = policy.check(ctx)
        assert decision.allowed

    def test_capability_missing(self):
        policy = compile_policy('{"op":"HasCapability","args":"sign_commit"}')
        ctx = PyEvalContext(
            issuer="did:keri:ETest",
            subject="did:key:zTest",
            capabilities=["read"],
        )
        decision = policy.check(ctx)
        assert decision.denied

    def test_not_revoked_passes(self):
        policy = compile_policy('{"op":"NotRevoked"}')
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest", revoked=False,
        )
        assert policy.check(ctx).allowed

    def test_revoked_denied(self):
        policy = compile_policy('{"op":"NotRevoked"}')
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest", revoked=True,
        )
        assert policy.check(ctx).denied


class TestDecision:

    def test_repr(self):
        policy = compile_policy('{"op":"True"}')
        ctx = PyEvalContext(issuer="did:keri:ETest", subject="did:key:zTest")
        d = policy.check(ctx)
        r = repr(d)
        assert "Decision" in r
        assert "allow" in r

    def test_has_message(self):
        policy = compile_policy('{"op":"True"}')
        ctx = PyEvalContext(issuer="did:keri:ETest", subject="did:key:zTest")
        d = policy.check(ctx)
        assert isinstance(d.message, str)
        assert len(d.message) > 0


class TestToJson:

    def test_round_trip(self):
        original = '{"op":"NotRevoked"}'
        policy = compile_policy(original)
        exported = policy.to_json()
        policy2 = compile_policy(exported)
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest", revoked=False,
        )
        assert policy2.check(ctx).allowed


class TestPolicyBuilder:

    def test_standard_factory(self):
        from auths.policy import PolicyBuilder
        policy = PolicyBuilder.standard("sign_commit").build()
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest",
            capabilities=["sign_commit"],
        )
        assert policy.check(ctx).allowed

    def test_standard_missing_capability(self):
        from auths.policy import PolicyBuilder
        policy = PolicyBuilder.standard("admin").build()
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest",
            capabilities=["sign"],
        )
        assert not policy.check(ctx).allowed

    def test_builder_chaining(self):
        from auths.policy import PolicyBuilder
        policy = (
            PolicyBuilder()
            .not_revoked()
            .require_capability("sign_commit")
            .require_issuer("did:keri:EOrg")
            .require_human()
            .max_chain_depth(3)
            .build()
        )
        assert policy is not None

    def test_builder_to_json_roundtrip(self):
        from auths.policy import PolicyBuilder
        builder = PolicyBuilder().not_revoked().require_capability("sign")
        json_str = builder.to_json()
        policy = compile_policy(json_str)
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest",
            capabilities=["sign"],
        )
        assert policy.check(ctx).allowed

    def test_any_of_combinator(self):
        from auths.policy import PolicyBuilder
        admin = PolicyBuilder.standard("admin")
        deployer = PolicyBuilder.standard("sign").require_issuer("did:keri:EOrg")
        policy = PolicyBuilder.any_of(admin, deployer).build()
        ctx_admin = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest",
            capabilities=["admin"],
        )
        assert policy.check(ctx_admin).allowed

    def test_empty_builder_raises(self):
        from auths.policy import PolicyBuilder
        with pytest.raises(ValueError, match="empty policy"):
            PolicyBuilder().build()

    def test_repr(self):
        from auths.policy import PolicyBuilder
        builder = PolicyBuilder().not_revoked().require_capability("sign")
        r = repr(builder)
        assert "NotRevoked" in r
        assert "HasCapability" in r

    def test_len(self):
        from auths.policy import PolicyBuilder
        builder = PolicyBuilder().not_revoked().not_expired()
        assert len(builder) == 2

    def test_negate(self):
        from auths.policy import PolicyBuilder
        builder = PolicyBuilder().not_revoked()
        negated = builder.negate()
        policy = negated.build()
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest", revoked=False,
        )
        assert policy.check(ctx).denied

    def test_or_policy(self):
        from auths.policy import PolicyBuilder
        a = PolicyBuilder().require_capability("admin")
        b = PolicyBuilder().require_capability("superadmin")
        policy = a.or_policy(b).build()
        ctx = PyEvalContext(
            issuer="did:keri:ETest", subject="did:key:zTest",
            capabilities=["superadmin"],
        )
        assert policy.check(ctx).allowed


class TestImports:

    def test_compile_policy_importable(self):
        from auths.policy import compile_policy
        assert compile_policy is not None

    def test_eval_context_importable(self):
        from auths.policy import EvalContext
        assert EvalContext is not None

    def test_decision_importable(self):
        from auths.policy import Decision
        assert Decision is not None

    def test_policy_builder_importable(self):
        from auths.policy import PolicyBuilder
        assert PolicyBuilder is not None

    def test_policy_builder_from_top_level(self):
        from auths import PolicyBuilder
        assert PolicyBuilder is not None
