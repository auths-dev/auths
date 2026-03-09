"""Policy engine — compile, evaluate, enforce authorization rules."""

from __future__ import annotations

import json
from dataclasses import dataclass

from auths._native import (
    PyCompiledPolicy,
    PyDecision,
    PyEvalContext,
    compile_policy,
)

__all__ = [
    "CompiledPolicy",
    "Decision",
    "EvalContext",
    "PolicyBuilder",
    "compile_policy",
]

CompiledPolicy = PyCompiledPolicy
EvalContext = PyEvalContext


@dataclass
class Decision:
    """Result of evaluating a policy against a context.

    Supports boolean evaluation: `if decision:` is equivalent to `if decision.allowed`.
    """

    outcome: str
    """Policy result: `"allow"` or `"deny"`."""
    reason: str
    """Short machine-readable reason (e.g. `"revoked"`, `"capability_missing"`)."""
    message: str
    """Human-readable explanation of the decision."""

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def denied(self) -> bool:
        return self.outcome == "deny"

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        return f"Decision(outcome='{self.outcome}', reason='{self.reason}')"


class PolicyBuilder:
    """Fluent builder for Auths access policies.

    Usage:
        policy = PolicyBuilder.standard("sign_commit").build()

        policy = (PolicyBuilder()
            .not_revoked()
            .not_expired()
            .require_capability("sign_commit")
            .require_issuer("did:keri:EOrg123")
            .build())
    """

    def __init__(self):
        self._predicates: list[dict] = []

    @classmethod
    def standard(cls, capability: str) -> PolicyBuilder:
        """The "80% policy": not revoked, not expired, requires one capability."""
        return cls().not_revoked().not_expired().require_capability(capability)

    @classmethod
    def any_of(cls, *builders: PolicyBuilder) -> PolicyBuilder:
        """Create a policy that passes if ANY of the given policies pass."""
        result = cls()
        or_args = [{"op": "And", "args": b._predicates} for b in builders]
        result._predicates = [{"op": "Or", "args": or_args}]
        return result

    def not_revoked(self) -> PolicyBuilder:
        self._predicates.append({"op": "NotRevoked"})
        return self

    def not_expired(self) -> PolicyBuilder:
        self._predicates.append({"op": "NotExpired"})
        return self

    def expires_after(self, seconds: int) -> PolicyBuilder:
        """Require at least `seconds` of remaining validity."""
        self._predicates.append({"op": "ExpiresAfter", "args": seconds})
        return self

    def issued_within(self, seconds: int) -> PolicyBuilder:
        """Require the attestation was issued within `seconds` ago."""
        self._predicates.append({"op": "IssuedWithin", "args": seconds})
        return self

    def require_capability(self, cap: str) -> PolicyBuilder:
        self._predicates.append({"op": "HasCapability", "args": cap})
        return self

    def require_all_capabilities(self, caps: list[str]) -> PolicyBuilder:
        for cap in caps:
            self.require_capability(cap)
        return self

    def require_any_capability(self, caps: list[str]) -> PolicyBuilder:
        or_args = [{"op": "HasCapability", "args": c} for c in caps]
        self._predicates.append({"op": "Or", "args": or_args})
        return self

    def require_issuer(self, did: str) -> PolicyBuilder:
        self._predicates.append({"op": "IssuerIs", "args": did})
        return self

    def require_issuer_in(self, dids: list[str]) -> PolicyBuilder:
        or_args = [{"op": "IssuerIs", "args": d} for d in dids]
        self._predicates.append({"op": "Or", "args": or_args})
        return self

    def require_subject(self, did: str) -> PolicyBuilder:
        self._predicates.append({"op": "SubjectIs", "args": did})
        return self

    def require_delegated_by(self, did: str) -> PolicyBuilder:
        self._predicates.append({"op": "DelegatedBy", "args": did})
        return self

    def require_agent(self) -> PolicyBuilder:
        self._predicates.append({"op": "IsAgent"})
        return self

    def require_human(self) -> PolicyBuilder:
        self._predicates.append({"op": "IsHuman"})
        return self

    def require_workload(self) -> PolicyBuilder:
        self._predicates.append({"op": "IsWorkload"})
        return self

    def require_repo(self, repo: str) -> PolicyBuilder:
        self._predicates.append({"op": "RepoIs", "args": repo})
        return self

    def require_env(self, env: str) -> PolicyBuilder:
        self._predicates.append({"op": "EnvIs", "args": env})
        return self

    def max_chain_depth(self, depth: int) -> PolicyBuilder:
        self._predicates.append({"op": "MaxChainDepth", "args": depth})
        return self

    def or_policy(self, other: PolicyBuilder) -> PolicyBuilder:
        """Combine with another policy using OR logic."""
        return PolicyBuilder.any_of(self, other)

    def negate(self) -> PolicyBuilder:
        """Negate the entire policy (all current predicates)."""
        result = PolicyBuilder()
        result._predicates = [{"op": "Not", "args": {"op": "And", "args": self._predicates}}]
        return result

    def build(self) -> CompiledPolicy:
        """Compile the policy. Raises ValueError on invalid combinations."""
        if not self._predicates:
            raise ValueError(
                "Cannot build an empty policy. Add at least one predicate, "
                "or use PolicyBuilder.standard('capability') for the common case."
            )
        expr = {"op": "And", "args": self._predicates}
        return compile_policy(json.dumps(expr))

    def to_json(self) -> str:
        """Export the policy as JSON (for storage in config files)."""
        if not self._predicates:
            raise ValueError("Cannot export an empty policy.")
        expr = {"op": "And", "args": self._predicates}
        return json.dumps(expr)

    def __repr__(self) -> str:
        if not self._predicates:
            return "PolicyBuilder(empty)"
        pred_names = [p.get("op", "?") for p in self._predicates]
        return f"PolicyBuilder([{', '.join(pred_names)}])"

    def __len__(self) -> int:
        return len(self._predicates)
