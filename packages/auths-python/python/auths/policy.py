"""Policy engine — compile, evaluate, enforce authorization rules.

EvalContext DID Format Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both ``EvalContext.issuer`` and ``EvalContext.subject`` must be valid DID strings:

- **Identity DIDs**: ``did:keri:E...`` — for organizations and individuals.
- **Device DIDs**: ``did:key:z...`` — for device keys and signing keys.

The Rust policy engine parses both fields into ``CanonicalDid`` values. Both
``did:keri:`` and ``did:key:`` formats are accepted. Invalid DID strings will
cause evaluation to fail with a parse error.

Example::

    ctx = EvalContext(
        issuer="did:keri:EOrg123",       # organization identity
        subject="did:key:z6MkDevice",    # device key
        capabilities=["sign_commit"],
    )
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Optional

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
    "Outcome",
    "PolicyBuilder",
    "ReasonCode",
    "compile_policy",
]

CompiledPolicy = PyCompiledPolicy
EvalContext = PyEvalContext


class Outcome(enum.Enum):
    """Authorization outcome from a policy evaluation.

    Values match the Rust ``Outcome`` enum in ``auths-policy/src/decision.rs``.
    """

    ALLOW = "Allow"
    DENY = "Deny"
    INDETERMINATE = "Indeterminate"
    REQUIRES_APPROVAL = "RequiresApproval"
    MISSING_CREDENTIAL = "MissingCredential"


class ReasonCode(enum.Enum):
    """Machine-readable reason code for stable logging and alerting.

    Values match the Rust ``ReasonCode`` enum in ``auths-policy/src/decision.rs``.
    """

    UNCONDITIONAL = "Unconditional"
    ALL_CHECKS_PASSED = "AllChecksPassed"
    CAPABILITY_PRESENT = "CapabilityPresent"
    CAPABILITY_MISSING = "CapabilityMissing"
    ISSUER_MATCH = "IssuerMatch"
    ISSUER_MISMATCH = "IssuerMismatch"
    REVOKED = "Revoked"
    EXPIRED = "Expired"
    INSUFFICIENT_TTL = "InsufficientTtl"
    ISSUED_TOO_LONG_AGO = "IssuedTooLongAgo"
    ROLE_MISMATCH = "RoleMismatch"
    SCOPE_MISMATCH = "ScopeMismatch"
    CHAIN_TOO_DEEP = "ChainTooDeep"
    DELEGATION_MISMATCH = "DelegationMismatch"
    ATTR_MISMATCH = "AttrMismatch"
    MISSING_FIELD = "MissingField"
    RECURSION_EXCEEDED = "RecursionExceeded"
    SHORT_CIRCUIT = "ShortCircuit"
    COMBINATOR_RESULT = "CombinatorResult"
    WORKLOAD_MISMATCH = "WorkloadMismatch"
    WITNESS_QUORUM_NOT_MET = "WitnessQuorumNotMet"
    SIGNER_TYPE_MATCH = "SignerTypeMatch"
    SIGNER_TYPE_MISMATCH = "SignerTypeMismatch"
    APPROVAL_REQUIRED = "ApprovalRequired"
    APPROVAL_GRANTED = "ApprovalGranted"
    APPROVAL_EXPIRED = "ApprovalExpired"
    APPROVAL_ALREADY_USED = "ApprovalAlreadyUsed"
    APPROVAL_REQUEST_MISMATCH = "ApprovalRequestMismatch"


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
    def outcome_enum(self) -> Outcome:
        """Parse the outcome string into a typed :class:`Outcome` enum."""
        return Outcome(self.outcome)

    @property
    def reason_enum(self) -> ReasonCode:
        """Parse the reason string into a typed :class:`ReasonCode` enum."""
        return ReasonCode(self.reason)

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow" or self.outcome == "Allow"

    @property
    def denied(self) -> bool:
        return self.outcome == "deny" or self.outcome == "Deny"

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        return f"Decision(outcome='{self.outcome}', reason='{self.reason}')"


def eval_context_from_commit_result(
    commit_result,
    issuer: str,
    capabilities: Optional[list[str]] = None,
) -> dict:
    """Build an EvalContext dict from a ``CommitResult``.

    Extracts the signer hex from the commit result and converts it to a
    ``did:key:`` DID for use as the ``subject`` field.

    Args:
        commit_result: A ``CommitResult`` from ``verify_commit_range()``.
        issuer: The issuer DID (``did:keri:...``).
        capabilities: Optional capability list to include.

    Returns:
        A dict suitable for passing to ``EvalContext`` or ``evaluatePolicy``.

    Examples:
        ```python
        result = verify_commit_range("HEAD~1..HEAD")
        for cr in result.commits:
            ctx = eval_context_from_commit_result(cr, org.did, ["sign_commit"])
        ```
    """
    from auths._native import signer_hex_to_did

    subject = "unknown"
    if commit_result.signer:
        try:
            subject = signer_hex_to_did(commit_result.signer)
        except Exception:
            subject = f"did:key:z{commit_result.signer}"

    ctx: dict = {
        "issuer": issuer,
        "subject": subject,
    }
    if capabilities:
        ctx["capabilities"] = capabilities
    return ctx


class PolicyBuilder:
    """Fluent builder for Auths access policies.

    Examples:
        ```python
        policy = PolicyBuilder.standard("sign_commit").build()

        policy = (PolicyBuilder()
            .not_revoked()
            .not_expired()
            .require_capability("sign_commit")
            .require_issuer("did:keri:EOrg123")
            .build())
        ```
    """

    #: All available predicate method names for discoverability.
    AVAILABLE_PREDICATES: list[str] = [
        "not_revoked",
        "not_expired",
        "expires_after",
        "issued_within",
        "require_capability",
        "require_all_capabilities",
        "require_any_capability",
        "require_issuer",
        "require_issuer_in",
        "require_subject",
        "require_delegated_by",
        "require_agent",
        "require_human",
        "require_workload",
        "require_repo",
        "require_env",
        "max_chain_depth",
    ]

    #: Built-in preset policy names.
    AVAILABLE_PRESETS: list[str] = [
        "standard",
    ]

    def __init__(self):
        self._predicates: list[dict] = []

    @classmethod
    def standard(cls, capability: str) -> PolicyBuilder:
        """The "80% policy": not revoked, not expired, requires one capability."""
        return cls().not_revoked().not_expired().require_capability(capability)

    @classmethod
    def from_json(cls, json_str: str) -> PolicyBuilder:
        """Reconstruct a PolicyBuilder from a JSON policy expression.

        Args:
            json_str: JSON string from ``to_json()`` or config files.

        Returns:
            A new PolicyBuilder with the parsed predicates.

        Examples:
            ```python
            builder = PolicyBuilder.from_json(stored_json)
            policy = builder.build()
            ```
        """
        expr = json.loads(json_str)
        result = cls()
        if isinstance(expr, dict) and expr.get("op") == "And" and isinstance(expr.get("args"), list):
            result._predicates = expr["args"]
        else:
            result._predicates = [expr]
        return result

    @classmethod
    def available_predicates(cls) -> list[str]:
        """Return the list of available predicate method names."""
        return list(cls.AVAILABLE_PREDICATES)

    @classmethod
    def available_presets(cls) -> list[str]:
        """Return the list of available preset policy names."""
        return list(cls.AVAILABLE_PRESETS)

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
