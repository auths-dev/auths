"""Policy engine — compile, evaluate, enforce authorization rules."""

from __future__ import annotations

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
    reason: str
    message: str

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
