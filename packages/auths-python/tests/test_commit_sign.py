"""Tests for git commit signing workflow (fn-25.7)."""

import pytest

from auths import CommitSigningResult
from auths.commit import CommitSigningResult as CommitFromModule


class TestCommitSigningResult:

    def test_fields(self):
        r = CommitSigningResult(
            signature_pem="-----BEGIN SSH SIGNATURE-----\ntest\n-----END SSH SIGNATURE-----",
            method="direct",
            namespace="git",
        )
        assert r.signature_pem.startswith("-----BEGIN SSH SIGNATURE-----")
        assert r.method == "direct"
        assert r.namespace == "git"

    def test_repr(self):
        r = CommitSigningResult(
            signature_pem="-----BEGIN SSH SIGNATURE-----\n" + "A" * 100,
            method="direct",
            namespace="git",
        )
        s = repr(r)
        assert "CommitSigningResult" in s
        assert "direct" in s
        assert "..." in s

    def test_repr_short_pem(self):
        r = CommitSigningResult(
            signature_pem="short",
            method="ssh_agent",
            namespace="git",
        )
        s = repr(r)
        assert "ssh_agent" in s


class TestImports:

    def test_importable_from_top_level(self):
        from auths import CommitSigningResult
        assert CommitSigningResult is not None

    def test_importable_from_module(self):
        from auths.commit import CommitSigningResult
        assert CommitSigningResult is not None

    def test_ffi_function_importable(self):
        from auths._native import sign_commit
        assert sign_commit is not None
