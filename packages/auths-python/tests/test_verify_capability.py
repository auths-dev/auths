"""Tests for capability-based verification (Phase 2).

These tests use the bare FFI functions directly since they don't require
a full git registry — just attestation JSON and public keys.
"""

import json

import pytest

from auths import Auths

TEST_SEED_HEX = "a" * 64


def test_verify_without_capability_backwards_compat():
    """Calling verify without required_capability should work as before."""
    auths = Auths()
    with pytest.raises(Exception):
        auths.verify(attestation_json="{}", issuer_key="bad-hex")


def test_verify_with_capability_invalid_attestation():
    """Invalid attestation should still fail even with capability param."""
    auths = Auths()
    with pytest.raises(Exception):
        auths.verify(
            attestation_json="{}",
            issuer_key="bad-hex",
            required_capability="sign_commit",
        )


def test_verify_chain_without_capability_backwards_compat():
    """Calling verify_chain without required_capability should work as before."""
    auths = Auths()
    with pytest.raises(Exception):
        auths.verify_chain(attestations=["{}"], root_key="bad-hex")


def test_verify_chain_with_capability_invalid_attestation():
    """Invalid chain should still fail even with capability param."""
    auths = Auths()
    with pytest.raises(Exception):
        auths.verify_chain(
            attestations=["{}"],
            root_key="bad-hex",
            required_capability="sign_commit",
        )


def test_bare_function_imports():
    """The capability functions should be importable from auths.verify."""
    from auths.verify import (
        verify_attestation_with_capability,
        verify_chain_with_capability,
    )

    assert verify_attestation_with_capability is not None
    assert verify_chain_with_capability is not None
