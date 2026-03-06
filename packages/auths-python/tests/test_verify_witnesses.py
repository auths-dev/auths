"""Tests for witness chain verification (fn-25.2)."""

import pytest

from auths import Auths
from auths.verify import WitnessConfig, WitnessKey, verify_chain_with_witnesses


class TestWitnessConfigValidation:

    def test_threshold_zero_raises(self):
        with pytest.raises(ValueError, match="threshold must be >= 1"):
            WitnessConfig(
                receipts=[],
                keys=[WitnessKey(did="did:key:z1", public_key_hex="a" * 64)],
                threshold=0,
            )

    def test_threshold_exceeds_keys_raises(self):
        with pytest.raises(ValueError, match="cannot exceed"):
            WitnessConfig(
                receipts=[],
                keys=[WitnessKey(did="did:key:z1", public_key_hex="a" * 64)],
                threshold=2,
            )

    def test_valid_config_creates(self):
        config = WitnessConfig(
            receipts=[],
            keys=[
                WitnessKey(did="did:key:z1", public_key_hex="a" * 64),
                WitnessKey(did="did:key:z2", public_key_hex="b" * 64),
            ],
            threshold=1,
        )
        assert config.threshold == 1
        assert len(config.keys) == 2


class TestWitnessKeyDataclass:

    def test_witness_key_fields(self):
        wk = WitnessKey(did="did:key:zTest", public_key_hex="ab" * 32)
        assert wk.did == "did:key:zTest"
        assert wk.public_key_hex == "ab" * 32

    def test_witness_key_repr(self):
        wk = WitnessKey(did="did:key:z6MkLongWitnessDid", public_key_hex="ab" * 32)
        assert "WitnessKey" in repr(wk)


class TestVerifyChainWithWitnessesFFI:

    def test_empty_chain_with_witnesses(self):
        config = WitnessConfig(
            receipts=[],
            keys=[WitnessKey(did="did:key:z1", public_key_hex="a" * 64)],
            threshold=1,
        )
        report = verify_chain_with_witnesses([], "a" * 64, config)
        assert hasattr(report, "status")
        assert hasattr(report, "warnings")

    def test_invalid_root_key_raises(self):
        config = WitnessConfig(
            receipts=[],
            keys=[WitnessKey(did="did:key:z1", public_key_hex="a" * 64)],
            threshold=1,
        )
        with pytest.raises(ValueError, match="hex"):
            verify_chain_with_witnesses([], "not-hex", config)


class TestClientVerifyChainWithWitnesses:

    def test_client_verify_chain_with_witnesses(self):
        auths = Auths()
        config = WitnessConfig(
            receipts=[],
            keys=[WitnessKey(did="did:key:z1", public_key_hex="a" * 64)],
            threshold=1,
        )
        report = auths.verify_chain([], "a" * 64, witnesses=config)
        assert hasattr(report, "status")


class TestImports:

    def test_imports_from_verify_module(self):
        from auths.verify import WitnessConfig, WitnessKey, verify_chain_with_witnesses
        assert WitnessConfig is not None
        assert WitnessKey is not None
        assert verify_chain_with_witnesses is not None

    def test_imports_from_top_level(self):
        from auths import WitnessConfig, WitnessKey
        assert WitnessConfig is not None
        assert WitnessKey is not None
