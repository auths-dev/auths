"""Tests for device authorization extension (fn-25.4)."""

import pytest

from auths import DeviceExtension
from auths.devices import DeviceExtension as DeviceExtensionFromModule


class TestDeviceExtension:

    def test_device_extension_fields(self):
        ext = DeviceExtension(
            device_did="did:key:zTest",
            new_expires_at="2025-06-15T00:00:00Z",
            previous_expires_at="2025-03-15T00:00:00Z",
        )
        assert ext.device_did == "did:key:zTest"
        assert ext.new_expires_at == "2025-06-15T00:00:00Z"
        assert ext.previous_expires_at == "2025-03-15T00:00:00Z"

    def test_device_extension_none_previous(self):
        ext = DeviceExtension(
            device_did="did:key:zTest",
            new_expires_at="2025-06-15T00:00:00Z",
            previous_expires_at=None,
        )
        assert ext.previous_expires_at is None

    def test_device_extension_repr(self):
        ext = DeviceExtension(
            device_did="did:key:z6MkTestDevice1234567890",
            new_expires_at="2025-06-15T00:00:00Z",
            previous_expires_at=None,
        )
        r = repr(ext)
        assert "DeviceExtension" in r
        assert "expires" in r

    def test_days_zero_raises(self):
        from auths._native import extend_device_authorization_ffi
        with pytest.raises(ValueError, match="positive"):
            extend_device_authorization_ffi("did:key:z", "main", 0, "/tmp", None)


class TestImports:

    def test_device_extension_importable_from_top_level(self):
        from auths import DeviceExtension
        assert DeviceExtension is not None

    def test_device_extension_importable_from_module(self):
        from auths.devices import DeviceExtension
        assert DeviceExtension is not None

    def test_extend_ffi_importable(self):
        from auths._native import extend_device_authorization_ffi
        assert extend_device_authorization_ffi is not None
