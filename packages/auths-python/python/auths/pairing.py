from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from auths._native import (
    PyPairingHandle,
    complete_pairing_ffi as _complete_pairing,
    create_pairing_session_ffi as _create_session,
    join_pairing_session_ffi as _join_session,
)
from auths._client import _map_error
from auths._errors import PairingError


@dataclass
class PairingResponse:
    """The response from a device that joined a pairing session."""

    device_did: str
    device_name: Optional[str]
    device_public_key_hex: str
    capabilities: list[str]


@dataclass
class PairingResult:
    """The result of completing a pairing flow."""

    device_did: str
    device_name: Optional[str]
    attestation_rid: Optional[str]


class PairingSession:
    """A running pairing session with an active LAN server."""

    def __init__(
        self,
        session_id: str,
        short_code: str,
        endpoint: str,
        token: str,
        controller_did: str,
        handle: PyPairingHandle,
    ):
        self.session_id = session_id
        self.short_code = short_code
        self.endpoint = endpoint
        self.token = token
        self.controller_did = controller_did
        self._handle = handle

    def wait_for_response(self, timeout_secs: int = 300) -> PairingResponse:
        """Block until a device submits a pairing response.

        Args:
            timeout_secs: Maximum seconds to wait.

        Usage:
            response = session.wait_for_response(timeout_secs=30)
        """
        try:
            device_did, device_name, pk_hex, caps_json = self._handle.wait_for_response(
                timeout_secs,
            )
            caps = json.loads(caps_json) if caps_json else []
            return PairingResponse(
                device_did=device_did,
                device_name=device_name,
                device_public_key_hex=pk_hex,
                capabilities=caps,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=PairingError) from exc

    def stop(self) -> None:
        """Stop the pairing server and release the port."""
        self._handle.stop()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def __del__(self):
        try:
            self.stop()
        except Exception:
            pass

    def __repr__(self):
        return (
            f"PairingSession(code={self.short_code!r}, "
            f"endpoint={self.endpoint!r})"
        )


class PairingService:
    """Resource service for programmatic device pairing."""

    def __init__(self, client):
        self._client = client

    def create_session(
        self,
        capabilities: list[str] | None = None,
        timeout_secs: int = 300,
        bind_address: str = "0.0.0.0",
        enable_mdns: bool = True,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> PairingSession:
        """Start a LAN pairing server and return a session handle.

        Args:
            capabilities: Capabilities to grant the paired device.
            timeout_secs: Session lifetime in seconds.
            bind_address: IP address to bind the HTTP server to.
            enable_mdns: Whether to advertise via mDNS.

        Usage:
            session = client.pairing.create_session(
                bind_address="127.0.0.1", enable_mdns=False
            )
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        caps_json = json.dumps(capabilities) if capabilities else None
        try:
            sid, code, ep, tok, did, handle = _create_session(
                rp, caps_json, timeout_secs, bind_address, enable_mdns, pp,
            )
            return PairingSession(
                session_id=sid,
                short_code=code,
                endpoint=ep,
                token=tok,
                controller_did=did,
                handle=handle,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=PairingError) from exc

    def join(
        self,
        short_code: str,
        endpoint: str,
        token: str,
        device_name: str | None = None,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> PairingResult:
        """Join an existing pairing session as a device.

        Args:
            short_code: The 6-character pairing code.
            endpoint: The controller's HTTP endpoint URL.
            token: The transport token from the controller's session.
            device_name: Human-readable name for this device.

        Usage:
            result = device.pairing.join(
                session.short_code,
                endpoint=session.endpoint,
                token=session.token,
            )
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        try:
            device_did, name = _join_session(
                short_code, endpoint, token, rp, device_name, pp,
            )
            return PairingResult(
                device_did=device_did,
                device_name=name,
                attestation_rid=None,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=PairingError) from exc

    def complete(
        self,
        session: PairingSession,
        response: PairingResponse,
        repo_path: str | None = None,
        passphrase: str | None = None,
    ) -> PairingResult:
        """Complete pairing by creating the device attestation.

        Args:
            session: The active PairingSession.
            response: The PairingResponse from wait_for_response().

        Usage:
            result = controller.pairing.complete(session, response)
        """
        rp = repo_path or self._client.repo_path
        pp = passphrase or self._client._passphrase
        caps_json = json.dumps(response.capabilities) if response.capabilities else None
        try:
            device_did, name, rid = _complete_pairing(
                response.device_did, response.device_public_key_hex,
                rp, caps_json, pp,
            )
            return PairingResult(
                device_did=device_did,
                device_name=name,
                attestation_rid=rid,
            )
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=PairingError) from exc
