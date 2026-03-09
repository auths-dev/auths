"""E2E tests for LAN pairing via the auths-pairing-daemon."""

import json
import re
import signal
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

from helpers.cli import run_auths


def _start_pair_server(auths_bin: Path, env: dict, *, timeout_secs: int = 15):
    """Start `auths device pair` in the background and wait for server readiness.

    Returns (process, endpoint_url, short_code, pairing_token).
    """
    proc = subprocess.Popen(
        [
            str(auths_bin),
            "device",
            "pair",
            "--no-qr",
            "--no-mdns",
            "--timeout",
            str(timeout_secs),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    endpoint = None
    short_code = None
    pairing_token = None

    deadline = time.monotonic() + 10
    lines = []
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
            continue
        lines.append(line)

        # Parse endpoint from debug line: "  Debug: Test from another terminal: curl http://...:PORT/health"
        curl_match = re.search(r"curl\s+(http://\S+)/health", line)
        if curl_match:
            endpoint = curl_match.group(1)

        # Parse short code from line like "    ABC-123" (indented, 3-dash-3 format)
        code_match = re.match(r"^\s{4}([A-Z0-9]{3}-[A-Z0-9]{3})\s*$", line)
        if code_match:
            short_code = code_match.group(1).replace("-", "")

        # Parse pairing token from endpoint query string: "?token=..."
        token_match = re.search(r"\?token=([A-Za-z0-9_-]+)", line)
        if token_match:
            pairing_token = token_match.group(1)

        if endpoint and short_code:
            break

    if endpoint is None:
        proc.terminate()
        proc.wait(timeout=5)
        output = "".join(lines)
        stderr = proc.stderr.read() if proc.stderr else ""
        pytest.fail(
            f"Failed to detect LAN server endpoint.\nstdout:\n{output}\nstderr:\n{stderr}"
        )

    return proc, endpoint, short_code, pairing_token


def _kill_pair_server(proc: subprocess.Popen):
    """Gracefully terminate the pairing server."""
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        proc.kill()
        proc.wait(timeout=3)


def _http_get(url: str, *, headers: dict | None = None, timeout: int = 5) -> tuple[int, str]:
    """HTTP GET returning (status_code, body)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _http_post_json(
    url: str, data: dict, *, headers: dict | None = None, timeout: int = 5
) -> tuple[int, str]:
    """HTTP POST with JSON body returning (status_code, body)."""
    body = json.dumps(data).encode()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


@pytest.mark.requires_binary
class TestLanPairing:
    """Tests for the LAN pairing server started by `auths device pair`."""

    def test_pair_help(self, auths_bin):
        result = run_auths(auths_bin, ["device", "pair", "--help"])
        result.assert_success()
        assert "pair" in result.stdout.lower()

    def test_pair_offline_generates_code(self, auths_bin, init_identity):
        """Offline mode should output a short code and exit on timeout."""
        result = run_auths(
            auths_bin,
            ["device", "pair", "--offline", "--no-qr", "--timeout", "2"],
            env=init_identity,
            timeout=10,
        )
        # Offline mode exits 0 after timeout
        assert result.returncode == 0
        assert re.search(r"[A-Z0-9]{3}-[A-Z0-9]{3}", result.stdout), (
            f"Expected short code in output, got:\n{result.stdout}"
        )

    @pytest.mark.skip(reason="Binds to LAN IP which is unreachable in CI; will be rewritten to use auths-python SDK bindings")
    def test_pair_lan_server_health(self, auths_bin, init_identity):
        """LAN server should respond to /health."""
        proc, endpoint, _, _ = _start_pair_server(auths_bin, init_identity)
        try:
            status, body = _http_get(f"{endpoint}/health")
            assert status == 200
            assert body == "ok"
        finally:
            _kill_pair_server(proc)

    @pytest.mark.skip(reason="Binds to LAN IP which is unreachable in CI; will be rewritten to use auths-python SDK bindings")
    def test_pair_lan_server_session_lookup(self, auths_bin, init_identity):
        """Look up the session by short code via the LAN server."""
        proc, endpoint, short_code, _ = _start_pair_server(auths_bin, init_identity)
        try:
            assert short_code is not None, "Failed to parse short code from output"

            status, body = _http_get(
                f"{endpoint}/v1/pairing/sessions/by-code/{short_code}"
            )
            assert status == 200

            session = json.loads(body)
            assert session["status"] == "pending"
            assert session["session_id"] == short_code
            assert "token" in session
        finally:
            _kill_pair_server(proc)

    @pytest.mark.skip(reason="Binds to LAN IP which is unreachable in CI; will be rewritten to use auths-python SDK bindings")
    def test_pair_lan_server_requires_token(self, auths_bin, init_identity):
        """Mutating endpoints should reject requests without X-Pairing-Token."""
        proc, endpoint, short_code, _ = _start_pair_server(auths_bin, init_identity)
        try:
            submit = {
                "device_x25519_pubkey": "dGVzdA",
                "device_signing_pubkey": "dGVzdA",
                "device_did": "did:key:z6Mktest",
                "signature": "c2ln",
            }
            status, _ = _http_post_json(
                f"{endpoint}/v1/pairing/sessions/{short_code}/response",
                submit,
            )
            assert status == 401, f"Expected 401 without token, got {status}"
        finally:
            _kill_pair_server(proc)

    @pytest.mark.skip(reason="Binds to LAN IP which is unreachable in CI; will be rewritten to use auths-python SDK bindings")
    def test_pair_lan_server_submit_response(self, auths_bin, init_identity):
        """Submit a pairing response with valid token and verify status transition."""
        proc, endpoint, short_code, pairing_token = _start_pair_server(
            auths_bin, init_identity
        )
        try:
            if pairing_token is None:
                pytest.skip("Could not parse pairing token from output")

            # Verify session is pending
            status, body = _http_get(
                f"{endpoint}/v1/pairing/sessions/by-code/{short_code}"
            )
            assert status == 200
            session = json.loads(body)
            assert session["status"] == "pending"

            # Submit response with valid token
            submit = {
                "device_x25519_pubkey": "dGVzdA",
                "device_signing_pubkey": "dGVzdA",
                "device_did": "did:key:z6Mktest",
                "signature": "c2ln",
            }
            status, body = _http_post_json(
                f"{endpoint}/v1/pairing/sessions/{short_code}/response",
                submit,
                headers={"X-Pairing-Token": pairing_token},
            )
            assert status == 200, f"Submit failed: {body}"

            # Verify status transitioned to responded
            status, body = _http_get(
                f"{endpoint}/v1/pairing/sessions/{short_code}"
            )
            assert status == 200
            session = json.loads(body)
            assert session["status"] == "responded"
        finally:
            _kill_pair_server(proc)
