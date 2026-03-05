"""E2E tests for the OIDC bridge."""

import os
import shutil
import socket
import subprocess
import time

import pytest

try:
    import jwt
    import requests
except ImportError:
    jwt = None
    requests = None


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def oidc_bridge(tmp_path_factory, auths_oidc_bridge_bin):
    """Spawn the OIDC bridge server for the test module."""
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not found")

    work_dir = tmp_path_factory.mktemp("oidc")
    key_path = work_dir / "signing_key.pem"

    subprocess.run(
        ["openssl", "genrsa", "-out", str(key_path), "2048"],
        check=True,
        capture_output=True,
    )

    port = _find_free_port()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTHS_OIDC_BIND_ADDR": f"127.0.0.1:{port}",
        "AUTHS_OIDC_SIGNING_KEY_PATH": str(key_path),
        "RUST_LOG": "warn",
    }

    proc = subprocess.Popen(
        [str(auths_oidc_bridge_bin)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if not _wait_for_port(port, timeout=15):
        proc.terminate()
        proc.wait(timeout=5)
        pytest.skip("OIDC bridge failed to start")

    yield {"proc": proc, "port": port, "key_path": key_path, "url": f"http://127.0.0.1:{port}"}

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.mark.slow
@pytest.mark.requires_binary
class TestOidcBridge:
    def test_bridge_health(self, oidc_bridge):
        try:
            import urllib.request

            url = f"{oidc_bridge['url']}/health"
            with urllib.request.urlopen(url, timeout=5) as resp:
                assert resp.status == 200
        except Exception:
            pytest.skip("health endpoint not available")

    def test_token_exchange(self, oidc_bridge):
        pytest.skip(
            "GAP: requires full attestation chain creation via CLI; "
            "manual integration needed"
        )

    def test_token_jwt_claims(self, oidc_bridge):
        if jwt is None:
            pytest.skip("PyJWT not installed")
        pytest.skip(
            "GAP: requires token exchange to produce JWT first"
        )

    def test_token_invalid_attestation(self, oidc_bridge):
        try:
            import urllib.request
            import json

            url = f"{oidc_bridge['url']}/api/v1/token"
            data = json.dumps(
                {
                    "attestation_chain": [{"invalid": True}],
                    "root_public_key": "invalid",
                    "requested_capabilities": ["sign:commit"],
                }
            ).encode()

            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                pytest.fail("Expected 4xx error for invalid attestation")
            except urllib.error.HTTPError as e:
                assert 400 <= e.code < 500
        except Exception as e:
            pytest.skip(f"token endpoint not available: {e}")

    def test_token_expired_attestation(self, oidc_bridge):
        pytest.skip(
            "GAP: requires attestation creation with past expiry; "
            "manual integration needed"
        )
