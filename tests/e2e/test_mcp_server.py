"""E2E tests for the MCP server authorization."""

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest


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


def _find_binary(env_var: str, name: str):
    """Resolve a binary from env var, PATH, or target/debug."""
    from pathlib import Path

    if path := os.environ.get(env_var):
        p = Path(path)
        if p.exists():
            return p

    if found := shutil.which(name):
        return Path(found)

    workspace_root = Path(__file__).resolve().parent.parent.parent
    debug_path = workspace_root / "target" / "debug" / name
    if debug_path.exists():
        return debug_path

    return None


@pytest.fixture(scope="module")
def auths_mcp_server_bin():
    """Path to the `auths-mcp-server` binary."""
    path = _find_binary("AUTHS_MCP_SERVER_BIN", "auths-mcp-server")
    if path is None:
        pytest.skip("auths-mcp-server binary not found")
    return path


@pytest.fixture(scope="module")
def mcp_server(tmp_path_factory, auths_mcp_server_bin):
    """Spawn the MCP server for the test module.

    Requires an OIDC bridge to be running for JWKS validation.
    For now, the MCP server starts without a live bridge; tests that
    need token validation will need the bridge fixture too.
    """
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not found")

    # Find the OIDC bridge binary
    oidc_bin = _find_binary("AUTHS_OIDC_BRIDGE_BIN", "auths-oidc-bridge")
    if oidc_bin is None:
        pytest.skip("auths-oidc-bridge binary not found")

    work_dir = tmp_path_factory.mktemp("mcp")
    key_path = work_dir / "signing_key.pem"

    subprocess.run(
        ["openssl", "genrsa", "-out", str(key_path), "2048"],
        check=True,
        capture_output=True,
    )

    # Start the OIDC bridge
    bridge_port = _find_free_port()
    bridge_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTHS_OIDC_BIND_ADDR": f"127.0.0.1:{bridge_port}",
        "AUTHS_OIDC_SIGNING_KEY_PATH": str(key_path),
        "AUTHS_OIDC_ISSUER_URL": f"http://127.0.0.1:{bridge_port}",
        "AUTHS_OIDC_AUDIENCE": "auths-mcp-server",
        "RUST_LOG": "warn",
    }

    bridge_proc = subprocess.Popen(
        [str(oidc_bin)],
        env=bridge_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if not _wait_for_port(bridge_port, timeout=15):
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)
        pytest.skip("OIDC bridge failed to start")

    # Start the MCP server
    mcp_port = _find_free_port()
    mcp_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTHS_MCP_BIND_ADDR": f"127.0.0.1:{mcp_port}",
        "AUTHS_MCP_JWKS_URL": f"http://127.0.0.1:{bridge_port}/.well-known/jwks.json",
        "AUTHS_MCP_EXPECTED_ISSUER": f"http://127.0.0.1:{bridge_port}",
        "AUTHS_MCP_EXPECTED_AUDIENCE": "auths-mcp-server",
        "RUST_LOG": "warn",
    }

    mcp_proc = subprocess.Popen(
        [str(auths_mcp_server_bin)],
        env=mcp_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if not _wait_for_port(mcp_port, timeout=15):
        mcp_proc.terminate()
        mcp_proc.wait(timeout=5)
        bridge_proc.terminate()
        bridge_proc.wait(timeout=5)
        pytest.skip("MCP server failed to start")

    yield {
        "mcp_proc": mcp_proc,
        "mcp_port": mcp_port,
        "mcp_url": f"http://127.0.0.1:{mcp_port}",
        "bridge_proc": bridge_proc,
        "bridge_port": bridge_port,
        "bridge_url": f"http://127.0.0.1:{bridge_port}",
        "key_path": key_path,
    }

    mcp_proc.terminate()
    bridge_proc.terminate()
    try:
        mcp_proc.wait(timeout=5)
        bridge_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        mcp_proc.kill()
        bridge_proc.kill()


@pytest.mark.slow
@pytest.mark.requires_binary
class TestMcpServer:
    def test_mcp_health(self, mcp_server):
        """Health endpoint should return 200 without authentication."""
        url = f"{mcp_server['mcp_url']}/health"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
            assert body["status"] == "ok"

    def test_mcp_protected_resource_metadata(self, mcp_server):
        """Protected Resource Metadata should return valid JSON."""
        url = f"{mcp_server['mcp_url']}/.well-known/oauth-protected-resource"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
            assert "authorization_servers" in body
            assert "scopes_supported" in body
            assert len(body["scopes_supported"]) > 0

    def test_mcp_list_tools(self, mcp_server):
        """Tool listing endpoint should return registered tools."""
        url = f"{mcp_server['mcp_url']}/mcp/tools"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200
            tools = json.loads(resp.read())
            assert isinstance(tools, list)
            tool_names = [t["name"] for t in tools]
            assert "read_file" in tool_names
            assert "write_file" in tool_names
            assert "deploy" in tool_names

    def test_mcp_no_token(self, mcp_server):
        """Tool call without Authorization header should return 401."""
        url = f"{mcp_server['mcp_url']}/mcp/tools/read_file"
        data = json.dumps({"path": "/tmp/test.txt"}).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            pytest.fail("Expected 401 for missing token")
        except urllib.error.HTTPError as e:
            assert e.code == 401

    def test_mcp_invalid_token(self, mcp_server):
        """Tool call with garbage Bearer token should return 401."""
        url = f"{mcp_server['mcp_url']}/mcp/tools/read_file"
        data = json.dumps({"path": "/tmp/test.txt"}).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer not-a-real-jwt",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            pytest.fail("Expected 401 for invalid token")
        except urllib.error.HTTPError as e:
            assert e.code == 401

    def test_mcp_authorized_read(self, mcp_server):
        """Full flow: exchange attestation for token, call tool.

        GAP: requires attestation chain creation; skipped until CLI
        integration supports `auths agent provision`.
        """
        pytest.skip(
            "GAP: requires full attestation chain creation via CLI; "
            "will be enabled when agent provisioning is implemented"
        )

    def test_mcp_unauthorized_tool(self, mcp_server):
        """Agent with fs:read should get 403 when calling deploy.

        GAP: requires valid JWT with specific capabilities.
        """
        pytest.skip(
            "GAP: requires valid JWT with scoped capabilities; "
            "will be enabled when token exchange E2E is complete"
        )

    def test_mcp_expired_token(self, mcp_server):
        """Expired JWT should return 401.

        GAP: requires ability to create a JWT with past expiry.
        """
        pytest.skip(
            "GAP: requires token with past expiry for testing"
        )
