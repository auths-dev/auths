"""E2E tests for `auths scim` CLI subcommands and full SCIM server lifecycle."""

import json
import os
import shutil
import socket
import subprocess
import time
import uuid

import pytest


# ---------------------------------------------------------------------------
# CLI help tests (no server required)
# ---------------------------------------------------------------------------


def test_scim_help(auths_bin):
    """auths scim --help shows subcommands."""
    result = subprocess.run(
        [auths_bin, "scim", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "serve" in result.stdout.lower()
    assert "quickstart" in result.stdout.lower()
    assert "test-connection" in result.stdout.lower()
    assert "add-tenant" in result.stdout.lower()


def test_scim_serve_help(auths_bin):
    """auths scim serve --help shows options."""
    result = subprocess.run(
        [auths_bin, "scim", "serve", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--bind" in result.stdout
    assert "--database-url" in result.stdout


def test_scim_quickstart_help(auths_bin):
    """auths scim quickstart --help shows options."""
    result = subprocess.run(
        [auths_bin, "scim", "quickstart", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--bind" in result.stdout


def test_scim_test_connection_help(auths_bin):
    """auths scim test-connection --help shows options."""
    result = subprocess.run(
        [auths_bin, "scim", "test-connection", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--url" in result.stdout
    assert "--token" in result.stdout


def test_scim_add_tenant_help(auths_bin):
    """auths scim add-tenant --help shows options."""
    result = subprocess.run(
        [auths_bin, "scim", "add-tenant", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--name" in result.stdout
    assert "--database-url" in result.stdout


def test_scim_rotate_token_help(auths_bin):
    """auths scim rotate-token --help shows options."""
    result = subprocess.run(
        [auths_bin, "scim", "rotate-token", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--name" in result.stdout


def test_scim_status_help(auths_bin):
    """auths scim status --help shows options."""
    result = subprocess.run(
        [auths_bin, "scim", "status", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--database-url" in result.stdout


# ---------------------------------------------------------------------------
# Full SCIM server E2E tests (require PostgreSQL + auths-scim-server binary)
# ---------------------------------------------------------------------------

TEST_TOKEN = "scim_test_token_for_e2e"
SCIM_CONTENT_TYPE = "application/scim+json"


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _scim_request(base_url, method, path, token=None, body=None):
    """Make an HTTP request to the SCIM server using urllib (no external deps)."""
    import urllib.error
    import urllib.request

    url = f"{base_url}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data:
        headers["Content-Type"] = SCIM_CONTENT_TYPE

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_body = resp.read().decode()
            return resp.status, json.loads(resp_body) if resp_body else None
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode()
        return e.code, json.loads(resp_body) if resp_body else None


def _find_psql() -> str | None:
    """Find the psql binary on PATH or common Homebrew locations."""
    found = shutil.which("psql")
    if found:
        return found
    for candidate in [
        "/opt/homebrew/bin/psql",
        "/usr/local/bin/psql",
        "/usr/bin/psql",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


def _pg_admin_url() -> str | None:
    """Return a PostgreSQL admin URL for creating/dropping databases.

    Priority:
      1. SCIM_TEST_DATABASE_URL env var (use as-is, skip auto-create)
      2. SCIM_TEST_PG_URL env var (connect to this server, auto-create a temp DB)
      3. Try postgres://localhost/postgres as a default
    """
    if os.environ.get("SCIM_TEST_DATABASE_URL"):
        return None  # signal: use the explicit URL, skip auto-create
    if url := os.environ.get("SCIM_TEST_PG_URL"):
        return url
    return "postgres://localhost/postgres"


def _psql_exec(psql: str, admin_url: str, sql: str) -> bool:
    """Run a SQL statement via psql. Returns True on success."""
    result = subprocess.run(
        [psql, admin_url, "-c", sql],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode == 0


@pytest.fixture(scope="module")
def scim_server(tmp_path_factory, auths_scim_server_bin):
    """Spawn the SCIM server backed by PostgreSQL in test mode.

    Automatically creates a temporary database and drops it on teardown.
    Set SCIM_TEST_DATABASE_URL to use a pre-existing database instead.
    Set SCIM_TEST_PG_URL to point to a non-default PostgreSQL server.
    """
    temp_db_name = None
    admin_url = _pg_admin_url()

    if admin_url is None:
        # Explicit SCIM_TEST_DATABASE_URL — use as-is
        db_url = os.environ["SCIM_TEST_DATABASE_URL"]
    else:
        psql = _find_psql()
        if not psql:
            pytest.skip("psql not found — install PostgreSQL or set SCIM_TEST_DATABASE_URL")

        if not _psql_exec(psql, admin_url, "SELECT 1"):
            pytest.skip(
                "Cannot connect to PostgreSQL — "
                "start PostgreSQL or set SCIM_TEST_DATABASE_URL"
            )

        temp_db_name = f"auths_scim_e2e_{uuid.uuid4().hex[:12]}"
        if not _psql_exec(psql, admin_url, f'CREATE DATABASE "{temp_db_name}"'):
            pytest.skip(f"Failed to create temporary database {temp_db_name}")

        # Build the URL for the temp database (same server, different dbname)
        # admin_url is like postgres://localhost/postgres or postgres://user:pass@host:port/postgres
        db_url = admin_url.rsplit("/", 1)[0] + f"/{temp_db_name}"

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "DATABASE_URL": db_url,
        "SCIM_LISTEN_ADDR": f"127.0.0.1:{port}",
        "SCIM_BASE_URL": base_url,
        "AUTHS_SCIM_TEST": "1",
        "RUST_LOG": "warn",
    }

    proc = subprocess.Popen(
        [str(auths_scim_server_bin)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if not _wait_for_port(port, timeout=15):
        stderr = ""
        try:
            proc.terminate()
            _, stderr_bytes = proc.communicate(timeout=5)
            stderr = stderr_bytes.decode(errors="replace")
        except Exception:
            proc.kill()
        if temp_db_name and admin_url:
            _psql_exec(psql, admin_url, f'DROP DATABASE IF EXISTS "{temp_db_name}"')
        pytest.skip(f"SCIM server failed to start: {stderr[:500]}")

    yield {"proc": proc, "port": port, "url": base_url, "token": TEST_TOKEN}

    # Teardown: stop server, then drop temp database
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    if temp_db_name and admin_url:
        _psql_exec(psql, admin_url, f'DROP DATABASE IF EXISTS "{temp_db_name}"')


@pytest.mark.slow
@pytest.mark.requires_binary
class TestScimServerDiscovery:
    """Discovery endpoints require no authentication."""

    def test_api_root(self, scim_server):
        status, body = _scim_request(scim_server["url"], "GET", "/")
        assert status == 200
        assert body["name"] == "Auths SCIM 2.0 Provisioning API"
        assert "users" in body["endpoints"]

    def test_service_provider_config(self, scim_server):
        status, body = _scim_request(scim_server["url"], "GET", "/ServiceProviderConfig")
        assert status == 200
        assert isinstance(body["schemas"], list)

    def test_resource_types(self, scim_server):
        status, body = _scim_request(scim_server["url"], "GET", "/ResourceTypes")
        assert status == 200
        assert isinstance(body, list)
        assert body[0]["id"] == "User"
        assert body[0]["endpoint"] == "/Users"


@pytest.mark.slow
@pytest.mark.requires_binary
class TestScimServerAuth:
    """Authentication enforcement on User endpoints."""

    def test_no_auth_returns_401(self, scim_server):
        status, body = _scim_request(scim_server["url"], "GET", "/Users")
        assert status == 401
        assert body["status"] == "401"

    def test_invalid_token_returns_401(self, scim_server):
        status, body = _scim_request(
            scim_server["url"], "GET", "/Users", token="bad_token"
        )
        assert status == 401

    def test_basic_auth_returns_401(self, scim_server):
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            f"{scim_server['url']}/Users",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
            pytest.fail("Expected 401")
        except urllib.error.HTTPError as e:
            assert e.code == 401


@pytest.mark.slow
@pytest.mark.requires_binary
class TestScimServerLifecycle:
    """Full CRUD lifecycle: create -> get -> list -> patch -> put -> delete."""

    def test_create_user(self, scim_server):
        """POST /Users creates an agent and returns 201."""
        status, body = _scim_request(
            scim_server["url"],
            "POST",
            "/Users",
            token=scim_server["token"],
            body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "e2e-deploy-bot",
                "displayName": "E2E Deploy Bot",
                "externalId": "e2e-ext-001",
            },
        )
        assert status == 201, f"Expected 201, got {status}: {body}"
        assert body["userName"] == "e2e-deploy-bot"
        assert body["displayName"] == "E2E Deploy Bot"
        assert body["active"] is True
        assert body["id"]  # UUID assigned
        assert body["meta"]["resourceType"] == "User"
        assert "/Users/" in body["meta"]["location"]

        # Store for subsequent tests
        scim_server["_created_id"] = body["id"]
        scim_server["_created_etag"] = f'W/"v1"'

    def test_idempotent_create(self, scim_server):
        """POST /Users with same externalId returns 200 (not 201)."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        status, body = _scim_request(
            scim_server["url"],
            "POST",
            "/Users",
            token=scim_server["token"],
            body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "e2e-deploy-bot",
                "externalId": "e2e-ext-001",
            },
        )
        assert status == 200, f"Idempotent POST should return 200, got {status}"
        assert body["id"] == scim_server["_created_id"]

    def test_get_user(self, scim_server):
        """GET /Users/{id} retrieves the created agent."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        agent_id = scim_server["_created_id"]
        status, body = _scim_request(
            scim_server["url"],
            "GET",
            f"/Users/{agent_id}",
            token=scim_server["token"],
        )
        assert status == 200
        assert body["id"] == agent_id
        assert body["userName"] == "e2e-deploy-bot"

    def test_list_users(self, scim_server):
        """GET /Users returns a SCIM ListResponse containing the agent."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        status, body = _scim_request(
            scim_server["url"],
            "GET",
            "/Users",
            token=scim_server["token"],
        )
        assert status == 200
        assert body["totalResults"] >= 1
        assert body["schemas"] == [
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        ]
        user_ids = [r["id"] for r in body["Resources"]]
        assert scim_server["_created_id"] in user_ids

    def test_patch_deactivate(self, scim_server):
        """PATCH /Users/{id} sets active=false."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        agent_id = scim_server["_created_id"]
        status, body = _scim_request(
            scim_server["url"],
            "PATCH",
            f"/Users/{agent_id}",
            token=scim_server["token"],
            body={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "Replace", "value": {"active": False}}
                ],
            },
        )
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body["active"] is False

        # Update etag for subsequent requests
        scim_server["_created_etag"] = body["meta"]["version"]

    def test_patch_reactivate(self, scim_server):
        """PATCH /Users/{id} sets active=true."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        agent_id = scim_server["_created_id"]
        status, body = _scim_request(
            scim_server["url"],
            "PATCH",
            f"/Users/{agent_id}",
            token=scim_server["token"],
            body={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "Replace", "value": {"active": True}}
                ],
            },
        )
        assert status == 200
        assert body["active"] is True
        scim_server["_created_etag"] = body["meta"]["version"]

    def test_put_replace(self, scim_server):
        """PUT /Users/{id} replaces mutable fields."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        agent_id = scim_server["_created_id"]
        etag = scim_server.get("_created_etag", 'W/"v1"')

        status, body = _scim_request(
            scim_server["url"],
            "PUT",
            f"/Users/{agent_id}",
            token=scim_server["token"],
            body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "e2e-deploy-bot",
                "displayName": "Updated Bot Name",
                "active": True,
                "externalId": "e2e-ext-001",
            },
        )
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body["displayName"] == "Updated Bot Name"
        scim_server["_created_etag"] = body["meta"]["version"]

    def test_delete_user(self, scim_server):
        """DELETE /Users/{id} removes the agent."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        agent_id = scim_server["_created_id"]
        status, body = _scim_request(
            scim_server["url"],
            "DELETE",
            f"/Users/{agent_id}",
            token=scim_server["token"],
        )
        assert status == 204

    def test_get_deleted_user_returns_404(self, scim_server):
        """GET /Users/{id} after DELETE returns 404."""
        if "_created_id" not in scim_server:
            pytest.skip("create_user must run first")

        agent_id = scim_server["_created_id"]
        status, body = _scim_request(
            scim_server["url"],
            "GET",
            f"/Users/{agent_id}",
            token=scim_server["token"],
        )
        assert status == 404
