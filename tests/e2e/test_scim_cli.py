"""E2E tests for `auths scim` CLI subcommands."""

import subprocess


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
