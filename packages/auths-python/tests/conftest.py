import subprocess

import pytest

from auths import Auths


@pytest.fixture
def auths_client(tmp_path):
    """Create an Auths client with a temp directory."""
    repo = tmp_path / "test-repo"
    repo.mkdir()
    return Auths(repo_path=str(repo), passphrase="Test-pass-123")


@pytest.fixture
def auths_with_identity(auths_client):
    """Create an Auths client with an initialized identity."""
    identity = auths_client.identities.create(label="main")
    return auths_client, identity


@pytest.fixture
def git_repo(tmp_path):
    """Initialize a git repo with one unsigned commit for audit tests."""
    repo_dir = tmp_path / "git-repo"
    repo_dir.mkdir()
    subprocess.run(
        ["git", "init"], cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    readme = repo_dir / "README.md"
    readme.write_text("# Test Repo\n")
    subprocess.run(
        ["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "initial commit"],
        cwd=str(repo_dir), check=True, capture_output=True,
    )
    return repo_dir


@pytest.fixture
def controller_and_device(tmp_path):
    """Create two separate Auths clients with identities for pairing tests."""
    controller_home = tmp_path / "controller"
    controller_home.mkdir()
    controller = Auths(
        repo_path=str(controller_home / ".auths"), passphrase="Test-pass-123",
    )
    controller.identities.create(label="controller")

    device_home = tmp_path / "device"
    device_home.mkdir()
    device = Auths(
        repo_path=str(device_home / ".auths"), passphrase="Test-pass-123",
    )
    device.identities.create(label="device")

    return controller, device
