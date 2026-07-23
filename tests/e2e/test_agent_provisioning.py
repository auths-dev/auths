"""End-to-end integration tests for `auths agent provision` and subagent ergonomics (Spec 12)."""

import os
import subprocess
from pathlib import Path

import pytest

from helpers.cli import run_auths


def test_agent_provision_manual_flags(auths_bin, isolated_env, tmp_path):
    """Test provisioning an agent using explicit command line flags."""
    # 1. Initialize root identity
    init_res = run_auths(
        auths_bin,
        ["init", "--profile", "developer", "--non-interactive"],
        env=isolated_env,
    )
    assert init_res.returncode == 0, f"Init failed: {init_res.stderr}"

    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text("TestAgentPassphrase!12345")
    out_dir = tmp_path / "agent-builder"

    # 2. Provision agent with flags
    prov_res = run_auths(
        auths_bin,
        [
            "agent",
            "provision",
            "--label",
            "agent-builder",
            "--key",
            "main",
            "--profile",
            "assistant",
            "--out",
            str(out_dir),
            "--passphrase-file",
            str(passphrase_file),
        ],
        env=isolated_env,
    )
    assert prov_res.returncode == 0, f"Provisioning failed: {prov_res.stderr}\n{prov_res.stdout}"
    assert "Your agent is provisioned!" in prov_res.stdout

    # 3. Verify directory contents and permissions
    assert out_dir.exists()
    assert (out_dir / "keys.enc").exists()
    assert (out_dir / "env.sh").exists()
    assert (out_dir / "bin" / "auths-agent").exists()

    # 4. Verify agent list output
    list_res = run_auths(auths_bin, ["agent", "list"], env=isolated_env)
    assert list_res.returncode == 0
    assert "agent-builder" in list_res.stdout or "did:keri:" in list_res.stdout


def test_agent_provision_custom_backend(auths_bin, isolated_env, tmp_path):
    """Test agent provision with file backend explicitly set."""
    env = isolated_env.copy()
    env["AUTHS_KEYCHAIN_BACKEND"] = "file"
    env["AUTHS_PASSPHRASE"] = "RootPassphrase1234!"

    init_res = run_auths(
        auths_bin,
        ["init", "--profile", "developer", "--non-interactive"],
        env=env,
    )
    assert init_res.returncode == 0, f"Init failed: {init_res.stderr}"

    passphrase_file = tmp_path / "agent_pass.txt"
    passphrase_file.write_text("AgentPassphrase1234!")
    out_dir = tmp_path / "sub-agent"

    prov_res = run_auths(
        auths_bin,
        [
            "agent",
            "provision",
            "--label",
            "sub-agent",
            "--key",
            "main",
            "--profile",
            "ci",
            "--out",
            str(out_dir),
            "--passphrase-file",
            str(passphrase_file),
        ],
        env=env,
    )
    assert prov_res.returncode == 0, f"Provisioning failed: {prov_res.stderr}\n{prov_res.stdout}"
    assert (out_dir / "keys.enc").exists()


def test_agent_provision_recursive_subagent(auths_bin, isolated_env, tmp_path):
    """Test that a provisioned agent can recursively provision a subagent."""
    init_res = run_auths(
        auths_bin,
        ["init", "--profile", "developer", "--non-interactive"],
        env=isolated_env,
    )
    assert init_res.returncode == 0

    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text("TestAgentPassphrase!12345")
    parent_agent_dir = tmp_path / "agent-builder"

    # Provision parent agent
    prov_res = run_auths(
        auths_bin,
        [
            "agent",
            "provision",
            "--label",
            "agent-builder",
            "--key",
            "main",
            "--profile",
            "assistant",
            "--out",
            str(parent_agent_dir),
            "--passphrase-file",
            str(passphrase_file),
        ],
        env=isolated_env,
    )
    assert prov_res.returncode == 0

    # Provision sub-agent using parent agent's wrapper script
    subagent_dir = tmp_path / "sub-agent"
    sub_pass_file = tmp_path / "sub_pass.txt"
    sub_pass_file.write_text("SubAgentPassphrase!12345")

    wrapper_bin = parent_agent_dir / "bin" / "auths-agent"
    assert wrapper_bin.exists()

    sub_env = isolated_env.copy()
    sub_env["AUTHS_PASSPHRASE"] = "TestAgentPassphrase!12345"

    sub_res = subprocess.run(
        [
            str(wrapper_bin),
            "agent",
            "provision",
            "--label",
            "sub-agent",
            "--key",
            "agent-builder",
            "--profile",
            "ci",
            "--out",
            str(subagent_dir),
            "--passphrase-file",
            str(sub_pass_file),
        ],
        capture_output=True,
        text=True,
        env=sub_env,
    )
    assert sub_res.returncode == 0, f"Subagent provision failed: {sub_res.stderr}\n{sub_res.stdout}"
    assert subagent_dir.exists()
    assert (subagent_dir / "keys.enc").exists()
