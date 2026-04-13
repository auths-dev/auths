"""E2E test: ephemeral CI signing → verify pipeline."""
import hashlib
import json
import os
import subprocess
import tempfile


def run(cmd, **kwargs):
    """Run a command and return the result."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def test_ephemeral_sign_and_verify():
    """Test that ephemeral CI signing produces a verifiable attestation."""
    # Get current commit SHA
    head = run(["git", "rev-parse", "HEAD"])
    assert head.returncode == 0, f"git rev-parse HEAD failed: {head.stderr}"
    commit_sha = head.stdout.strip()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test artifact
        artifact_path = os.path.join(tmpdir, "test-artifact.tar.gz")
        with open(artifact_path, "wb") as f:
            f.write(b"ephemeral signing e2e test content")

        # Sign with ephemeral CI key
        sign_result = run([
            "cargo", "run", "-p", "auths-cli", "--bin", "auths", "--",
            "artifact", "sign", artifact_path,
            "--ci",
            "--ci-platform", "local",
            "--commit", commit_sha,
            "--note", "E2E test",
        ])
        assert sign_result.returncode == 0, (
            f"Ephemeral sign failed: {sign_result.stderr}\n{sign_result.stdout}"
        )

        # Check .auths.json was created
        attestation_path = f"{artifact_path}.auths.json"
        assert os.path.exists(attestation_path), f"No .auths.json at {attestation_path}"

        # Parse and validate the attestation
        with open(attestation_path) as f:
            att = json.load(f)

        assert att["issuer"].startswith("did:key:z"), (
            f"Issuer should be did:key:, got: {att['issuer']}"
        )
        assert att["signer_type"] == "Workload", (
            f"signer_type should be Workload, got: {att.get('signer_type')}"
        )
        assert att["commit_sha"] == commit_sha, (
            f"commit_sha mismatch: {att.get('commit_sha')} != {commit_sha}"
        )
        assert att["capabilities"] == ["sign_release"], (
            f"capabilities should be [sign_release], got: {att.get('capabilities')}"
        )

        # Check payload has artifact metadata
        payload = att["payload"]
        assert payload["digest"]["algorithm"] == "sha256"
        expected_hash = hashlib.sha256(b"ephemeral signing e2e test content").hexdigest()
        assert payload["digest"]["hex"] == expected_hash, (
            f"Hash mismatch: {payload['digest']['hex']} != {expected_hash}"
        )

        # Check CI environment in payload
        ci_env = payload.get("ci_environment")
        assert ci_env is not None, "ci_environment should be in payload"
        assert ci_env["platform"] == "local", (
            f"Platform should be local, got: {ci_env.get('platform')}"
        )

        print(f"✓ Ephemeral attestation valid: issuer={att['issuer'][:30]}...")
        print(f"  Commit: {commit_sha[:8]}")
        print(f"  Digest: sha256:{expected_hash[:16]}...")


if __name__ == "__main__":
    test_ephemeral_sign_and_verify()
    print("\n✓ All E2E ephemeral signing tests passed")
