"""E2E: the MCP gateway's spend log stays offline-verifiable AND tamper-evident
across period rotation.

Why this exists (what a user expects):

* **Security.** The spend log a bounded-agent gateway writes is the moat: anyone
  can re-derive the spend and re-verify every signed proof OFFLINE, trusting
  neither the gateway nor its operator. Tampering — an edited proof, a dropped
  record, a truncated tail — must be caught.
* **Performance / scale.** For high-frequency agents the log rotates by period
  into ``spend-log/<delegation>/<YYYY-MM>.jsonl`` so no single file grows without
  bound. Rotation is a *performance* feature and it must never open a *security*
  hole: a log split across period files has to still fully re-verify and still
  catch tampering across the rotation boundary.

Regression guard: the offline audit (in ``replay``/``wrap`` and the standalone
``verify-spend``) once read the pre-rotation *flat* path and silently SKIPPED the
audit of a rotated log ("no spend log to audit"). This test fails closed if that
returns.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


def _find_binary(env_var: str, name: str):
    if path := os.environ.get(env_var):
        p = Path(path)
        if p.exists():
            return p
    if found := shutil.which(name):
        return Path(found)
    workspace_root = Path(__file__).resolve().parent.parent.parent
    for profile in ("debug", "release"):
        cand = workspace_root / "target" / profile / name
        if cand.exists():
            return cand
    return None


@pytest.fixture(scope="module")
def gateway_bin():
    b = _find_binary("GATEWAY_BIN", "auths-mcp-gateway")
    if b is None:
        pytest.skip("auths-mcp-gateway binary not built")
    return b


@pytest.fixture
def transcript(tmp_path):
    """A minimal hermetic session: four in-scope, in-budget calls — enough
    records to split across two period files for the rotation-boundary check."""
    t = {
        "grant": {"scope": ["fs.read"], "budget": "$5.00", "ttl": "30m"},
        "calls": [
            {"tool": "read_file", "args": {"path": f"/etc/hosts#{i}"},
             "cost_cents": 0, "expect": "allowed"}
            for i in range(4)
        ],
    }
    p = tmp_path / "transcript.json"
    p.write_text(json.dumps(t))
    return p


def _replay(gateway_bin, transcript, tmp_path):
    """Drive the hermetic replay; return (stdout, parsed audit-cmd args dict)."""
    lab = tmp_path / "lab"
    lab.mkdir()
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "LAB_DIR": str(lab),
        "AUTHS_HOME": str(lab / "registry"),
        "AUTHS_REPO": str(lab / "registry"),
        "AUTHS_KEYCHAIN_BACKEND": "file",
        "AUTHS_KEYCHAIN_FILE": str(lab / "keys.enc"),
        "AUTHS_PASSPHRASE": "TestPassphrase!42",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@auths.dev",
        "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@auths.dev",
        "NO_COLOR": "1",
    }
    out = subprocess.run(
        [str(gateway_bin), "replay", "--transcript", str(transcript)],
        capture_output=True, text=True, env=env, timeout=180,
    )
    stdout = out.stdout + out.stderr
    m = re.search(r"audit-cmd:\s*--log\s+(\S+)\s+--registry\s+(\S+)\s+--agent\s+(\S+)\s+--root\s+(\S+)", stdout)
    args = None
    if m:
        args = {"log": m.group(1), "registry": m.group(2),
                "agent": m.group(3), "root": m.group(4), "env": env}
    return stdout, args


def _verify_spend(gateway_bin, log, args):
    out = subprocess.run(
        [str(gateway_bin), "verify-spend",
         "--log", str(log), "--registry", args["registry"],
         "--agent", args["agent"], "--root", args["root"]],
        capture_output=True, text=True, env=args["env"], timeout=120,
    )
    return out.stdout + out.stderr


@pytest.mark.slow
@pytest.mark.requires_binary
class TestSpendLogAuditAcrossRotation:
    def test_replay_self_audit_finds_the_rotated_log(self, gateway_bin, transcript, tmp_path):
        """The in-process self-audit must FIND and re-verify the rotated log —
        never 'SKIPPED — no spend log to audit' (the exact regression)."""
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert "audit: SKIPPED" not in stdout, f"audit skipped a rotated log:\n{stdout}"
        assert "audit: consistent" in stdout, f"self-audit not consistent:\n{stdout}"
        assert args is not None, f"no audit-cmd emitted:\n{stdout}"
        # The emitted log path is the rotated layout: a per-delegation directory.
        assert f"spend-log{os.sep}" in args["log"] and args["log"].endswith(".jsonl")
        assert Path(args["log"]).parent.name != "spend-log", "log is flat, not rotated"

    def test_verify_spend_walks_a_multi_period_rotated_log(self, gateway_bin, transcript, tmp_path):
        """Split the log across two period files (a real rotation boundary) and
        assert the standalone auditor re-derives `consistent` over the directory —
        the hash chain must hold ACROSS files, not just within one."""
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        spend_dir = log_file.parent
        records = [ln for ln in log_file.read_text().splitlines() if ln.strip()]
        assert len(records) >= 2, "need >=2 records to split across periods"
        half = len(records) // 2
        # Sorted period names so the directory walk replays in append order.
        (spend_dir / "2000-01.jsonl").write_text("\n".join(records[:half]) + "\n")
        (spend_dir / "2999-12.jsonl").write_text("\n".join(records[half:]) + "\n")
        log_file.unlink()  # remove the original single-period file

        out = _verify_spend(gateway_bin, spend_dir, args)
        assert "verify-spend: consistent" in out, f"rotated multi-file audit not consistent:\n{out}"

    def test_tampering_is_caught_across_the_rotation_boundary(self, gateway_bin, transcript, tmp_path):
        """A dropped record in an EARLIER period file breaks the signed back-link
        chain and must be caught — rotation must not let a hostile operator hide a
        truncation between files."""
        stdout, args = _replay(gateway_bin, transcript, tmp_path)
        assert args is not None, stdout
        log_file = Path(args["log"])
        spend_dir = log_file.parent
        records = [ln for ln in log_file.read_text().splitlines() if ln.strip()]
        assert len(records) >= 3
        half = len(records) // 2
        # Rotate, then DROP the first record of the earlier period (chain break).
        (spend_dir / "2000-01.jsonl").write_text("\n".join(records[1:half]) + "\n")
        (spend_dir / "2999-12.jsonl").write_text("\n".join(records[half:]) + "\n")
        log_file.unlink()

        out = _verify_spend(gateway_bin, spend_dir, args)
        assert "verify-spend: consistent" not in out, f"tampered rotated log passed:\n{out}"
        assert re.search(r"dropped-call|budget-mismatch|tampered-proof", out), \
            f"tamper not caught with a distinct verdict:\n{out}"
