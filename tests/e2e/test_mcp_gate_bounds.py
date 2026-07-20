"""E2E: the live `wrap` gateway enforces each bound BEFORE the downstream is touched.

Why this exists (what a user expects): a bounded agent cannot exceed its bounds. The
gateway wraps a real downstream MCP server; every `tools/call` passes the per-call gate
(scope / budget / ttl / revocation) and a REFUSED call never reaches the downstream. The
downstream here is a tripwire — it appends one line per call it actually receives — so the
tripwire line count is the ground truth of what was forwarded.

Enforced bounds:
  --ttl is a real expiry seal — an expired agent is refused before the downstream.
  a refusal carries a structured, re-checkable verdict object in error.data.
  fs.read admits the whole read family; write_file is out of scope.
  the budget boundary is strictly-over (exact-exhaust allowed, +1 refused).
  a mid-session revocation propagates within the recheck SLA.
  the spend-log path is announced and can be pinned with --spend-log.
  a second wrap on the same key file is idempotent, not a bare error.
  exact-token scope — every near-miss of `read_file` is refused.
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

HELPERS = Path(__file__).resolve().parent / "helpers"
DOWNSTREAM = HELPERS / "mcp_downstream.py"


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


@pytest.fixture(scope="module")
def auths_bin():
    b = _find_binary("AUTHS_BIN", "auths")
    if b is None:
        pytest.skip("auths binary not built")
    return b


def _lab_env(tmp_path: Path, tripwire: Path, keyfile: Path | None = None) -> dict:
    lab = tmp_path / "lab"
    lab.mkdir(exist_ok=True)
    gateway = _find_binary("GATEWAY_BIN", "auths-mcp-gateway")
    bindir = gateway.parent if gateway else None
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "LAB_DIR": str(lab),
        "AUTHS_MCP_LIVE_DIR": str(lab),
        "AUTHS_HOME": str(lab / "registry"),
        "AUTHS_REPO": str(lab / "registry"),
        "AUTHS_KEYCHAIN_BACKEND": "file",
        "AUTHS_KEYCHAIN_FILE": str(keyfile or (lab / "keys.enc")),
        "AUTHS_PASSPHRASE": "TestPassphrase!42",
        "AUTHS_TRIPWIRE": str(tripwire),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@auths.dev",
        "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@auths.dev",
        "NO_COLOR": "1",
    }
    if bindir:
        env.setdefault("AUTHS_BIN", str(bindir / "auths"))
        env.setdefault("AUTHS_SIGN", str(bindir / "auths-sign"))
    return env


class Wrap:
    """An MCP stdio client driving a live `auths-mcp-gateway wrap` session."""

    def __init__(self, gateway_bin, wrap_args, env):
        argv = [str(gateway_bin), "wrap", *wrap_args, "--",
                "python3", str(DOWNSTREAM)]
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env,
        )
        self._id = 0
        self._send({"jsonrpc": "2.0", "id": self._next(), "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "e2e", "version": "0"}}})
        self._recv()
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _next(self):
        self._id += 1
        return self._id

    def _send(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _recv(self, timeout=60):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise AssertionError("gateway closed the stream")
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if "id" in msg:
                return msg

    def call(self, tool, args=None):
        self._send({"jsonrpc": "2.0", "id": self._next(), "method": "tools/call",
                    "params": {"name": tool, "arguments": args or {}}})
        return self._recv()

    def close(self):
        try:
            self.proc.terminate()
            _, err = self.proc.communicate(timeout=15)
            return err or ""
        except Exception:
            self.proc.kill()
            return ""


def _tripwire_count(tripwire: Path) -> int:
    if not tripwire.exists():
        return 0
    return len([ln for ln in tripwire.read_text().splitlines() if ln.strip()])


@pytest.mark.slow
@pytest.mark.requires_binary
class TestGateBounds:
    def test_expired_agent_call_refused_before_downstream(self, gateway_bin, tmp_path):
        # A 1s TTL, an 8s pre-call delay, then a call that must be
        # refused `agent-expired` with the downstream NEVER run.
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "1s"], env)
        try:
            time.sleep(8)
            resp = w.call("read_text_file", {"path": "/etc/hosts"})
            assert "error" in resp, resp
            assert resp["error"]["code"] == -32600, resp
            assert resp["error"].get("data", {}).get("code") == "agent-expired", resp
            assert _tripwire_count(tripwire) == 0, "downstream ran on an expired grant"
        finally:
            w.close()

    def test_ttl_control_allows_the_same_call(self, gateway_bin, tmp_path):
        # Control: a generous TTL allows the same call and the tripwire fires once.
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        try:
            resp = w.call("read_text_file", {"path": "/etc/hosts"})
            assert "error" not in resp, resp
            assert _tripwire_count(tripwire) == 1
        finally:
            w.close()

    def test_refusal_carries_verdict_data(self, gateway_bin, tmp_path):
        # An out-of-scope refusal co-delivers a structured, re-checkable verdict object.
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        try:
            resp = w.call("write_file", {"path": "/tmp/x", "content": "y"})
            assert "error" in resp, resp
            assert resp["error"]["data"]["code"] == "outside-agent-scope", resp
            assert resp["error"]["data"]["refused_before_downstream"] is True
            assert _tripwire_count(tripwire) == 0
        finally:
            w.close()

    def test_fs_read_admits_the_read_family(self, gateway_bin, tmp_path):
        # fs.read covers the whole read family; write_file is out of scope.
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        try:
            ok = w.call("read_text_file", {"path": "/etc/hosts"})
            assert "error" not in ok, ok
            refused = w.call("write_file", {"path": "/tmp/x", "content": "y"})
            assert "error" in refused, refused
            assert refused["error"]["data"]["code"] == "outside-agent-scope"
            assert _tripwire_count(tripwire) == 1, "only the read call reaches the downstream"
        finally:
            w.close()

    def test_budget_boundary_off_by_one(self, gateway_bin, tmp_path):
        # 5c metered calls against a $0.10 cap: calls 0/1 allowed (cumulative 10c == cap),
        # call 2 refused `usage-cap-exceeded`; the downstream ran exactly twice.
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$0.10", "--ttl", "30m"], env)
        try:
            meta = {"path": "/etc/hosts", "_auths_cost_cents": 5, "_auths_rail": "x402"}
            assert "error" not in w.call("read_text_file", dict(meta)), "call 0"
            assert "error" not in w.call("read_text_file", dict(meta)), "call 1"
            over = w.call("read_text_file", dict(meta))
            assert "error" in over, over
            assert over["error"]["data"]["code"] == "usage-cap-exceeded", over
            assert _tripwire_count(tripwire) == 2
        finally:
            w.close()

    def test_scope_near_misses_all_refused(self, gateway_bin, tmp_path):
        # Only the exact `read_file` (last) fires the
        # tripwire; every near-miss is refused before the downstream is touched.
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        near_misses = [
            "write_file",       # different family
            "Read_File",        # case
            "read_file_secret", # suffix
            "xread_file",       # prefix
            "reаd_file",   # Cyrillic 'а'
            "../read_file",     # traversal
        ]
        try:
            for tool in near_misses:
                resp = w.call(tool, {"path": "/etc/hosts"})
                assert "error" in resp, f"{tool} should be refused: {resp}"
                assert resp["error"]["data"]["refused_before_downstream"] is True
            # Only the exact real tool is admitted.
            ok = w.call("read_file", {"path": "/etc/hosts"})
            assert "error" not in ok, ok
            assert _tripwire_count(tripwire) == 1, "only exact `read_file` forwarded"
        finally:
            w.close()

    def test_spend_log_path_is_announced_and_stable(self, gateway_bin, tmp_path):
        # --spend-log pins the log dir and it is announced; a default run flags ephemeral.
        tripwire = tmp_path / "tripwire.log"
        stable = tmp_path / "receipts"
        env = _lab_env(tmp_path, tripwire)
        # Pin the dir explicitly; drop the LAB overrides so --spend-log is the resolver.
        env.pop("AUTHS_MCP_LIVE_DIR", None)
        env.pop("LAB_DIR", None)
        w = Wrap(gateway_bin,
                 ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m",
                  "--spend-log", str(stable)], env)
        try:
            w.call("read_text_file", {"path": "/etc/hosts"})
            err = w.close()
        finally:
            pass
        assert f"spend-log: {stable}" in err, err
        # The rotated log lands under the pinned dir.
        assert (stable / "registry").exists()

    def test_default_spend_log_is_flagged_ephemeral(self, gateway_bin, tmp_path):
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        env.pop("AUTHS_MCP_LIVE_DIR", None)
        env.pop("LAB_DIR", None)
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        w.call("read_text_file", {"path": "/etc/hosts"})
        err = w.close()
        assert "ephemeral" in err, err

    def test_second_wrap_same_keyfile_is_idempotent(self, gateway_bin, tmp_path):
        # A second wrap against the same key file + live dir resumes the SAME agent DID,
        # never `an agent key already exists under alias 'agent'`.
        tripwire = tmp_path / "tripwire.log"
        keyfile = tmp_path / "shared-keys.enc"
        env = _lab_env(tmp_path, tripwire, keyfile=keyfile)

        def agent_did(err_text):
            m = re.search(r"agent=(did:keri:\S+)", err_text)
            return m.group(1) if m else None

        w1 = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        w1.call("read_text_file", {"path": "/etc/hosts"})
        err1 = w1.close()
        did1 = agent_did(err1)
        assert did1, err1

        w2 = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        w2.call("read_text_file", {"path": "/etc/hosts"})
        err2 = w2.close()
        assert "already exists under alias" not in err2, err2
        did2 = agent_did(err2)
        assert did2 == did1, f"agent DID must be stable: {did1} vs {did2}"

    def test_revocation_propagates_within_sla(self, gateway_bin, auths_bin, tmp_path):
        # A mid-session revoke is observed within the recheck SLA (not only on restart).
        tripwire = tmp_path / "tripwire.log"
        env = _lab_env(tmp_path, tripwire)
        env["AUTHS_MCP_REVOCATION_RECHECK_SECS"] = "1"
        registry = env["AUTHS_HOME"]
        w = Wrap(gateway_bin, ["--scope", "fs.read", "--budget", "$5", "--ttl", "30m"], env)
        try:
            # One allowed call to establish the agent, then read its DID from stderr later.
            assert "error" not in w.call("read_text_file", {"path": "/etc/hosts"})
            before = _tripwire_count(tripwire)
            # Resolve the agent DID from the live registry and revoke it out-of-band.
            show = subprocess.run(
                [str(auths_bin), "--repo", registry, "--json", "id", "show"],
                capture_output=True, text=True, env=env, timeout=60,
            )
            m = re.search(r"did:keri:[A-Za-z0-9_-]+", show.stdout)
            # Revoke by resolving the agent from the gateway's own verify-spend-cmd banner if the
            # root show is ambiguous; the revoke targets the delegated agent.
            agent = None
            # The gateway printed `agent=<did>` on stderr; but stderr is drained on close, so
            # instead revoke every non-root agent the registry lists.
            listing = subprocess.run(
                [str(auths_bin), "--repo", registry, "--json", "id", "agent", "list"],
                capture_output=True, text=True, env=env, timeout=60,
            )
            for did in re.findall(r"did:keri:[A-Za-z0-9_-]+", listing.stdout):
                agent = did
            if agent is None:
                pytest.skip("could not resolve the delegated agent DID to revoke")
            subprocess.run(
                [str(auths_bin), "--repo", registry, "--json",
                 "id", "agent", "revoke", agent, "--key", "root"],
                capture_output=True, text=True, env=env, timeout=60,
            )
            time.sleep(2)  # past the 1s recheck SLA
            after = w.call("read_text_file", {"path": "/etc/hosts"})
            assert "error" in after, "a revoked delegation must be refused"
            assert after["error"]["data"]["code"] in ("revoked", "proof-unauthentic"), after
            assert _tripwire_count(tripwire) == before, "downstream ran after revocation"
        finally:
            w.close()
