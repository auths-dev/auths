"""E2E: the witness-network duplicity funnel.

These drive the shipped binaries the way an operator and a counterparty do:

* the anchor role refuses to serve against an unsynced registry (the readiness
  gate) rather than booting healthy and then rejecting every submission;
* `auths anchor verify` re-checks a real, self-contained duplicity proof offline
  — no witness contacted — and rejects a tampered copy (the regulator's command);
* the watcher pushes a withholding alert to a configured webhook the moment a
  watched seed goes dark, instead of only writing a log line.

The proofs here are signed with a Python-held Ed25519 key against the exact
`party_signing_bytes` canonicalization the node commits to, so what the CLI
verifies is a genuine cryptographic contradiction, not a fixture blob.
"""

import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

crypto = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _find_binary(env_var: str, name: str):
    if path := os.environ.get(env_var):
        p = Path(path)
        if p.exists():
            return p
    workspace_root = Path(__file__).resolve().parent.parent.parent
    for profile in ("debug", "release"):
        cand = workspace_root / "target" / profile / name
        if cand.exists():
            return cand
    return None


@pytest.fixture(scope="session")
def auths_bin():
    b = _find_binary("AUTHS_BIN", "auths")
    if b is None:
        pytest.skip("auths binary not built (set AUTHS_BIN or build with cargo)")
    return b


@pytest.fixture(scope="session")
def witness_node_bin():
    b = _find_binary("WITNESS_NODE_BIN", "witness-node")
    if b is None:
        pytest.skip("witness-node binary not built (set WITNESS_NODE_BIN or build with cargo)")
    return b


@pytest.fixture(scope="session")
def monitor_bin():
    b = _find_binary("MONITOR_BIN", "auths-monitor")
    if b is None:
        pytest.skip("auths-monitor binary not built (set MONITOR_BIN or build with cargo)")
    return b


# ---------------------------------------------------------------------------
# Anchor signing that mirrors the node's canonical party message
# ---------------------------------------------------------------------------

SEED_HEX = "ab" * 32
SAID = "EWitSet"
THRESHOLD = 1


def _party_signing_bytes(seed_hex, index, head_hex, cumulative, ts, said, threshold):
    """The RFC-8785 canonical bytes the party signs — sorted keys, compact."""
    message = {
        "v": "auths-anchor/party/v1",
        "seedId": seed_hex,
        "index": index,
        "head": head_hex,
        "cumulative": str(cumulative),
        "ts": ts,
        "witnessSet": {"said": said, "threshold": threshold},
    }
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode()


def _wire_anchor(sk, index, head_hex, cumulative, when, *, signature=None):
    ts = int(when.timestamp())
    if signature is None:
        signature = sk.sign(
            _party_signing_bytes(SEED_HEX, index, head_hex, cumulative, ts, SAID, THRESHOLD)
        )
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "seed_id": SEED_HEX,
        "index": index,
        "head": head_hex,
        "cumulative": cumulative,
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "witness_set": {"said": SAID, "threshold": THRESHOLD},
        "sig_party": {
            "curve": "ed25519",
            "public_key": pub.hex(),
            "signature": signature.hex(),
        },
    }


def _duplicity_proof():
    """A genuine same-party fork at one (seed, index): two heads, one key."""
    sk = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
    when = datetime(2024, 1, 1, tzinfo=timezone.utc)
    anchor_a = _wire_anchor(sk, 1, "01" * 32, 100, when)
    anchor_b = _wire_anchor(sk, 1, "02" * 32, 100, when)
    return {
        "seed_id": SEED_HEX,
        "index": 1,
        "anchor_a": anchor_a,
        "anchor_b": anchor_b,
    }


def _run_auths(auths_bin, args, tmp_path, timeout=30):
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "AUTHS_HOME": str(tmp_path / ".auths"),
        "NO_COLOR": "1",
    }
    return subprocess.run(
        [str(auths_bin)] + args,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# 1. Readiness gate: an unsynced registry refuses to serve
# ---------------------------------------------------------------------------


def test_empty_registry_node_reports_not_ready(witness_node_bin, tmp_path):
    empty_registry = tmp_path / "registry"
    empty_registry.mkdir()  # exists, but is not a synced git repo
    data_dir = tmp_path / "wdata"

    env = {**os.environ, "WITNESS_SEED": "11" * 32}
    result = subprocess.run(
        [
            str(witness_node_bin),
            "serve",
            "--roles",
            "anchor",
            "--data-dir",
            str(data_dir),
            "--registry",
            str(empty_registry),
            "--witness-name",
            "e2e-w1",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    assert result.returncode != 0, "an unsynced registry must not serve"
    assert "no synced registry" in result.stderr, result.stderr


# ---------------------------------------------------------------------------
# 2. The regulator's command: verify a proof offline, reject a tampered one
# ---------------------------------------------------------------------------


def test_cli_verifies_proof_and_rejects_tamper(auths_bin, tmp_path):
    proof = _duplicity_proof()
    proof_path = tmp_path / "duplicity-proof.json"
    proof_path.write_text(json.dumps(proof))

    ok = _run_auths(auths_bin, ["anchor", "verify", "--proof", str(proof_path)], tmp_path)
    assert ok.returncode == 0, f"stdout={ok.stdout}\nstderr={ok.stderr}"
    assert "DUPLICITY PROVEN" in ok.stdout, ok.stdout

    tampered = _duplicity_proof()
    head = bytearray.fromhex(tampered["anchor_b"]["head"])
    head[0] ^= 0xFF
    tampered["anchor_b"]["head"] = head.hex()
    tampered_path = tmp_path / "tampered-proof.json"
    tampered_path.write_text(json.dumps(tampered))

    bad = _run_auths(auths_bin, ["anchor", "verify", "--proof", str(tampered_path)], tmp_path)
    assert bad.returncode != 0, "a tampered proof must not verify"
    assert "INVALID duplicity proof" in bad.stderr, bad.stderr


# ---------------------------------------------------------------------------
# 3. The watcher pushes a withholding alert to a webhook when a seed goes dark
# ---------------------------------------------------------------------------


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(handler_cls, port):
    server = HTTPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_watcher_pushes_on_dark_seed(monitor_bin, tmp_path):
    # A witness that serves one long-stale anchor for the watched seed. The
    # withholding path never verifies the party signature, so a placeholder one
    # is enough to exercise the gap detection.
    stale = datetime(2000, 1, 1, tzinfo=timezone.utc)
    dark_anchor = {
        "seed_id": SEED_HEX,
        "index": 1,
        "head": "01" * 32,
        "cumulative": 100,
        "timestamp": stale.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "witness_set": {"said": SAID, "threshold": THRESHOLD},
        "sig_party": {"curve": "ed25519", "public_key": "00" * 32, "signature": "00" * 64},
    }

    class Witness(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == f"/v1/anchor/{SEED_HEX}":
                body = json.dumps({"anchor": dark_anchor}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    received = []
    received_lock = threading.Lock()

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("content-length", 0))
            payload = self.rfile.read(length)
            with received_lock:
                received.append(payload)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    witness_port = _free_port()
    sink_port = _free_port()
    witness = _serve(Witness, witness_port)
    sink = _serve(Sink, sink_port)
    witness_url = f"http://127.0.0.1:{witness_port}"
    sink_url = f"http://127.0.0.1:{sink_port}/"

    env = {
        **os.environ,
        "AUTHS_REGISTRY_URL": witness_url,  # /v1/log/checkpoint 404s → cycle errors, loop continues
        "AUTHS_MONITOR_INTERVAL_SECS": "1",
        "AUTHS_MONITOR_STATE_PATH": str(tmp_path / "monitor_state.json"),
        "AUTHS_LOG_PUBLIC_KEY": "00" * 32,
        "AUTHS_WATCH_WITNESSES": witness_url,
        "AUTHS_WATCH_SEEDS": SEED_HEX,
        "AUTHS_WATCH_GAP_SECS": "0",
        "AUTHS_ALERT_WEBHOOK": sink_url,
    }

    proc = subprocess.Popen(
        [str(monitor_bin)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 15
        alert = None
        while time.time() < deadline and alert is None:
            with received_lock:
                for raw in received:
                    event = json.loads(raw)
                    if event.get("kind") == "withholding":
                        alert = event
                        break
            time.sleep(0.2)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        witness.shutdown()
        sink.shutdown()

    assert alert is not None, "the watcher never pushed a withholding alert"
    assert alert["event"]["seed_id"] == SEED_HEX
    assert alert["event"]["gap_seconds"] > 0
