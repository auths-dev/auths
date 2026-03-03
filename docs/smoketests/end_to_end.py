#!/usr/bin/env python3
"""
Radicle + Auths Full-Stack E2E Smoke Test

Orchestrates the entire local stack:
  1. Builds auths CLI, radicle-httpd, and the radicle-explorer frontend
  2. Creates two Radicle nodes with deterministic keys
  3. Creates a KERI identity and links both nodes as devices
  4. Creates a new Radicle project (git repo)
  5. Starts a Radicle node to host the project
  6. Pushes a signed patch from device 1
  7. Pushes a signed patch from device 2
  8. Starts radicle-httpd to serve the API
  9. Starts the radicle-explorer frontend
 10. Runs HTTP assertions against the API
 11. Prints URLs for manual browser inspection

Usage:
python3 docs/smoketests/end_to_end.py
# skip cargo/npm builds
python3 docs/smoketests/end_to_end.py --skip-build
# keep services running for manual testing      
python3 docs/smoketests/end_to_end.py --keep-alive
# skip frontend build/serve
python3 docs/smoketests/end_to_end.py --no-frontend
# open browser at the end
python3 docs/smoketests/end_to_end.py --open-browser
# ALL
python3 docs/smoketests/end_to_end.py --keep-alive --open-browser

Requirements:
    - Python 3.10+
    - rad CLI installed (https://radicle.xyz)
    - Rust toolchain (cargo)
    - Node.js 20+ and npm
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Paths ────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
AUTHS_REPO = SCRIPT_DIR.parent.parent  # auths-base/auths
EXPLORER_REPO = AUTHS_REPO.parent.parent / "radicle-base" / "radicle-explorer"
HTTPD_CRATE = EXPLORER_REPO / "radicle-httpd"
VERIFIER_CRATE = AUTHS_REPO / "crates" / "auths-verifier"
VERIFIER_TS = AUTHS_REPO / "packages" / "auths-verifier-ts"

# ── Ports ────────────────────────────────────────────────────────────────────

NODE1_P2P_PORT = 19876
NODE2_P2P_PORT = 19877
HTTPD_PORT = 8080  # must match defaultLocalHttpdPort in explorer config
FRONTEND_PORT = 3000

# ── Colors ───────────────────────────────────────────────────────────────────

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{NC}"


# ── Logging ──────────────────────────────────────────────────────────────────


def phase(title: str) -> None:
    print()
    print(_c(BLUE, "=" * 64))
    print(_c(BOLD, f"  {title}"))
    print(_c(BLUE, "=" * 64))
    print()


def info(msg: str) -> None:
    print(f"  {_c(CYAN, chr(0x2192))} {msg}")


def ok(msg: str) -> None:
    print(f"  {_c(GREEN, chr(0x2713))} {msg}")


def fail(msg: str) -> None:
    print(f"  {_c(RED, chr(0x2717))} {msg}")


def warn(msg: str) -> None:
    print(f"  {_c(YELLOW, chr(0x26A0))} {msg}")


# ── Subprocess helpers ───────────────────────────────────────────────────────


def run(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    capture: bool = True,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Run a command, merging env with os.environ."""
    merged_env = {**os.environ, **(env or {})}
    try:
        result = subprocess.run(
            cmd,
            env=merged_env,
            cwd=cwd,
            capture_output=capture,
            text=True,
            check=check,
            timeout=timeout,
        )
        return result
    except subprocess.CalledProcessError as e:
        fail(f"Command failed: {' '.join(cmd)}")
        if e.stdout:
            for line in e.stdout.strip().splitlines():
                print(f"    {line}")
        if e.stderr:
            for line in e.stderr.strip().splitlines():
                print(f"    {_c(DIM, line)}")
        raise
    except subprocess.TimeoutExpired:
        fail(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise


def spawn(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    log_path: Path | None = None,
) -> subprocess.Popen[str]:
    """Spawn a background process. Stdout/stderr go to log_path or DEVNULL."""
    merged_env = {**os.environ, **(env or {})}
    if log_path:
        log_file = open(log_path, "w")  # noqa: SIM115
        stdout = log_file
        stderr = subprocess.STDOUT
    else:
        log_file = None  # type: ignore[assignment]
        stdout = subprocess.DEVNULL  # type: ignore[assignment]
        stderr = subprocess.DEVNULL  # type: ignore[assignment]
    proc = subprocess.Popen(
        cmd,
        env=merged_env,
        cwd=cwd,
        stdout=stdout,
        stderr=stderr,
        text=True,
    )
    return proc


def wait_for_http(url: str, *, timeout: int = 30, label: str = "") -> bool:
    """Poll an HTTP endpoint until it responds 2xx."""
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status < 400:
                    return True
        except Exception as e:
            last_err = str(e)
        time.sleep(0.5)
    warn(f"Timed out waiting for {label or url}: {last_err}")
    return False


def http_get_json(url: str) -> Any:
    """GET a URL, parse JSON."""
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


# ── Workspace ────────────────────────────────────────────────────────────────


@dataclass
class Workspace:
    root: Path
    auths_home: Path = field(init=False)
    node1_home: Path = field(init=False)
    node2_home: Path = field(init=False)
    node1_seed_path: Path = field(init=False)
    node2_seed_path: Path = field(init=False)
    project_dir: Path = field(init=False)
    project_node2_dir: Path = field(init=False)
    keychain_file: Path = field(init=False)
    metadata_file: Path = field(init=False)
    allowed_signers: Path = field(init=False)
    logs_dir: Path = field(init=False)

    # Populated during execution
    node1_did: str = ""
    node2_did: str = ""
    node1_nid: str = ""
    node2_nid: str = ""
    controller_did: str = ""
    project_rid: str = ""

    # Background processes
    _procs: list[subprocess.Popen] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self.auths_home = self.root / ".auths"
        self.node1_home = self.root / "rad-node-1"
        self.node2_home = self.root / "rad-node-2"
        self.node1_seed_path = self.root / "node1.seed"
        self.node2_seed_path = self.root / "node2.seed"
        self.project_dir = self.root / "e2e-project"
        self.project_node2_dir = self.root / "e2e-project-node2"
        self.keychain_file = self.root / "keys.enc"
        self.metadata_file = self.root / "metadata.json"
        self.allowed_signers = self.root / "allowed_signers"
        self.logs_dir = self.root / "logs"

        for d in [
            self.auths_home,
            self.node1_home,
            self.node2_home,
            self.logs_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def base_env(self) -> dict[str, str]:
        """Shared env vars for headless operation."""
        return {
            "AUTHS_KEYCHAIN_BACKEND": "file",
            "AUTHS_KEYCHAIN_FILE": str(self.keychain_file),
            "AUTHS_PASSPHRASE": "e2e-smoke-test",
            "RAD_PASSPHRASE": "e2e-rad",
            "GIT_AUTHOR_NAME": "Smoke Tester",
            "GIT_AUTHOR_EMAIL": "smoke@test.local",
            "GIT_COMMITTER_NAME": "Smoke Tester",
            "GIT_COMMITTER_EMAIL": "smoke@test.local",
        }

    def node_env(self, node: int) -> dict[str, str]:
        """Env for a specific Radicle node."""
        home = self.node1_home if node == 1 else self.node2_home
        return {**self.base_env(), "RAD_HOME": str(home)}

    def auths_env(self) -> dict[str, str]:
        """Env for auths CLI."""
        return self.base_env()

    def register_proc(self, proc: subprocess.Popen) -> None:
        self._procs.append(proc)

    def cleanup(self, rad: str | None = None) -> None:
        """Stop Radicle nodes and kill all background processes."""
        if rad:
            for home in [self.node1_home, self.node2_home]:
                try:
                    subprocess.run(
                        [rad, "node", "stop"],
                        env={**os.environ, **self.base_env(), "RAD_HOME": str(home)},
                        capture_output=True, text=True, timeout=5,
                    )
                except Exception:
                    pass
        for proc in reversed(self._procs):
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        self._procs.clear()


# ── Binary resolution ────────────────────────────────────────────────────────


def find_auths_bin() -> Path:
    for profile in ["release", "debug"]:
        p = AUTHS_REPO / "target" / profile / "auths"
        if p.is_file() and os.access(p, os.X_OK):
            return p
    raise FileNotFoundError("auths binary not found. Run: cargo build --release --package auths-cli")


def find_auths_sign_bin() -> Path:
    for profile in ["release", "debug"]:
        p = AUTHS_REPO / "target" / profile / "auths-sign"
        if p.is_file() and os.access(p, os.X_OK):
            return p
    raise FileNotFoundError("auths-sign binary not found. Run: cargo build --release --package auths-cli")


def find_httpd_bin() -> Path:
    # Prefer locally compiled httpd from explorer (has auths-radicle integration)
    local = HTTPD_CRATE / "target" / "debug" / "radicle-httpd"
    if local.is_file() and os.access(local, os.X_OK):
        return local
    local_release = HTTPD_CRATE / "target" / "release" / "radicle-httpd"
    if local_release.is_file() and os.access(local_release, os.X_OK):
        return local_release
    # Fall back to system radicle-httpd
    system = shutil.which("radicle-httpd")
    if system:
        return Path(system)
    raise FileNotFoundError(
        "radicle-httpd not found. Run:\n"
        f"  cd {HTTPD_CRATE} && cargo build"
    )


def find_rad_bin() -> Path:
    p = shutil.which("rad")
    if p:
        return Path(p)
    raise FileNotFoundError("rad CLI not found. Install from https://radicle.xyz")


# ── Phase implementations ────────────────────────────────────────────────────


def phase_0_prerequisites(args: argparse.Namespace) -> dict[str, Path]:
    """Verify all tools exist. Optionally build."""
    phase("Phase 0: Prerequisites & Build")

    rad = find_rad_bin()
    ok(f"rad CLI: {rad}")

    if not args.skip_build:
        info("Building auths CLI (release)...")
        run(
            ["cargo", "build", "--release", "--package", "auths-cli"],
            cwd=AUTHS_REPO,
            capture=False,
        )
        ok("auths CLI built")

        info("Building radicle-httpd (debug, with auths-radicle)...")
        run(
            ["cargo", "build"],
            cwd=HTTPD_CRATE,
            capture=False,
        )
        ok("radicle-httpd built")

    auths = find_auths_bin()
    auths_sign = find_auths_sign_bin()
    httpd = find_httpd_bin()

    ok(f"auths: {auths}")
    ok(f"auths-sign: {auths_sign}")
    ok(f"radicle-httpd: {httpd}")

    v = run([str(rad), "--version"]).stdout.strip()
    info(f"rad version: {v}")
    v = run([str(auths), "--version"]).stdout.strip()
    info(f"auths version: {v}")

    if not args.no_frontend:
        node = shutil.which("node")
        npm = shutil.which("npm")
        if not node or not npm:
            raise FileNotFoundError("Node.js and npm are required for the frontend")
        ok(f"node: {node}")
        ok(f"npm: {npm}")

    return {"rad": rad, "auths": auths, "auths_sign": auths_sign, "httpd": httpd}


def phase_1_setup_nodes(ws: Workspace, bins: dict[str, Path]) -> None:
    """Initialize two Radicle nodes with deterministic keys."""
    phase("Phase 1: Set up two Radicle nodes")

    rad = str(bins["rad"])

    # Generate deterministic seeds
    node1_seed_hex = "aa" * 32
    node2_seed_hex = "bb" * 32

    ws.node1_seed_path.write_bytes(bytes.fromhex(node1_seed_hex))
    ws.node2_seed_path.write_bytes(bytes.fromhex(node2_seed_hex))

    ok("Generated deterministic seeds")

    info("Initializing node 1...")
    run(
        [rad, "auth", "--alias", "device-1"],
        env={**ws.node_env(1), "RAD_KEYGEN_SEED": node1_seed_hex},
    )

    info("Initializing node 2...")
    run(
        [rad, "auth", "--alias", "device-2"],
        env={**ws.node_env(2), "RAD_KEYGEN_SEED": node2_seed_hex},
    )

    ws.node1_did = run(
        [rad, "self", "--did"], env=ws.node_env(1)
    ).stdout.strip()
    ws.node2_did = run(
        [rad, "self", "--did"], env=ws.node_env(2)
    ).stdout.strip()

    ws.node1_nid = ws.node1_did.removeprefix("did:key:")
    ws.node2_nid = ws.node2_did.removeprefix("did:key:")

    ok(f"Node 1 DID: {ws.node1_did}")
    ok(f"Node 2 DID: {ws.node2_did}")

    assert ws.node1_did.startswith("did:key:z6Mk"), f"Unexpected DID format: {ws.node1_did}"
    assert ws.node2_did.startswith("did:key:z6Mk"), f"Unexpected DID format: {ws.node2_did}"


def phase_2_create_identity(ws: Workspace, bins: dict[str, Path]) -> None:
    """Create a KERI identity using the auths CLI."""
    phase("Phase 2: Create Auths identity")

    auths = str(bins["auths"])

    ws.metadata_file.write_text(json.dumps({
        "xyz.radicle.project": {"name": "e2e-smoke-test"},
        "profile": {"name": "Smoke Test Identity"},
    }))

    info("Creating identity...")
    result = run(
        [
            auths, "--repo", str(ws.auths_home), "id", "create",
            "--metadata-file", str(ws.metadata_file),
            "--local-key-alias", "identity-key",
        ],
        env=ws.auths_env(),
        check=False,
    )
    output = result.stdout + result.stderr
    for line in output.strip().splitlines():
        print(f"    {line}")

    # Extract controller DID
    for line in output.splitlines():
        if "Controller DID:" in line:
            ws.controller_did = line.split("Controller DID:")[-1].strip()
            break

    if not ws.controller_did:
        info("Falling back to `auths id show`...")
        show = run(
            [auths, "--repo", str(ws.auths_home), "id", "show"],
            env=ws.auths_env(),
            check=False,
        )
        for line in (show.stdout + show.stderr).splitlines():
            if "Controller DID" in line:
                ws.controller_did = line.split(":")[-1].strip()
                # Reconstruct the full DID if truncated
                if not ws.controller_did.startswith("did:"):
                    parts = line.split()
                    for p in parts:
                        if p.startswith("did:keri:"):
                            ws.controller_did = p
                            break

    assert ws.controller_did, "Failed to extract controller DID"
    ok(f"Controller DID: {ws.controller_did}")


def phase_3_link_devices(ws: Workspace, bins: dict[str, Path]) -> None:
    """Import device keys and link both devices to the identity."""
    phase("Phase 3: Link devices to identity")

    auths = str(bins["auths"])
    env = ws.auths_env()

    for i, (alias, seed_path, did, note) in enumerate([
        ("node1-key", ws.node1_seed_path, ws.node1_did, "Radicle Device 1"),
        ("node2-key", ws.node2_seed_path, ws.node2_did, "Radicle Device 2"),
    ], 1):
        info(f"Importing device {i} key...")
        run(
            [
                auths, "key", "import",
                "--alias", alias,
                "--seed-file", str(seed_path),
                "--controller-did", ws.controller_did,
            ],
            env=env,
        )
        ok(f"Device {i} key imported as '{alias}'")

        info(f"Linking device {i}...")
        run(
            [
                auths, "--repo", str(ws.auths_home), "device", "link",
                "--identity-key-alias", "identity-key",
                "--device-key-alias", alias,
                "--device-did", did,
                "--note", note,
            ],
            env=env,
        )
        ok(f"Device {i} linked: {did}")

    # Verify
    result = run(
        [auths, "--repo", str(ws.auths_home), "device", "list"],
        env=env,
    )
    device_list = result.stdout
    assert ws.node1_did in device_list, "Node 1 DID not in device list"
    assert ws.node2_did in device_list, "Node 2 DID not in device list"
    ok("Both devices appear in device list")

    info("Device list:")
    for line in device_list.strip().splitlines():
        print(f"    {line}")


def phase_4_create_project(ws: Workspace, bins: dict[str, Path]) -> None:
    """Create a new Radicle project (git repo) from node 1."""
    phase("Phase 4: Create Radicle project")

    rad = str(bins["rad"])
    env = ws.node_env(1)

    # Create a git repo first
    ws.project_dir.mkdir(parents=True, exist_ok=True)
    run(["git", "init"], cwd=ws.project_dir, env=env)
    run(["git", "config", "user.name", "Smoke Tester"], cwd=ws.project_dir)
    run(["git", "config", "user.email", "smoke@test.local"], cwd=ws.project_dir)
    run(["git", "config", "commit.gpgsign", "false"], cwd=ws.project_dir)

    (ws.project_dir / "README.md").write_text(
        "# E2E Smoke Test Project\n\nCreated by the auths+radicle E2E smoke test.\n"
    )
    run(["git", "add", "."], cwd=ws.project_dir, env=env)
    run(["git", "commit", "-m", "Initial commit"], cwd=ws.project_dir, env=env)

    ok("Git repo initialized with initial commit")

    # Start node 1 temporarily to init the radicle project.
    # Use an ephemeral port (not NODE1_P2P_PORT) so the real Phase 5
    # node can bind cleanly after this one exits.
    info("Starting node 1 for project init...")
    run(
        [rad, "node", "start", "--", "--listen", "0.0.0.0:0"],
        env=env,
        check=False,
    )
    time.sleep(3)

    info("Initializing Radicle project...")
    result = run(
        [
            rad, "init",
            "--name", "e2e-smoke-test",
            "--description", "Auths+Radicle E2E smoke test project",
            "--public",
            "--no-confirm",
        ],
        cwd=ws.project_dir,
        env=env,
        check=False,
    )
    output = result.stdout + result.stderr
    for line in output.strip().splitlines():
        print(f"    {line}")

    # Extract RID
    for line in output.splitlines():
        for word in line.split():
            if word.startswith("rad:"):
                ws.project_rid = word.rstrip(".")
                break
        if ws.project_rid:
            break

    if not ws.project_rid:
        # Try rad inspect
        inspect = run([rad, "inspect"], cwd=ws.project_dir, env=env, check=False)
        for word in (inspect.stdout + inspect.stderr).split():
            if word.startswith("rad:"):
                ws.project_rid = word.rstrip(".")
                break

    assert ws.project_rid, "Failed to extract project RID"
    ok(f"Project RID: {ws.project_rid}")

    # Stop the temporary node and wait for full cleanup
    info("Stopping temporary node...")
    run([rad, "node", "stop"], env=env, check=False)
    # Wait for the daemon to fully exit (control socket removed)
    control_sock = ws.node1_home / "node" / "control.sock"
    for _ in range(10):
        if not control_sock.exists():
            break
        time.sleep(0.5)
    # Verify it's actually stopped
    for _ in range(5):
        r = run([rad, "node", "status"], env=env, check=False)
        if r.returncode != 0:
            break
        time.sleep(1)
    time.sleep(1)


def phase_5_start_node(ws: Workspace, bins: dict[str, Path]) -> None:
    """Start node 1 as persistent background process. Connect node 2."""
    phase("Phase 5: Start Radicle nodes")

    rad = str(bins["rad"])

    info(f"Starting node 1 (P2P: {NODE1_P2P_PORT})...")
    run(
        [rad, "node", "start", "--", "--listen", f"0.0.0.0:{NODE1_P2P_PORT}"],
        env=ws.node_env(1),
        check=False,
    )
    time.sleep(3)

    info(f"Starting node 2 (P2P: {NODE2_P2P_PORT})...")
    run(
        [rad, "node", "start", "--", "--listen", f"0.0.0.0:{NODE2_P2P_PORT}"],
        env=ws.node_env(2),
        check=False,
    )
    time.sleep(3)

    # Verify nodes are running via rad node status
    for node_num, home in [(1, ws.node1_home), (2, ws.node2_home)]:
        node_env = ws.node_env(node_num)
        r = run([rad, "node", "status"], env=node_env, check=False)
        if r.returncode == 0:
            ok(f"Node {node_num} is running")
        else:
            # Node logs may be rotated (node.log, node.log.1, node.log.2)
            node_dir = home / "node"
            log_files = sorted(node_dir.glob("node.log*"), reverse=True) if node_dir.exists() else []
            if log_files:
                fail(f"Node {node_num} failed to start. Last log lines ({log_files[0].name}):")
                for line in log_files[0].read_text().strip().splitlines()[-5:]:
                    print(f"    {_c(DIM, line)}")
            else:
                fail(f"Node {node_num} failed to start (no log found)")
            raise RuntimeError(f"Node {node_num} not running")

    # Connect node 2 to node 1
    info("Connecting node 2 to node 1...")
    run(
        [rad, "node", "connect", f"{ws.node1_nid}@127.0.0.1:{NODE1_P2P_PORT}",
         "--timeout", "10"],
        env=ws.node_env(2),
        check=False,
    )
    time.sleep(2)
    ok("Nodes connected")


def phase_6_push_patches(ws: Workspace, bins: dict[str, Path]) -> dict[str, str]:
    """Push signed patches from both devices."""
    phase("Phase 6: Signed patches from both devices")

    rad = str(bins["rad"])
    auths = str(bins["auths"])
    auths_sign = str(bins["auths_sign"])
    env_base = ws.auths_env()

    # Export public keys for allowed_signers
    info("Exporting device public keys...")
    pub1 = run(
        [auths, "key", "export", "--alias", "node1-key",
         "--passphrase", "e2e-smoke-test", "--format", "pub"],
        env=env_base,
    ).stdout.strip()
    pub2 = run(
        [auths, "key", "export", "--alias", "node2-key",
         "--passphrase", "e2e-smoke-test", "--format", "pub"],
        env=env_base,
    ).stdout.strip()

    ws.allowed_signers.write_text(
        f"smoke@test.local {pub1}\nsmoke@test.local {pub2}\n"
    )
    ok("allowed_signers file created")

    # Configure git signing for the project
    for key, val in [
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", auths_sign),
        ("gpg.ssh.allowedSignersFile", str(ws.allowed_signers)),
        ("commit.gpgsign", "true"),
    ]:
        run(["git", "config", key, val], cwd=ws.project_dir)

    patch_ids: dict[str, str] = {}

    # ── Device 1: signed commit + push patch ──────────────────────────
    info("Device 1: creating signed commit...")
    run(["git", "config", "user.signingKey", "auths:node1-key"], cwd=ws.project_dir)
    run(
        ["git", "checkout", "-b", "feature-device1"],
        cwd=ws.project_dir,
        env={**ws.node_env(1), **env_base},
        check=False,
    )
    (ws.project_dir / "device1.txt").write_text("Change from device 1\n")
    run(["git", "add", "device1.txt"], cwd=ws.project_dir, env={**ws.node_env(1), **env_base})
    run(
        ["git", "commit", "-m", "Signed commit from device 1"],
        cwd=ws.project_dir,
        env={**ws.node_env(1), **env_base},
    )
    ok("Device 1 signed commit created")

    info("Device 1: pushing patch...")
    push1 = run(
        ["git", "push", "rad", "HEAD:refs/patches"],
        cwd=ws.project_dir,
        env={**ws.node_env(1), **env_base},
        check=False,
    )
    push1_out = push1.stdout + push1.stderr
    for line in push1_out.strip().splitlines():
        print(f"    {line}")

    # Extract patch ID
    for word in push1_out.split():
        if len(word) == 40 and all(c in "0123456789abcdef" for c in word):
            patch_ids["device1"] = word
            break

    if patch_ids.get("device1"):
        ok(f"Device 1 patch: {patch_ids['device1']}")
    else:
        warn("Could not extract device 1 patch ID from push output")

    # ── Device 2: clone, signed commit + push patch ───────────────────
    info("Device 2: cloning project via node 2...")

    # Verify both nodes are still running before clone
    node2_ready = True
    for node_num, home in [(1, ws.node1_home), (2, ws.node2_home)]:
        r = run([rad, "node", "status"], env=ws.node_env(node_num), check=False)
        if r.returncode != 0:
            node_dir = home / "node"
            log_files = sorted(node_dir.glob("node.log*"), reverse=True) if node_dir.exists() else []
            if log_files:
                warn(f"Node {node_num} died. Last log lines ({log_files[0].name}):")
                for line in log_files[0].read_text().strip().splitlines()[-5:]:
                    print(f"    {_c(DIM, line)}")
            else:
                warn(f"Node {node_num} is not running (no log found)")
            node2_ready = False

    if not node2_ready:
        warn("Nodes not running. Skipping device 2 clone.")

    # Seed the project on node 2
    if node2_ready:
        run(
            [rad, "seed", ws.project_rid],
            env=ws.node_env(2),
            check=False,
        )
        time.sleep(3)

    result = run(
        [rad, "clone", ws.project_rid, str(ws.project_node2_dir),
         "--seed", ws.node1_nid, "--timeout", "30"],
        env=ws.node_env(2),
        check=False,
    ) if node2_ready else None

    if result:
        clone_out = result.stdout + result.stderr
        for line in clone_out.strip().splitlines():
            print(f"    {line}")

    if result and ws.project_node2_dir.exists() and (ws.project_node2_dir / ".git").exists():
        ok("Device 2 cloned the project")

        # Configure git signing for node 2 clone
        for key, val in [
            ("user.name", "Smoke Tester Device2"),
            ("user.email", "smoke@test.local"),
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", auths_sign),
            ("gpg.ssh.allowedSignersFile", str(ws.allowed_signers)),
            ("commit.gpgsign", "true"),
            ("user.signingKey", "auths:node2-key"),
        ]:
            run(["git", "config", key, val], cwd=ws.project_node2_dir)

        info("Device 2: creating signed commit...")
        run(
            ["git", "checkout", "-b", "feature-device2"],
            cwd=ws.project_node2_dir,
            env={**ws.node_env(2), **env_base},
            check=False,
        )
        (ws.project_node2_dir / "device2.txt").write_text("Change from device 2\n")
        run(
            ["git", "add", "device2.txt"],
            cwd=ws.project_node2_dir,
            env={**ws.node_env(2), **env_base},
        )
        run(
            ["git", "commit", "-m", "Signed commit from device 2"],
            cwd=ws.project_node2_dir,
            env={**ws.node_env(2), **env_base},
        )
        ok("Device 2 signed commit created")

        info("Device 2: pushing patch...")
        push2 = run(
            ["git", "push", "rad", "HEAD:refs/patches"],
            cwd=ws.project_node2_dir,
            env={**ws.node_env(2), **env_base},
            check=False,
        )
        push2_out = push2.stdout + push2.stderr
        for line in push2_out.strip().splitlines():
            print(f"    {line}")

        for word in push2_out.split():
            if len(word) == 40 and all(c in "0123456789abcdef" for c in word):
                patch_ids["device2"] = word
                break

        if patch_ids.get("device2"):
            ok(f"Device 2 patch: {patch_ids['device2']}")
        else:
            warn("Could not extract device 2 patch ID from push output")
    else:
        warn("Device 2 clone failed. Skipping device 2 patch.")

    # Sync device 2's patch from node 2 → node 1.
    #
    # Radicle gossip can fail due to sigrefs divergence when two nodes
    # independently modify a project.  The fix is:
    #   1. Node 1 follows node 2 (so it's willing to replicate)
    #   2. Node 2 announces its refs
    #   3. Node 1 fetches explicitly from node 2 using --seed <NID>@<ADDR>
    #   4. Verify with `rad patch list` on node 1
    node2_seed = f"{ws.node2_nid}@127.0.0.1:{NODE2_P2P_PORT}"

    info("Node 1: following node 2...")
    run(
        [rad, "follow", ws.node2_nid, "--alias", "node2"],
        env=ws.node_env(1),
        check=False,
    )

    info("Node 2: announcing refs...")
    run(
        [rad, "sync", "--announce", ws.project_rid, "--timeout", "10"],
        env=ws.node_env(2),
        check=False,
    )
    time.sleep(3)

    synced = False
    for attempt in range(5):
        info(f"Node 1: fetching from node 2 via --seed (attempt {attempt + 1}/5)...")
        r = run(
            [rad, "sync", "--fetch", "--seed", node2_seed,
             ws.project_rid, "--timeout", "30", "--debug"],
            env=ws.node_env(1),
            check=False,
        )
        sync_out = r.stdout + r.stderr
        for line in sync_out.strip().splitlines():
            print(f"      {_c(DIM, line)}")

        # Verify: count patches on node 1
        patch_check = run(
            [rad, "patch", "list"],
            cwd=ws.project_dir,
            env=ws.node_env(1),
            check=False,
        )
        patch_list = patch_check.stdout + patch_check.stderr
        # Count non-empty lines that look like patch entries
        patch_count = sum(
            1 for line in patch_list.strip().splitlines()
            if line.strip() and not line.startswith("Nothing")
        )
        info(f"Node 1 patch count: {patch_count}")
        if patch_count >= 2:
            synced = True
            break

        # Re-announce from both sides and retry
        run(
            [rad, "sync", "--announce", ws.project_rid, "--timeout", "10"],
            env=ws.node_env(2),
            check=False,
        )
        time.sleep(2)
        run(
            [rad, "sync", "--announce", ws.project_rid, "--timeout", "10"],
            env=ws.node_env(1),
            check=False,
        )
        time.sleep(3)

    if synced:
        ok("Nodes synced: both patches visible on node 1")
    else:
        warn("Sync incomplete. Trying full bidirectional sync as fallback...")
        # Last resort: full bidirectional sync (fetch + announce) from both sides
        run(
            [rad, "sync", ws.project_rid, "--timeout", "30"],
            env=ws.node_env(2),
            check=False,
        )
        time.sleep(2)
        run(
            [rad, "sync", ws.project_rid, "--timeout", "30",
             "--seed", node2_seed],
            env=ws.node_env(1),
            check=False,
        )
        time.sleep(2)
        # Final check
        patch_check = run(
            [rad, "patch", "list"],
            cwd=ws.project_dir,
            env=ws.node_env(1),
            check=False,
        )
        patch_list = patch_check.stdout + patch_check.stderr
        patch_count = sum(
            1 for line in patch_list.strip().splitlines()
            if line.strip() and not line.startswith("Nothing")
        )
        if patch_count >= 2:
            ok(f"Fallback sync succeeded: {patch_count} patches on node 1")
        else:
            warn(f"Sync still incomplete: only {patch_count} patch(es) on node 1. "
                 "Device 2's patch may not appear in the API.")

    return patch_ids


def phase_7_start_httpd(ws: Workspace, bins: dict[str, Path]) -> None:
    """Start radicle-httpd serving node 1's storage."""
    phase("Phase 7: Start radicle-httpd")

    httpd = str(bins["httpd"])

    info(f"Starting radicle-httpd on port {HTTPD_PORT}...")
    httpd_env = {**ws.node_env(1), "AUTHS_HOME": str(ws.auths_home)}
    proc = spawn(
        [httpd, "--listen", f"0.0.0.0:{HTTPD_PORT}"],
        env=httpd_env,
        log_path=ws.logs_dir / "httpd.log",
    )
    ws.register_proc(proc)

    url = f"http://127.0.0.1:{HTTPD_PORT}/api/v1"
    if wait_for_http(url, timeout=15, label="radicle-httpd"):
        ok(f"radicle-httpd is ready at http://127.0.0.1:{HTTPD_PORT}")
    else:
        fail("radicle-httpd failed to start. Check logs/httpd.log")
        raise RuntimeError("httpd not ready")


def phase_8_start_frontend(ws: Workspace, args: argparse.Namespace) -> None:
    """Build and serve the radicle-explorer frontend."""
    phase("Phase 8: Start radicle-explorer frontend")

    if args.no_frontend:
        warn("--no-frontend specified, skipping frontend")
        return

    if not EXPLORER_REPO.exists():
        warn(f"radicle-explorer not found at {EXPLORER_REPO}, skipping frontend")
        return

    if not args.skip_build:
        info("Building @auths/verifier WASM module...")
        wasm_out = VERIFIER_TS / "wasm"
        run(
            [
                "wasm-pack", "build",
                "--target", "bundler",
                "--no-default-features",
                "--features", "wasm",
            ],
            cwd=VERIFIER_CRATE,
            capture=False,
            timeout=300,
        )
        # Copy wasm-pack output from default pkg/ to verifier-ts/wasm/
        pkg_dir = VERIFIER_CRATE / "pkg"
        if pkg_dir.exists():
            if wasm_out.exists():
                shutil.rmtree(wasm_out)
            shutil.copytree(pkg_dir, wasm_out)
            # npm respects .gitignore when packing file: deps; .npmignore overrides it
            (wasm_out / ".npmignore").write_text("# Override .gitignore for npm\n.gitignore\n")
        ok("WASM module built")

        info("Installing @auths/verifier TypeScript dependencies...")
        run(["npm", "install"], cwd=VERIFIER_TS, capture=False, timeout=120)
        ok("verifier-ts dependencies installed")

        info("Building @auths/verifier TypeScript...")
        run(["npm", "run", "build:ts"], cwd=VERIFIER_TS, capture=False, timeout=120)
        ok("@auths/verifier built")

        info("Installing npm dependencies (fresh @auths/verifier)...")
        # Remove cached copy so npm re-packs the file: dependency with wasm files
        cached = EXPLORER_REPO / "node_modules" / "@auths" / "verifier"
        if cached.is_symlink():
            cached.unlink()
        elif cached.exists():
            shutil.rmtree(cached)
        run(["npm", "install"], cwd=EXPLORER_REPO, capture=False, timeout=300)
        ok("npm install complete")

        info("Building frontend...")
        run(["npm", "run", "build"], cwd=EXPLORER_REPO, capture=False, timeout=300)
        ok("Frontend built")

    info(f"Serving frontend on port {FRONTEND_PORT}...")
    proc = spawn(
        ["npm", "run", "serve", "--", "--strictPort", "--port", str(FRONTEND_PORT)],
        cwd=EXPLORER_REPO,
        log_path=ws.logs_dir / "frontend.log",
        env={
            **os.environ,
            "DEFAULT_LOCAL_HTTPD_PORT": str(HTTPD_PORT),
            "DEFAULT_HTTPD_SCHEME": "http",
        },
    )
    ws.register_proc(proc)

    url = f"http://localhost:{FRONTEND_PORT}"
    if wait_for_http(url, timeout=30, label="frontend"):
        ok(f"Frontend is ready at {url}")
    else:
        warn("Frontend failed to start. Check logs/frontend.log")


def phase_9_verify_api(ws: Workspace, patch_ids: dict[str, str]) -> None:
    """Run HTTP assertions against the API."""
    phase("Phase 9: Verify HTTP API")

    base = f"http://127.0.0.1:{HTTPD_PORT}/api/v1"

    # ── Node info ─────────────────────────────────────────────────────
    info("Checking /api/v1 ...")
    try:
        root = http_get_json(base)
        ok(f"API root responded: {root.get('service', 'unknown')}")
    except Exception as e:
        fail(f"API root failed: {e}")
        return

    # ── Delegates endpoint ────────────────────────────────────────────
    info(f"Checking delegates endpoint for {ws.controller_did} ...")
    try:
        user = http_get_json(f"{base}/delegates/{ws.controller_did}")
        info(f"Response: {json.dumps(user, indent=2)[:500]}")

        assert user.get("isKeri") is True, f"Expected isKeri=true, got {user.get('isKeri')}"
        ok("isKeri: true")

        controller_did = user.get("controllerDid")
        assert controller_did, "controllerDid is empty"
        ok(f"controllerDid: {controller_did}")

        devices = user.get("devices", [])
        assert len(devices) >= 2, f"Expected >= 2 devices, got {len(devices)}"
        ok(f"devices: {len(devices)} linked")

        assert user.get("isAbandoned") is False, "Identity should not be abandoned"
        ok("isAbandoned: false")

    except urllib.error.HTTPError as e:
        if e.code == 404:
            warn("Delegates endpoint returned 404. Modified httpd may not be running.")
            warn("Skipping remaining API assertions.")
            return
        raise
    except AssertionError as e:
        fail(str(e))
        return

    # ── KEL endpoint ──────────────────────────────────────────────────
    info("Checking KEL endpoint...")
    try:
        kel = http_get_json(f"{base}/identity/{ws.controller_did}/kel")
        assert isinstance(kel, list), f"Expected array, got {type(kel)}"
        assert len(kel) > 0, "KEL is empty"
        ok(f"KEL: {len(kel)} events")
    except urllib.error.HTTPError as e:
        warn(f"KEL endpoint failed: {e.code}")
    except AssertionError as e:
        fail(str(e))

    # ── Attestations endpoint ─────────────────────────────────────────
    info("Checking attestations endpoint...")
    try:
        atts = http_get_json(f"{base}/identity/{ws.controller_did}/attestations")
        assert isinstance(atts, list), f"Expected array, got {type(atts)}"
        assert len(atts) > 0, "Attestations empty"
        ok(f"Attestations: {len(atts)} returned")
    except urllib.error.HTTPError as e:
        warn(f"Attestations endpoint failed: {e.code}")
    except AssertionError as e:
        fail(str(e))

    # ── Repos endpoint ────────────────────────────────────────────────
    info("Checking repos...")
    try:
        repos = http_get_json(f"{base}/repos")
        assert isinstance(repos, list), f"Expected array, got {type(repos)}"
        ok(f"Repos: {len(repos)} listed")
        found = any(ws.project_rid in str(r) for r in repos)
        if found:
            ok(f"Project {ws.project_rid} found in repo list")
        else:
            warn(f"Project {ws.project_rid} not in repo list (may need sync)")
    except Exception as e:
        warn(f"Repos check failed: {e}")

    # ── Patches ───────────────────────────────────────────────────────
    if ws.project_rid:
        rid_encoded = ws.project_rid
        info(f"Checking patches for {rid_encoded}...")
        try:
            patches = http_get_json(f"{base}/repos/{rid_encoded}/patches")
            assert isinstance(patches, list), f"Expected array, got {type(patches)}"
            ok(f"Patches: {len(patches)} found")
            for p in patches:
                pid = p.get("id", "?")[:12]
                state = p.get("state", {})
                author_did = p.get("author", {}).get("id", "?")
                print(f"    Patch {pid}...  state={state}  author={author_did}")
        except Exception as e:
            warn(f"Patches check failed: {e}")


def phase_10_summary(
    ws: Workspace,
    patch_ids: dict[str, str],
    args: argparse.Namespace,
) -> None:
    """Print final summary with URLs for manual inspection."""
    phase("Summary")

    print(_c(CYAN, "  Identities:"))
    print(f"    Controller DID: {_c(BOLD, ws.controller_did)}")
    print(f"    Device 1 DID:   {ws.node1_did}")
    print(f"    Device 2 DID:   {ws.node2_did}")
    print(f"    Project RID:    {ws.project_rid}")
    print()

    print(_c(CYAN, "  Services:"))
    print(f"    radicle-httpd:  http://127.0.0.1:{HTTPD_PORT}/api/v1")
    if not args.no_frontend:
        print(f"    Frontend:       http://localhost:{FRONTEND_PORT}")
    print()

    print(_c(CYAN, "  URLs to verify manually:"))
    httpd_url = f"http://127.0.0.1:{HTTPD_PORT}/api/v1"
    print(f"    API - Delegates:    {httpd_url}/delegates/{ws.controller_did}")
    print(f"    API - KEL:          {httpd_url}/identity/{ws.controller_did}/kel")
    print(f"    API - Attestations: {httpd_url}/identity/{ws.controller_did}/attestations")
    if ws.project_rid:
        print(f"    API - Patches:      {httpd_url}/repos/{ws.project_rid}/patches")
    print()

    if not args.no_frontend:
        fe = f"http://localhost:{FRONTEND_PORT}"
        print(_c(CYAN, "  Frontend URLs:"))
        print(f"    Node view:     {fe}/nodes/127.0.0.1:{HTTPD_PORT}")
        if ws.project_rid:
            print(f"    Project:       {fe}/nodes/127.0.0.1:{HTTPD_PORT}/{ws.project_rid}")
        print(f"    User profile:  {fe}/nodes/127.0.0.1:{HTTPD_PORT}/users/{ws.controller_did}")
        if ws.node1_did:
            print(f"    Device 1:      {fe}/nodes/127.0.0.1:{HTTPD_PORT}/devices/{ws.node1_did}")
        if ws.node2_did:
            print(f"    Device 2:      {fe}/nodes/127.0.0.1:{HTTPD_PORT}/devices/{ws.node2_did}")
        print()

    print(_c(CYAN, "  Logs:"))
    print(f"    {ws.logs_dir}")
    print()

    if args.open_browser and not args.no_frontend:
        import webbrowser

        url = f"http://localhost:{FRONTEND_PORT}/nodes/127.0.0.1:{HTTPD_PORT}/users/{ws.controller_did}"
        info(f"Opening browser: {url}")
        webbrowser.open(url)


# ── Main ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Radicle + Auths Full-Stack E2E Smoke Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            This script orchestrates the full local stack: auths CLI, two Radicle
            nodes, radicle-httpd, and the radicle-explorer frontend. Both devices
            push signed patches, and the resulting state is verified via HTTP API
            and available for manual browser inspection.
        """),
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="Skip cargo/npm builds (use existing binaries)",
    )
    parser.add_argument(
        "--keep-alive", action="store_true",
        help="Keep all services running after tests for manual inspection",
    )
    parser.add_argument(
        "--no-frontend", action="store_true",
        help="Skip building and serving the frontend",
    )
    parser.add_argument(
        "--open-browser", action="store_true",
        help="Open browser to the user profile page at the end",
    )
    parser.add_argument(
        "--workspace", type=Path, default=None,
        help="Use a specific workspace directory instead of a tmpdir",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print()
    print(_c(CYAN, "  Radicle + Auths Full-Stack E2E Smoke Test"))
    print(_c(DIM, "  ─────────────────────────────────────────"))
    print()

    if args.workspace:
        ws_root = args.workspace
        ws_root.mkdir(parents=True, exist_ok=True)
    else:
        # Use /tmp directly (not the macOS per-user /var/folders/.../T/) to keep
        # paths short.  Radicle's control socket path must fit within the Unix
        # SUN_LEN limit (104 chars on macOS).  The default tempfile.mkdtemp()
        # uses a long per-user path that pushes the socket path over the limit.
        short_tmp = Path("/tmp/ae2e")
        if short_tmp.exists():
            shutil.rmtree(short_tmp)
        short_tmp.mkdir(parents=True)
        ws_root = short_tmp
    info(f"Workspace: {ws_root}")

    ws = Workspace(root=ws_root)
    rad_bin: str | None = None

    def cleanup() -> None:
        print()
        info("Cleaning up...")
        ws.cleanup(rad=rad_bin)
        if not args.workspace and not args.keep_alive:
            shutil.rmtree(ws_root, ignore_errors=True)
            info("Workspace removed")

    atexit.register(cleanup)

    def signal_handler(sig: int, frame: Any) -> None:
        print()
        warn("Interrupted. Cleaning up...")
        cleanup()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Phase 0: Prerequisites
        bins = phase_0_prerequisites(args)
        rad_bin = str(bins["rad"])

        # Phase 1: Two radicle nodes
        phase_1_setup_nodes(ws, bins)

        # Phase 2: Create KERI identity
        phase_2_create_identity(ws, bins)

        # Phase 3: Link both devices
        phase_3_link_devices(ws, bins)

        # Phase 4: Create project
        phase_4_create_project(ws, bins)

        # Phase 5: Start nodes
        phase_5_start_node(ws, bins)

        # Phase 6: Push patches from both devices
        patch_ids = phase_6_push_patches(ws, bins)

        # Phase 7: Start httpd
        phase_7_start_httpd(ws, bins)

        # Phase 8: Start frontend
        phase_8_start_frontend(ws, args)

        # Phase 9: Verify API
        phase_9_verify_api(ws, patch_ids)

        # Phase 10: Summary
        phase_10_summary(ws, patch_ids, args)

        if args.keep_alive:
            print()
            print(_c(GREEN, _c(BOLD, "  All services running. Press Ctrl+C to stop.")))
            print()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    except Exception as e:
        print()
        fail(f"E2E test failed: {e}")
        print()
        print(_c(DIM, f"  Workspace preserved at: {ws_root}"))
        print(_c(DIM, f"  Logs at: {ws.logs_dir}"))
        sys.exit(1)


if __name__ == "__main__":
    main()
