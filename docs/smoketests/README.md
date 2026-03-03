# Smoke Tests

End-to-end smoke tests that exercise the full Auths + Radicle stack locally.

## `end_to_end.py`

Orchestrates the complete local stack from scratch:

```
Phase 0   Prerequisites & Build       cargo build auths, radicle-httpd; verify rad, node, npm
Phase 1   Set up two Radicle nodes    rad auth with deterministic seeds, extract DIDs
Phase 2   Create Auths identity       auths id create → KERI controller DID
Phase 3   Link devices                auths key import + auths device link (x2)
Phase 4   Create Radicle project      git init → rad init (new project, not a clone)
Phase 5   Start Radicle nodes         node 1 (P2P:19876) + node 2 (P2P:19877), connect
Phase 6   Push signed patches         Device 1: signed commit + git push rad HEAD:refs/patches
                                      Device 2: clone via node 2, signed commit + push
Phase 7   Start radicle-httpd         Serves API on port 8080 (reads from node 1 storage)
Phase 8   Start frontend              npm run build + serve on port 3000
Phase 9   Verify HTTP API             Asserts on /delegates, /identity/kel, /attestations, /patches
Phase 10  Summary                     Prints all URLs for manual browser inspection
```

### Prerequisites

| Tool | Install |
|------|---------|
| `rad` CLI | https://radicle.xyz |
| Rust toolchain | https://rustup.rs |
| Node.js 20+ / npm | https://nodejs.org |
| Python 3.10+ | System or pyenv |

Repository layout expected:

```
workspace/
├── auths-base/
│   └── auths/              ← this repo (auths CLI + auths-radicle crate)
└── radicle-base/
    └── radicle-explorer/   ← frontend + modified radicle-httpd
        └── radicle-httpd/  ← radicle-httpd with auths-radicle integration
```

### Quick start

```bash
# Full run — builds everything, runs all phases, cleans up
python3 docs/smoketests/end_to_end.py

# Skip builds (use existing binaries)
python3 docs/smoketests/end_to_end.py --skip-build

# Keep services running for manual browser testing
python3 docs/smoketests/end_to_end.py --keep-alive

# Skip the frontend (API-only testing)
python3 docs/smoketests/end_to_end.py --no-frontend

# Open browser to the profile page automatically
python3 docs/smoketests/end_to_end.py --keep-alive --open-browser

# Use a fixed workspace (persists between runs)
python3 docs/smoketests/end_to_end.py --workspace /tmp/my-e2e

# ALL
python3 docs/smoketests/end_to_end.py --keep-alive --open-browser
```

### What gets built

| Binary | Source | Build command |
|--------|--------|---------------|
| `auths` + `auths-sign` | `crates/auths-cli` | `cargo build --release --package auths_cli` |
| `radicle-httpd` | `radicle-explorer/radicle-httpd` | `cargo build` (debug) |
| `@auths/verifier` | `packages/auths-verifier-ts` | `wasm-pack build` + `npm run build:ts` |
| Frontend | `radicle-explorer` | `npm install && npm run build` |

The modified `radicle-httpd` includes `auths-radicle` as a dependency, which adds
the `/delegates/{did}`, `/identity/{did}/kel`, and `/identity/{did}/attestations`
endpoints needed for KERI identity display.

### Ports

| Service | Port | Purpose |
|---------|------|---------|
| Radicle node 1 | 19876 | P2P protocol |
| Radicle node 2 | 19877 | P2P protocol |
| radicle-httpd | 8080 | HTTP API (matches `defaultLocalHttpdPort` in explorer config) |
| Frontend | 3000 | Vite preview server |

### Manual verification

After running with `--keep-alive`, open these URLs in your browser:

- **Node view**: http://localhost:3000/nodes/127.0.0.1:8080
- **Project**: http://localhost:3000/nodes/127.0.0.1:8080/{PROJECT_RID}
- **Profile (KERI)**: http://localhost:3000/nodes/127.0.0.1:8080/users/{CONTROLLER_DID}

The script prints the actual URLs with your test DIDs at the end.

On the profile page you should see:
- KERI Identity badge (Verified/Unverified)
- Linked Devices list (2 devices)
- Person/Device view toggle
- Repositories from both devices

### Workspace layout

The script creates an isolated workspace under `/tmp/auths-e2e-XXXXX/`:

```
/tmp/auths-e2e-XXXXX/
├── .auths/                 # Auths identity storage (Git repo)
├── rad-node-1/             # RAD_HOME for node 1
├── rad-node-2/             # RAD_HOME for node 2
├── e2e-project/            # Project (node 1 working copy)
├── e2e-project-node2/      # Project (node 2 clone)
├── node1.seed              # 32-byte Ed25519 seed
├── node2.seed              # 32-byte Ed25519 seed
├── metadata.json           # Identity metadata
├── keys.enc                # Encrypted keychain
├── allowed_signers         # Git SSH signing keys
└── logs/
    ├── node1.log
    ├── node2.log
    ├── httpd.log
    └── frontend.log
```

### Environment variables

The script sets these automatically for headless operation:

| Variable | Value | Purpose |
|----------|-------|---------|
| `AUTHS_KEYCHAIN_BACKEND` | `file` | File-based keychain (no OS keyring) |
| `AUTHS_KEYCHAIN_FILE` | `{workspace}/keys.enc` | Keychain location |
| `AUTHS_PASSPHRASE` | `e2e-smoke-test` | Keychain passphrase |
| `RAD_HOME` | `{workspace}/rad-node-{N}` | Per-node Radicle home |
| `RAD_PASSPHRASE` | `e2e-rad` | Node passphrase |
| `RAD_KEYGEN_SEED` | Deterministic hex | Reproducible key generation |

### Troubleshooting

**"radicle-httpd not found"**: Build it from the explorer repo:
```bash
cd radicle-base/radicle-explorer/radicle-httpd && cargo build
```

**"delegates endpoint returned 404"**: You're running the stock `radicle-httpd` instead
of the modified one. Make sure to build from `radicle-explorer/radicle-httpd/` which
includes the `auths-radicle` dependency.

**Port conflicts**: If port 8080 or 3000 is in use, stop the conflicting service.
The ports must match the explorer's `defaultLocalHttpdPort` config (8080).

**Node fails to start**: Check `logs/node1.log`. Common cause: leftover `control.sock`
from a previous run. Use `--workspace /tmp/my-e2e` with a fresh directory, or delete
the stale workspace.

**Clone fails between nodes**: Nodes need a few seconds to discover each other. The
script waits 2-3 seconds after connecting. If clone still fails, check `logs/node2.log`
for connection errors.
