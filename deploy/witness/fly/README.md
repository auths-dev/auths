# deploy/witness/fly — network.auths.dev on Fly

The first-party Auths witness, `network.auths.dev`, is a Fly deployment of the
**open** `auths-witness-node` image built by [`../Dockerfile`](../Dockerfile) —
the exact artifact anyone else runs. This directory is *only config*; there is
no `network.auths.dev`-specific code (see
[`docs/plans/network/network-auths-dev.md`](../../../docs/plans/network/network-auths-dev.md)).

## What it runs

`serve --roles anchor,kel,cosign,registry` — one node that both **witnesses
members** (KEL receipting, spend anchoring, checkpoint cosigning) and **serves
what it holds**: the party `refs/auths/*` read-only over git smart-HTTP, so the
node is its own resolution surface.

| Surface | URL |
|---|---|
| Resolve KELs (git) | `git fetch https://network.auths.dev +refs/auths/*:refs/auths/*` |
| Submit a spend anchor | `POST https://network.auths.dev/v1/anchor` |
| Latest anchor / withholding view | `GET https://network.auths.dev/v1/anchor/{seed_id}` |
| Health | `GET https://network.auths.dev/health` |

Writes are never anonymous: the registry is **read-only over git** (no
`receive-pack` path exists). Members' KELs enter via signed KEL receipting, a
peer sync, or a maintainer push — not a push to this endpoint.

## First-time setup

Run everything from the **repo root** (the Dockerfile's build context is the
workspace):

| Step | Command |
|---|---|
| Create the app (don't deploy yet) | `fly launch --no-deploy --copy-config --config deploy/witness/fly/fly.toml --name auths-network` |
| Create the durable volume | `fly volumes create witness_data --region lhr --size 1 --app auths-network` |
| Set the witness seed (stable, secret) | `fly secrets set WITNESS_SEED="$(openssl rand -hex 32)" --app auths-network` |
| Deploy | `fly deploy --config deploy/witness/fly/fly.toml` |
| Add the domain | `fly certs add network.auths.dev --app auths-network` (then point DNS at the app) |

The `WITNESS_SEED` is the node's identity — **keep it stable across restarts**; a
changed seed is a *new* witness. Store it only in Fly secrets.

## Bootstrapping the registry

The node **auto-initializes** an empty `/data/registry` on first boot — an empty
registry (no members yet) is a valid state, and it serves an empty
`refs/auths/*` until populated. Populate it by:

- **members receipting** their KELs to this witness (the KEL role), or
- **a peer sync** from another witness — `fly ssh console -a auths-network -C "witness-node sync-registry --from <peer-url> --registry /data/registry"`, or
- a maintainer push of vetted KELs.

## After deploy — verify it is a real witness

```bash
# resolution surface is live (empty until members exist):
git ls-remote https://network.auths.dev

# it fail-closes, it doesn't fake success:
curl -fsS https://network.auths.dev/health

# publish its member key + endpoint in the /network directory (auths-site) so
# members can name it in their witness set.
```

## Operations

| Task | Command |
|---|---|
| Logs | `fly logs --app auths-network` |
| Shell (has the volume) | `fly ssh console --app auths-network` |
| Rotate to a new seed (⚠ new identity) | `fly secrets set WITNESS_SEED=… ` then redeploy |
| Scale memory | edit `[[vm]] memory` in `fly.toml`, redeploy |

Never run more than one machine for a given seed: the anchor store is a
single-writer, and two writers on one identity is exactly the equivocation the
witness exists to prevent (`auto_stop_machines = 'off'`, `min_machines_running =
1`, single machine).

## Troubleshooting

Everything below was learned bringing the first witness up. The build itself is
reliable — nearly every "deploy failure" here was the **node rejecting its
runtime environment on boot**, visible only after the image was already built.

### First rule: get the node's *real* error (Fly hides a fast crash)

A witness that rejects its environment exits in a few seconds. Fly's log
shipping usually misses that window, so `fly logs` shows nothing and the deploy
just reports `timeout reached waiting for health checks`. **Do not guess from
that** — read the stderr directly:

```bash
# 1. Confirm it's crash-looping and see the exit code (1 = the node refused something).
fly machine status <machine-id> --app auths-network      # read the Event Logs block
#   stopped │ exit │ … exit_code=1,oom_killed=false,requested_stop=false   ← a real crash

# 2. Free the volume, then launch a one-off that just sleeps (so you can poke at it).
fly machine destroy <machine-id> --app auths-network --force
IMG=$(fly image show --app auths-network --json | jq -r '.Ref')   # or the image: line from a deploy log
fly machine run "$IMG" 900 --app auths-network \
  --volume witness_data:/data --entrypoint /bin/sleep

# 3. ssh in and run the EXACT command with a timeout — stderr comes back to YOUR terminal.
SEED=0000000000000000000000000000000000000000000000000000000000000000   # any 64 hex chars
fly ssh console --app auths-network --machine <diag-id> -C "sh -c '
  id; git --version;
  WITNESS_SEED=$SEED timeout 6 /usr/local/bin/witness-node \
    serve --roles kel,cosign,registry --data-dir /data --registry /data/registry \
    --bind 127.0.0.1:3399 --witness-name diag 2>&1 | head -40'"

# 4. Clean up (and free the volume for the real deploy).
fly machine destroy <diag-id> --app auths-network --force
```

The one-off mounts the *real* volume and runs the *real* binary, so it
reproduces the failure exactly — and `fly ssh console -C` hands you the output
that `fly logs` swallowed. This one technique found both bugs below.

### Known failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `dockerfile '…/fly/deploy/witness/Dockerfile' not found` (doubled path) | flyctl resolves `[build] dockerfile` relative to the **config file's directory**, not the build context | Make the path relative to the config: `dockerfile = '../Dockerfile'`. Keep running `fly deploy` from the **repo root** (that's the build context `COPY . .` needs). |
| `WARN Build context is ~940 MB` and slow uploads | `COPY . .` ships the whole working tree | `.dockerignore` the non-source trees (`tests/`, `.recurve/`, `.chunkhound/`, `site/`, `target/`, venvs). |
| `registry init: … '/data/registry' is not owned by current user; class=Config (7); code=Owner (-36)` | libgit2's dubious-ownership check (CVE-2022-24765): the repo dir's owner ≠ the process user (a container volume, or a dir a *previous* run created as a different user) | The node opts out at startup (`git2::opts::set_verify_owner_validation(false)`). Debugging by hand: `git config --global --add safe.directory '*'`, or `chown -R <user> /data`. |
| Machine `exit_code=1` immediately; anything under `/data` fails to create | a freshly attached Fly volume mounts **root-owned**, so a non-root container user cannot create its state there | Run the node as **root** — its data dir *is* the volume, and the VM/container is the isolation boundary (the node exposes only HTTP). |
| `anchor role: this witness has no synced registry` | intentional fail-closed (RT-2): the anchor role refuses to start without parties to resolve against | A *fresh* witness has no members yet — boot with `--roles kel,cosign,registry` (the registry role serves an empty namespace fine). Add `anchor` once the registry has parties. |
| deploy ends `timeout reached waiting for health checks` + Fly API `request canceled` | almost always the machine is **crash-looping** (health never comes up), not Fly flakiness | Don't retry blindly — run the "First rule" recipe; `fly machine status` will show the `exit_code`. |
| A previous crash left junk / wrong-owned files on the volume | half-initialized state from failed boots | Wipe it from a one-off shell: `fly ssh console -C "sh -c 'rm -rf /data/registry /data/*.db /data/log /data/duplicity'"`, then redeploy (the node re-initializes on boot). |

### Redeploying after a code fix

`fly deploy --config deploy/witness/fly/fly.toml` from the repo root. A source
change re-runs the full release compile (~3–4 min); only pure config/`fly.toml`
edits are fast. After it reports success, always confirm the node actually
serves — a green build is not a healthy witness:

```bash
curl -fsS https://<app>.fly.dev/health              # {"status":"ok","witness_did":"did:key:…"}
git ls-remote https://<app>.fly.dev                 # registry smart-HTTP responds (empty is fine)
```
