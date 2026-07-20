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
