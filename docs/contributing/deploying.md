# Deploying

```mermaid
graph LR
    subgraph Backend
        A[GitHub push to main] --> B[GitHub Actions]
        B --> C[Fly.io]
        C --> D[auths-registry-server<br/>public.auths.dev]
        D --> E[(Postgres)]
        D --> F[(NVMe Volume<br/>KERI ledger)]
    end

    subgraph Frontend
        G[auths-site repo] --> H[Vercel]
        H --> I[auths.dev]
    end

    I -- API calls --> D
```

## Quick start

### Backend (Fly.io)

```bash
# One-time setup
fly launch --no-deploy
fly postgres create --name auths-registry-db
fly postgres attach auths-registry-db
fly secrets set REGISTRY_POSTGRES_URL="postgres://...from attach output..."
fly volumes create auths_ledger --size 10 --region iad

# Deploy
fly deploy --local-only
```

> Note: `fly deploy` will run all PostGres migrations as well.

After first deploy, pushes to `main` auto-deploy via GitHub Actions. Add `FLY_API_TOKEN` to your repo secrets:

```bash
fly tokens create deploy
# Paste the token into GitHub > Settings > Secrets > Actions as FLY_API_TOKEN
```

### Frontend (Vercel)

The site defaults to `https://public.auths.dev` as the registry API. Since we own `public.auths.dev`, point its DNS to the Fly app and set one env var in Vercel:

| Vercel Environment Variable | Value |
|---|---|
| `NEXT_PUBLIC_USE_FIXTURES` | `false` |

That's it. No `NEXT_PUBLIC_REGISTRY_URL` needed — the code default already points to `public.auths.dev`.

Local `.env` / `.env.local` files keep `NEXT_PUBLIC_USE_FIXTURES=true` for development with mock data.

### DNS

| Record | Type | Value |
|---|---|---|
| `public.auths.dev` | CNAME | `https://auths-registry.fly.dev` |

---

## Advanced

### Fly.io configuration

#### fly.toml

```toml
app = 'auths-registry'
primary_region = 'iad'

[build]
  dockerfile = 'Dockerfile.registry-server'

[env]
  AUTHS_BIND_ADDR = '0.0.0.0:3000'
  AUTHS_REPO_PATH = '/data/repo'
  AUTHS_LOG_LEVEL = 'info'
  AUTHS_CORS = 'true'

[[mounts]]
  source = 'auths_ledger'
  destination = '/data'

[http_service]
  internal_port = 3000
  force_https = true
  auto_stop_machines = 'off'
  auto_start_machines = true
  min_machines_running = 1

  [[http_service.checks]]
    interval = '15s'
    timeout = '2s'
    grace_period = '10s'
    method = 'get'
    path = '/v1/health'
```

Key choices:

- **Always-on**: `auto_stop_machines = 'off'`. The cryptographic engine must stay available.
- **Volume mount**: NVMe at `/data` holds the Git-backed KERI ledger. Pinned to region `iad`.
- **Health check**: `GET /v1/health` returns `{"status": "ok", "version": "..."}`.

#### Environment variables

Set via `fly.toml` `[env]` (non-sensitive) or `fly secrets set` (sensitive).

| Variable | Source | Required | Description |
|---|---|---|---|
| `REGISTRY_POSTGRES_URL` | secret | Yes | Postgres connection string |
| `AUTHS_BIND_ADDR` | fly.toml | -- | Bind address (`0.0.0.0:3000`) |
| `AUTHS_REPO_PATH` | fly.toml | -- | Git ledger path on the volume (`/data/repo`) |
| `AUTHS_LOG_LEVEL` | fly.toml | -- | Log level (`info`) |
| `AUTHS_CORS` | fly.toml | -- | Enable CORS (`true`) |
| `AUTHS_ADMIN_TOKEN` | secret | For multi-tenant | Admin provisioning token |
| `AUTHS_TENANT_BASE_PATH` | secret | For multi-tenant | Enables multi-tenant mode |
| `STRIPE_SECRET_KEY` | secret | No | Stripe billing integration |
| `STRIPE_WEBHOOK_SECRET` | secret | No | Stripe webhook verification |
| `AUTHS_REDIS_URL` | secret | No | Redis cache tiering (single-tenant only) |
| `AUTHS_RATE_LIMIT_SECRET` | secret | No | HMAC secret for IP anonymization |

#### Postgres

`fly postgres attach` injects `DATABASE_URL`, but the server reads `REGISTRY_POSTGRES_URL`. Copy the connection string from the attach output:

```bash
fly secrets set REGISTRY_POSTGRES_URL="postgres://auths_registry:PASSWORD@auths-registry-db.flycast:5432/auths_registry?sslmode=disable"
```

Migrations run automatically on server boot. The Postgres instance is only reachable within Fly's private network (`.flycast` DNS).

#### Routine operations

```bash
fly status                              # Check deployment
fly logs                                # Stream logs
fly ssh console                         # SSH into the machine
fly postgres connect -a auths-registry-db  # Postgres shell

fly scale vm shared-cpu-2x --memory 2048   # Scale the VM
fly volumes extend <volume-id> --size 20   # Extend the volume
```

#### Deploying

`fly deploy --local-only` builds on your laptop and pushes the image. This avoids OOM issues on Fly's remote builder (Rust + async-stripe is memory-heavy to compile).

For CI, `.github/workflows/deploy.yml` runs `flyctl deploy --remote-only` on every push to `main`. The Dockerfile limits `CARGO_BUILD_JOBS=2` to prevent OOM on remote builders.

Zero-downtime: Fly detaches the NVMe volume from the old machine, attaches it to the new one, and swaps the load balancer.

### Vercel configuration

The frontend is a Next.js app deployed on Vercel from the `auths-site` repo.

#### Environment variables

| Variable | Production | Preview/Dev |
|---|---|---|
| `NEXT_PUBLIC_USE_FIXTURES` | `false` | `true` |
| `NEXT_PUBLIC_REGISTRY_URL` | _(not set, defaults to `https://public.auths.dev`)_ | _(not set)_ |

Setting `NEXT_PUBLIC_REGISTRY_URL` is only needed if you want to point to a different backend (e.g. a staging Fly app):

```
NEXT_PUBLIC_REGISTRY_URL=https://auths-registry-staging.fly.dev
```

#### How the frontend connects

`apps/web/src/lib/api/registry.ts` contains:

```typescript
const REGISTRY_BASE_URL =
  process.env.NEXT_PUBLIC_REGISTRY_URL ?? 'https://public.auths.dev';
```

When `NEXT_PUBLIC_USE_FIXTURES=true`, all fetch functions return mock data from `fixtures.ts` instead of hitting the API. This is the default for local development.

#### API endpoints consumed

| Endpoint | Purpose |
|---|---|
| `GET /v1/artifacts?package=` | Search signed artifacts |
| `GET /v1/pubkeys?platform=&namespace=` | Fetch public keys by platform |
| `GET /v1/identities/{did}` | Fetch identity by DID |
| `GET /v1/activity/recent` | Recent packages and identities |
