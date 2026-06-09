# get.auths.dev

Serves `scripts/install.sh` (fetched live from `main`, 5-minute edge cache) so
`curl -fsSL https://get.auths.dev | sh` works. Hosted on Vercel because the
`auths.dev` zone lives on Vercel DNS (same team as the main site) — a
Cloudflare Worker can't bind the domain without moving the zone.

Routes:

| Path | Behavior |
|------|----------|
| `/` | the install script (`Content-Type: application/x-sh`) |
| `/health` | `ok` |
| anything else | 302 → auths.dev docs |

## Deploy

```bash
cd deploy/get-auths-dev
npx vercel deploy --prod
```

One-time setup (already done): create the project on the team that owns
`auths.dev`, then attach the domain — Vercel auto-creates the DNS record:

```bash
npx vercel link
npx vercel domains add get.auths.dev
```

No per-release action is needed: the function reads `scripts/install.sh`
from GitHub at request time, so pushing to `main` updates the served script
within the cache window.
