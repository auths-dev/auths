# murmur-relay deployment kit (Fly.io)

The **untrusted store-and-forward mailbox** for Murmur. A device drops a sealed
envelope into a mailbox; the recipient drains it. The relay never sees plaintext, a
sender AID, or a phone number — only an opaque mailbox id and opaque ciphertext. It is
*designed* to be untrusted, which is why a single shared, publicly-hosted relay is safe
and is the model every messenger uses: the security is in the payload, not the server.

This directory is the kit to stand one up on Fly.io as the **default relay** the apps
auto-connect to — so users just QR each other and message, no terminal, no setup.

> The relay binary lives in `crates/murmur-relay` and is unchanged by this kit. This is
> deploy config only: a `Dockerfile`, a `fly.toml`, and this runbook.

## What it does today

- Serves `GET /` (health → `murmur-relay <version>`; pings the backend), `POST /deposit`,
  `GET /drain/{mailbox}`, and `PUT`/`GET /prekey/{aid}` (the first-contact directory).
- **Pluggable backend.** With no `MURMUR_RELAY_REDIS_URL` it runs in-memory (dev/demo — a
  restart drops the queue). With a Redis URL it is **durable**: a relay restart loses
  nothing, and many stateless relay machines share one Redis. **Use Redis for anything
  real** — see [Durable backlog](#durable-backlog-redis--use-this-for-real-traffic) below.
  Design + benchmarks: [`docs/PRD-durable-relay.md`](docs/PRD-durable-relay.md),
  [`docs/perf-results.md`](docs/perf-results.md).
- Caps: 1024 msgs / 16 MiB per mailbox; messages expire on a TTL (default 30 d) so the
  relay is a buffer, not an archive. The global bound is Redis `maxmemory` (set on the
  instance).

It does **not** terminate TLS itself (the Fly edge does), federate, or run any crypto — it
cannot decrypt what it carries. Durable or not, it only ever holds an opaque mailbox id
and opaque ciphertext.

## Posture

- **distroless-static, non-root** (uid 65532), static musl binary — minimal attack
  surface, no shell, no package manager in the runtime image.
- **No secrets** anywhere — nothing to inject, nothing to leak. The relay holds no keys.
- **HTTPS for free** — Fly's edge terminates TLS and proxies plaintext to the container,
  so the public URL is `https://<app>.fly.dev`. Point the app there and you need **no
  App Transport Security exception** (that exception is only for the LAN-http dev path).
- **Metadata caveat (honest):** content is sealed, but the relay still sees deposit/drain
  timing, source IPs, and which mailbox/AID is fetched. Mailbox ids are already a PRF of
  the pairwise session secret (unlinkable to your AID). Reducing the rest (sealed-sender
  style, fetch privacy) is tracked separately.

## Durable backlog (Redis) — use this for real traffic

In-memory is fine for a demo, but a relay restart (every deploy, host move, crash) drops
every undelivered message. Point the relay at Redis and a restart **loses nothing**; the
relay tier also becomes stateless, so you can run several machines behind one Redis.

Provision a managed Redis next to the app (Upstash via Fly), wire it as a secret, and set
the memory cap:

```bash
# A managed Redis (Upstash) in your region; prints a rediss:// URL with auth + TLS.
fly redis create                      # or: fly ext upstash-redis create

# Tell the relay to use it (a secret, not in fly.toml).
fly secrets set --app <your-app> \
  MURMUR_RELAY_REDIS_URL='rediss://default:<password>@<host>:<port>'

# The global backlog bound is Redis maxmemory + noeviction (set on the Upstash plan /
# instance). Per-mailbox caps + message TTL are enforced by the relay.
```

Redeploy and the boot log reads `… backend: redis (durable)`. If the Redis URL is set but
unreachable at boot, the relay **crash-loops** (fail-fast) rather than serving errors —
Fly will surface it.

**Tuning** (all optional env; secrets/`fly secrets set`):

| Env | Default | Meaning |
|---|---|---|
| `MURMUR_RELAY_REDIS_URL` | *(unset → in-memory)* | `redis://` / `rediss://` (TLS). Set → durable. |
| `MURMUR_RELAY_MSG_TTL_SECS` | `2592000` (30 d) | undrained-message expiry (sliding per mailbox) |
| `MURMUR_RELAY_DEDUP_TTL_SECS` | `86400` (1 d) | replay-recognition horizon |
| `MURMUR_RELAY_PREKEY_TTL_SECS` | `2592000` (30 d) | published-bundle expiry |
| `MURMUR_RELAY_MAX_MSGS_PER_MAILBOX` | `1024` | per-mailbox message cap |
| `MURMUR_RELAY_MAX_BYTES_PER_MAILBOX` | `16777216` | per-mailbox byte cap |

**Sizing:** budget ~**800 B of Redis per undrained 256 B message** (the at-rest encoding is
a known ~3× overhead — see `docs/perf-results.md`); a 512 MB–1 GB Redis holds a large
offline backlog. One relay + one small Redis does **34k deposit/drain round-trips/s at p99
1.7 ms** locally — scale relay machines (`fly scale count N`) and Redis memory independently.

## Prerequisites

```bash
brew install flyctl      # or: curl -L https://fly.io/install.sh | sh
fly auth login
```

## First deploy

Run from the **auths repo root** (the build context must be the whole workspace — the
relay crate pulls in `murmur-core` and its deps):

```bash
# 1. Create the app (pick a globally-unique name; update `app` in fly.toml to match)
fly apps create your-murmur-relay

# 2. Build + deploy (Fly builds the Dockerfile remotely)
fly deploy --config deploy/murmur-relay/fly.toml \
           --dockerfile deploy/murmur-relay/Dockerfile .
```

First build pulls the crate's dep graph and compiles under musl — a few minutes; later
deploys are cached.

## Verify

```bash
curl https://your-murmur-relay.fly.dev/        # → murmur-relay 0.1.3

# full transport round-trip (same shape as the NET-1 probe)
curl -s -X POST https://your-murmur-relay.fly.dev/deposit \
  -H 'content-type: application/json' \
  -d '{"to_mailbox":"mbx-smoke","ciphertext":[1,2,3]}'        # → {"outcome":"queued"}
curl -s https://your-murmur-relay.fly.dev/drain/mbx-smoke     # → [{"to_mailbox":"mbx-smoke","ciphertext":[1,2,3]}]
```

## Point the app at it

In Murmur on **each** device: **You ▸ Relays & witnesses ▸ Message relay** →
`https://your-murmur-relay.fly.dev` → **Connect**. Once both devices show *Connected*,
QR each other and message — with no terminal running anywhere.

(Long-term, this URL is baked in as the app's default and the contact QR carries each
user's home relay, so even this one-time step disappears — see "Next" below.)

## Operate

```bash
fly status                       # machines, health, region
fly logs                         # tail; look for "listening on http://0.0.0.0:8080"
fly scale memory 1024            # bump RAM if you raise the queue caps
fly deploy --config deploy/murmur-relay/fly.toml --dockerfile deploy/murmur-relay/Dockerfile .   # redeploy
fly apps destroy your-murmur-relay   # tear down
```

## Cost / scaling

- Default `fly.toml`: **one always-on** `shared-cpu-1x` / 512 MB machine (a few $/mo).
- **With Redis, the relay tier is stateless** — `fly scale count N` (or more regions) all
  share one Redis, so you scale relay machines and Redis memory independently. Without
  Redis, keep it to one machine (each has its own in-memory queue).
- Cheaper, idle-friendly: `auto_stop_machines = "suspend"` + `min_machines_running = 0`.
  Safe **with Redis** (state is in Redis, not the machine); with the in-memory backend it
  drops anything queued while suspended.

## Next (not in this kit)

- **Bake this URL as the app's default relay** + auto-connect on launch → removes the
  manual "Connect" step.
- **Relay-in-the-QR (federation):** the contact code carries each user's home relay, so
  two people on different relays still reach each other — the step that keeps a default
  relay from hardening into centralization.
- **Endpoint delivery-acks** (the hybrid's second half — app-side; see the PRD §8) and a
  more compact at-rest encoding (base64/binary instead of JSON number arrays — ~3× memory
  win, `docs/perf-results.md`).
