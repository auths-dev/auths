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

- Serves `GET /` (health → `murmur-relay <version>`), `POST /deposit`,
  `GET /drain/{mailbox}`, and `PUT`/`GET /prekey/{aid}` (the first-contact directory).
- Stores everything **in memory** (`MailboxStore` + a prekey map). There is **no disk
  state and no volume** — a restart drops whatever is queued. That is acceptable by
  design: store-and-forward is transient and the app's outbox re-sends. (A durable
  backing store is future work.)
- Caps memory: 1024 msgs / 16 MiB per mailbox, **256 MiB global** queue, 4096-entry
  dedup window. The 512 MB VM in `fly.toml` sits comfortably above that.

It does **not** terminate TLS itself (the Fly edge does), persist, federate, or run any
crypto — it cannot decrypt what it carries.

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

- Default here: **one always-on** `shared-cpu-1x` / 512 MB machine (a few $/mo) so the
  in-memory queue is never dropped mid-conversation.
- Cheaper, idle-friendly: set `auto_stop_machines = "suspend"` and
  `min_machines_running = 0` in `fly.toml` — Fly wakes the machine on the next request,
  at the cost of dropping anything queued while it was suspended.
- Run more than one region by adding machines (`fly scale count 2 --region lhr`); note
  each machine has its **own** in-memory queue until a shared backing store lands, so
  keep it single-machine until then.

## Next (not in this kit)

- **Bake this URL as the app's default relay** + auto-connect on launch → removes the
  manual "Connect" step.
- **Relay-in-the-QR (federation):** the contact code carries each user's home relay, so
  two people on different relays still reach each other — the step that keeps a default
  relay from hardening into centralization.
- **Durability + a lean no-`proofs` build + env-var config** for the relay crate.
