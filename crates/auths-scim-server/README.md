# auths-scim-server

A SCIM 2.0 provisioning server for Auths, exposed as a library `router()` that is
mountable both standalone (the `auths-scim-server` binary) and nested inside
`auths-api`'s control plane. It is the thin HTTP presentation boundary for SCIM:
it serves discovery, authenticates the per-tenant channel, and maps domain errors
to the RFC 7644 `urn:ietf:params:scim:api:messages:2.0:Error` envelope.

**KERI/registry is the source of truth.** There is no authoritative database
here — the archived server's Postgres + fake-DID path is deliberately not
reproduced. Provisioning writes through real identity-lifecycle workflows
(Joiner → delegated org identity; Leaver → off-boarding), wired in later tasks.

## What ships today (skeleton)

- `GET /scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` — read-only
  discovery, served from the shipped `auths-scim` types, **unauthenticated** (as
  Okta/Entra expect).
- `GET /scim/v2/Users` — auth-gated; returns an empty list until lifecycle wiring
  lands.
- `GET /health` — liveness.
- Bearer-token tenant auth (`AuthenticatedTenant` extractor) and RFC 7644 error
  mapping (`ScimServerError`).

## Accepted risk: static bearer token

SCIM clients (Okta, Microsoft Entra) authenticate with a **static bearer token** —
the protocol speaks nothing else. This is a tension with Auths' DeviceDID-signature
default, accepted and contained:

- The token authenticates the **provisioning channel only**. The provisioned
  *identity* is still a real delegated KERI identity.
- Tokens are **per-tenant**, stored only as a SHA-256 hash, compared in constant
  time, and rotatable.
- The channel is scoped to SCIM provisioning; it grants no signing authority.

## Configuration (binary)

- `SCIM_LISTEN_ADDR` — bind address (default `0.0.0.0:8787`).
- `SCIM_TENANT_ID` / `SCIM_ORG_PREFIX` / `SCIM_BEARER_TOKEN` — single-tenant
  bootstrap. Unset ⇒ discovery-only (every `/Users` call is rejected 401).

```bash
SCIM_TENANT_ID=acme SCIM_ORG_PREFIX=EAbc123 SCIM_BEARER_TOKEN=secret \
  auths-scim-server
curl -s localhost:8787/scim/v2/ServiceProviderConfig | jq .
```

## Mounting inside auths-api

`router(state)` returns a router with its state applied, so it composes into a
parent router:

```rust,ignore
let app = Router::new()
    .merge(auths_scim_server::router(scim_state))   // SCIM under /scim/v2
    .merge(control_plane_router(api_state));
```
