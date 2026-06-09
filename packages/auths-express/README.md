# @auths-dev/express

Drop-in [Express](https://expressjs.com/) middleware that authenticates an
`Auths-Presentation` request and attaches a verified `Principal`. It is the Express analogue
of the Axum reference middleware (`auths-api`'s `rp_auth`): the same injectable verifier, the
same single-use challenge store, the same verdict → HTTP-status mapping, and the same
extractor-only access to the principal.

A client (an AI agent, a CI job, a service) authenticates a request by **presenting
proof-of-control of a delegated KERI credential** — not a bearer API key. The crypto check is
the shipped, pure verifier in `@auths-dev/sdk` (`verifyPresentation`).

> **First-party only.** This package is intended for a relying party authenticating
> **its own** credentials (issued under roots it pins). It is not a general-purpose
> third-party OAuth/OIDC server.

## Install

```bash
npm install @auths-dev/express express @auths-dev/sdk
```

`express` and `@auths-dev/sdk` are peer dependencies.

## Quick start

```ts
import express from 'express'
import { verifyPresentation } from '@auths-dev/sdk'
import {
  authsAuth,
  challengeHandler,
  ChallengeStore,
  KeriPresentationVerifier,
  RequestWithPrincipal,
} from '@auths-dev/express'

const AUDIENCE = 'api.example.com'
const PINNED_ROOTS = ['did:keri:Eexample_root_aid'] // `.auths/roots` — DID-only

const challenges = new ChallengeStore({ maxLive: 10_000 })

const verifier = new KeriPresentationVerifier({
  audience: AUDIENCE,
  challenges,
  pinnedRoots: PINNED_ROOTS,
  loadInputs: async (credentialSaid) => {
    /* resolve the issuer/subject/delegator KELs, TEL, and receipts from your registry */
  },
  verifyPresentation,
})

const app = express()

// 1. The challenge mint route — clients GET a nonce, sign over it, then present.
app.get('/v1/auth/challenge', challengeHandler({ audience: AUDIENCE, challenges }))

// 2. A guarded route — only a current-key holder with `acme:deploy` reaches the handler.
app.post('/v1/deploy', authsAuth({ verifier, capabilityFor: () => 'acme:deploy' }), (req, res) => {
  const principal = (req as RequestWithPrincipal).principal
  res.json({ deployedBy: principal.subject, caps: principal.caps })
})
```

## How it works

`authsAuth(...)` returns an Express `RequestHandler` that, in order:

1. **Strips any client-supplied `req.principal`** (anti-forgery) before doing anything — only
   the middleware ever sets the verified principal.
2. Reads the `Authorization: Auths-Presentation <token>` header; missing or wrong-scheme → **401**.
3. Calls `verifier.verify(token, now)`, which **consumes the single-use challenge** from the
   store and runs the crypto check. On failure it sends the denial's status:
   - malformed / missing / expired / revoked / wrong-audience / holder-not-current / replayed → **401**
   - missing capability → **403**
   - challenge store full → **503**
4. Enforces `capabilityFor(req)` against the principal's capabilities; missing → **403**.
5. Attaches the verified `Principal` and calls `next()`.

Unexpected (non-denial) async errors are surfaced via `next(err)` — never swallowed. The
**nonce and signature are never logged**.

### The injectable verifier

The crypto step is injected behind the `PresentationVerifier` interface, exactly like the
Rust `PresentationVerifier` trait:

```ts
interface PresentationVerifier {
  verify(wireToken: string, now: Date): Promise<Principal>
}
```

- **Production** uses `KeriPresentationVerifier`, which wraps the Node binding's
  `verifyPresentation` plus your `loadInputs`.
- **Tests** inject a fake verifier over the **real `ChallengeStore`**, so replay and
  wrong-audience protection are genuinely exercised with no native `.node` binary.

### Typed handlers (`RequestWithPrincipal`)

The principal is **not** a global `Express.Request` augmentation (optional-everywhere proves
nothing). Instead, a guarded handler reads it through `RequestWithPrincipal` (where
`principal` is non-optional) or narrows with the `hasPrincipal(req)` type guard:

```ts
import { hasPrincipal } from '@auths-dev/express'

app.get('/v1/whoami', (req, res) => {
  if (!hasPrincipal(req)) return res.sendStatus(401)
  res.json({ subject: req.principal.subject })
})
```

A handler typed with a plain `Request` cannot read `req.principal` — it is a compile error.

### Pinned roots

`pinnedRoots` is **DID-only**: it pins *who* may issue (`.auths/roots`), never *what* they
may grant. Capabilities always come from the credential and are enforced separately. An empty
`pinnedRoots` set **denies everything** (fail-closed).

## Challenge binding (the default) vs. TTL

**Challenge mode is the default and the recommended path.** The client fetches a fresh,
single-use nonce from `/v1/auth/challenge`, signs over it, and presents it; the store's
remove-on-read `consume` guarantees the nonce verifies **exactly once**.

TTL (non-interactive) binding is behind explicit opt-in. Its residual risk: a TTL nonce can be
**replayed within its TTL window** — there is no single-use store entry to burn. Prefer
challenge mode unless you cannot run the interactive round-trip.

### Single-process caveat

`ChallengeStore` lives in one process's heap. Behind a load balancer fronting N nodes, a nonce
minted on node A is unknown to node B, and the single-use guarantee holds only *per node* — a
within-TTL replay can land on a different node than the original. Single-process or
sticky-session deployments are safe; a multi-node deployment must supply a shared store backend
(Redis/SQL) implementing the same `issue`/`consume` contract.

## Client helper

```ts
import { fetchChallenge } from '@auths-dev/express'

const { nonce, notAfter } = await fetchChallenge('https://api.example.com/v1/auth/challenge')
// sign over `nonce`, build the `Auths-Presentation` header, then call your guarded route
```

## License

Apache-2.0
