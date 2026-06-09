/**
 * Example wiring of `@auths-dev/express`.
 *
 * Mounts the challenge mint route and a guarded `POST /v1/deploy` that reads a typed
 * principal. The production verifier wraps the Node binding's `verifyPresentation` plus an
 * app-supplied `loadInputs` that resolves a credential SAID to its bundled KEL/TEL inputs.
 *
 * NOTE: this is illustrative wiring, not run by the test suite. It imports `@auths-dev/sdk`
 * and `express` (peer deps) and is excluded from the build `tsconfig`.
 */

import express from 'express'
import type { Request, RequestHandler, Response } from 'express'
import { verifyPresentation } from '@auths-dev/sdk'

import {
  authsAuth,
  challengeHandler,
  ChallengeStore,
  KeriPresentationVerifier,
  RequestWithPrincipal,
} from '../src/index'
import type { LoadInputs } from '../src/index'

const AUDIENCE = 'api.example.com'

/** Trusted root issuers — `.auths/roots` is DID-only; capabilities come from the credential. */
const PINNED_ROOTS = ['did:keri:Eexample_root_aid']

/** Resolve a credential SAID to its bundled verification inputs (your registry lookup). */
const loadInputs: LoadInputs = async (_credentialSaid: string) => {
  // In a real app: read the issuer/subject/delegator KELs, TEL, and receipts from your
  // registry for this credential SAID and return them. `credential.signatureB64` and the
  // KEL/TEL events must be standard base64 / CESR-tagged JSON exactly as the contract expects.
  throw new Error('wire up your registry lookup here')
}

const challenges = new ChallengeStore({ maxLive: 10_000 })

const verifier = new KeriPresentationVerifier({
  audience: AUDIENCE,
  challenges,
  loadInputs,
  pinnedRoots: PINNED_ROOTS,
  verifyPresentation,
})

const app = express()

// The challenge mint: clients GET a nonce, sign over it, then present.
app.use('/v1/auth/challenge', challengeHandler({ audience: AUDIENCE, challenges }))

/** A guarded handler: `req` is narrowed to carry a non-optional verified principal. */
const deployHandler = (req: RequestWithPrincipal, res: Response): void => {
  // `req.principal` is guaranteed present here because `authsAuth` ran first.
  res.json({ deployedBy: req.principal.subject, caps: req.principal.caps })
}

app.post(
  '/v1/deploy',
  authsAuth({ verifier, capabilityFor: () => 'acme:deploy' }),
  deployHandler as RequestHandler,
)

/**
 * A handler typed WITHOUT the principal cannot access it — the `@ts-expect-error` below proves
 * the compile error. Only a `RequestWithPrincipal` (set by `authsAuth`) exposes `principal`.
 */
const unguardedHandler: RequestHandler = (req: Request, res: Response) => {
  // @ts-expect-error principal is not on a plain Request; an unauthenticated path cannot read it.
  res.json({ leaked: req.principal })
}

app.get('/v1/whoami', unguardedHandler)

export { app }
