/**
 * The drop-in Express middleware: authenticate an `Auths-Presentation` request and attach a
 * verified {@link Principal}.
 *
 * Mirrors the Axum reference `rp_auth_middleware`. The middleware owns the orchestration —
 * read header → (verifier) consume challenge + crypto verify + pinned-roots → capability
 * check → attach principal — while the crypto step is injected behind
 * {@link PresentationVerifier}. The principal is reachable only after this middleware sets it;
 * any client-supplied `req.principal` is stripped BEFORE verification (anti-forgery), and the
 * verified one is set only on success. Async failures surface via `next(err)`. The nonce and
 * signature are never logged.
 */

import type { NextFunction, Request, RequestHandler, Response } from 'express'

import { ChallengeStore, ChallengeStoreFullError } from './challengeStore'
import { PresentationDenied } from './denied'
import { authorize, Principal } from './principal'
import { AUTHS_PRESENTATION_SCHEME } from './wire'
import { KeriPresentationVerifier, LoadInputs, PresentationVerifier } from './verifier'
import type { PresentationReport } from '@auths-dev/sdk'

/** A request after successful authentication: `principal` is guaranteed present (non-optional). */
export interface RequestWithPrincipal extends Request {
  /** The verified principal, set only by {@link authsAuth} on a successful presentation. */
  principal: Principal
}

/**
 * Type guard narrowing a request to one that carries a verified principal.
 *
 * A handler MUST guard with this (or be mounted behind {@link authsAuth}) before reading
 * `req.principal`; an unguarded handler cannot access it as a non-optional field.
 *
 * Args:
 * * `req`: The incoming request.
 *
 * Usage:
 * ```ts
 * if (!hasPrincipal(req)) return res.sendStatus(401)
 * res.json({ subject: req.principal.subject })
 * ```
 */
export function hasPrincipal(req: Request): req is RequestWithPrincipal {
  const candidate = (req as { principal?: unknown }).principal
  return typeof candidate === 'object' && candidate !== null && 'subject' in candidate
}

/** Options for {@link authsAuth} with an explicitly-supplied verifier (the testable path). */
export interface AuthsAuthOptionsWithVerifier {
  /** The injected crypto-verify seam (a fake in tests, {@link KeriPresentationVerifier} in prod). */
  verifier: PresentationVerifier
  /** Resolve the capability a given request requires; `undefined` → no capability gate. */
  capabilityFor?: (req: Request) => string | undefined
}

/** Options for {@link authsAuth} that builds the production KERI verifier internally. */
export interface AuthsAuthOptionsProduction {
  /** This relying party's canonical audience — the trust source, never the wire header. */
  audience: string
  /** Trusted root `did:keri:` strings (`.auths/roots`, DID-only). Empty → deny all. */
  pinnedRoots: readonly string[]
  /** The single-use challenge store, shared with the mint route. */
  challenges: ChallengeStore
  /** Resolves a credential SAID to its bundled KEL/TEL inputs. */
  loadInputs: LoadInputs
  /** The Node binding's `verifyPresentation`. */
  verifyPresentation: (requestJson: string) => PresentationReport
  /** Resolve the capability a given request requires; `undefined` → no capability gate. */
  capabilityFor?: (req: Request) => string | undefined
}

/** The accepted shape: either inject a verifier directly, or supply production wiring. */
export type AuthsAuthOptions = AuthsAuthOptionsWithVerifier | AuthsAuthOptionsProduction

/** True when the options carry a ready-made verifier (the testable path). */
function hasVerifier(options: AuthsAuthOptions): options is AuthsAuthOptionsWithVerifier {
  return 'verifier' in options
}

/**
 * Build the Express middleware that authenticates `Auths-Presentation` requests.
 *
 * Behavior, in order:
 * 1. Strip any client-supplied `req.principal` (anti-forgery) before doing anything.
 * 2. Read the `Authorization` header; missing/wrong-scheme → 401.
 * 3. `verifier.verify(token, now)` — consumes the single-use challenge and runs the crypto
 *    check; on {@link PresentationDenied} send its status (401/403/503).
 * 4. Enforce `capabilityFor(req)` against the principal's caps; missing → 403.
 * 5. Attach the verified principal and call `next()`.
 *
 * Any unexpected async error is forwarded via `next(err)`, never swallowed. The nonce and
 * signature are never logged.
 *
 * Args:
 * * `options`: Either `{ verifier, capabilityFor? }` (inject a verifier — the testable path)
 *   or full production wiring `{ audience, pinnedRoots, challenges, loadInputs,
 *   verifyPresentation, capabilityFor? }` (builds a {@link KeriPresentationVerifier}).
 *
 * Usage:
 * ```ts
 * app.post('/v1/deploy', authsAuth({ verifier, capabilityFor: () => 'acme:deploy' }), handler)
 * ```
 */
export function authsAuth(options: AuthsAuthOptions): RequestHandler {
  const verifier = hasVerifier(options)
    ? options.verifier
    : new KeriPresentationVerifier({
        audience: options.audience,
        challenges: options.challenges,
        loadInputs: options.loadInputs,
        pinnedRoots: options.pinnedRoots,
        verifyPresentation: options.verifyPresentation,
      })
  const capabilityFor = options.capabilityFor

  return (req: Request, res: Response, next: NextFunction): void => {
    // Anti-forgery: a client cannot pre-seed a principal; only this middleware sets it.
    delete (req as { principal?: unknown }).principal

    const token = presentationToken(req.headers.authorization)
    if (token === undefined) {
      sendDenied(res, 401, 'authentication required')
      return
    }

    void runVerification(verifier, token, capabilityFor, req, res, next)
  }
}

/** Run the async verify + capability check, surfacing only unexpected errors via `next`. */
async function runVerification(
  verifier: PresentationVerifier,
  token: string,
  capabilityFor: ((req: Request) => string | undefined) | undefined,
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  let principal: Principal
  try {
    principal = await verifier.verify(token, new Date())
  } catch (err) {
    if (err instanceof PresentationDenied) {
      sendDenied(res, err.status, 'presentation rejected')
      return
    }
    if (err instanceof ChallengeStoreFullError) {
      sendDenied(res, 503, 'challenge store full')
      return
    }
    next(err)
    return
  }

  const needed = capabilityFor?.(req)
  if (needed !== undefined && !authorize(principal, needed)) {
    sendDenied(res, 403, 'insufficient capability')
    return
  }

  ;(req as RequestWithPrincipal).principal = principal
  next()
}

/** Extract the base64url token from an `Auths-Presentation` header, or `undefined`. */
function presentationToken(authorization: string | undefined): string | undefined {
  if (authorization === undefined || !authorization.startsWith(`${AUTHS_PRESENTATION_SCHEME} `)) {
    return undefined
  }
  const token = authorization.slice(AUTHS_PRESENTATION_SCHEME.length + 1).trim()
  return token.length === 0 ? undefined : token
}

/** Send a minimal JSON error carrying only a coarse reason (never the nonce/signature). */
function sendDenied(res: Response, status: number, message: string): void {
  res.status(status).json({ error: message })
}
