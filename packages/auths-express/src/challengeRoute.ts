/**
 * The `GET /v1/auth/challenge` mint route and a tiny client helper.
 *
 * Mirrors the Axum `challenge_handler`: mint a fresh CSPRNG nonce bound to this relying
 * party's audience and return `{ nonce, notAfter }`. The store is bounded; at capacity the
 * route returns 503 rather than evicting a live nonce. The client signs over the returned
 * nonce and presents it in the `Auths-Presentation` header.
 */

import type { Request, RequestHandler, Response } from 'express'

import { ChallengeStore, ChallengeStoreFullError } from './challengeStore'

/** The `/v1/auth/challenge` response: a fresh single-use nonce and its expiry. */
export interface ChallengeResponse {
  /** base64url-encoded single-use nonce the client signs over. */
  nonce: string
  /** RFC-3339 instant after which the challenge is no longer live. */
  notAfter: string
}

/** Options for {@link challengeHandler}. */
export interface ChallengeHandlerOptions {
  /** This relying party's canonical audience the nonce is bound to. */
  audience: string
  /** The single-use challenge store, shared with the verifier. */
  challenges: ChallengeStore
}

/**
 * Build the `GET /v1/auth/challenge` handler that mints a fresh nonce.
 *
 * The store is bounded; at capacity the handler returns 503 (back-pressure) rather than
 * evicting a live nonce. Never logs the minted nonce.
 *
 * Args:
 * * `options`: The bound audience and the shared {@link ChallengeStore}.
 *
 * Usage:
 * ```ts
 * app.get('/v1/auth/challenge', challengeHandler({ audience, challenges }))
 * ```
 */
export function challengeHandler(options: ChallengeHandlerOptions): RequestHandler {
  return (_req: Request, res: Response): void => {
    try {
      const issued = options.challenges.issue(options.audience, new Date())
      const body: ChallengeResponse = {
        nonce: issued.nonce,
        notAfter: issued.notAfter.toISOString(),
      }
      res.status(200).json(body)
    } catch (err) {
      if (err instanceof ChallengeStoreFullError) {
        res.status(503).json({ error: 'challenge store full' })
        return
      }
      res.status(500).json({ error: 'challenge mint failed' })
    }
  }
}

/**
 * Fetch a fresh challenge from a relying party's mint route (client helper).
 *
 * Uses the global `fetch`. Throws on a non-2xx response (e.g. a 503 when the store is full).
 *
 * Args:
 * * `url`: The absolute URL of the relying party's `/v1/auth/challenge` route.
 *
 * Usage:
 * ```ts
 * const { nonce, notAfter } = await fetchChallenge('https://api.example.com/v1/auth/challenge')
 * ```
 */
export async function fetchChallenge(url: string): Promise<ChallengeResponse> {
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`challenge mint failed: HTTP ${res.status}`)
  }
  const body = (await res.json()) as ChallengeResponse
  return { nonce: body.nonce, notAfter: body.notAfter }
}
