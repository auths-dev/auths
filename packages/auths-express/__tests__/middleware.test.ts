/**
 * Middleware tests over a FAKE verifier + the REAL {@link ChallengeStore}.
 *
 * The fake substitutes only the crypto step; it still consumes the single-use challenge from
 * the real store, so replay and wrong-audience protection are genuinely exercised without a
 * native `.node` binary. supertest drives a real Express app.
 */

import express from 'express'
import type { Request } from 'express'
import request from 'supertest'
import { describe, expect, it } from 'vitest'

import {
  authsAuth,
  challengeHandler,
  ChallengeStore,
  ChallengeStoreFullError,
  PresentationDenied,
  Principal,
  PresentationVerifier,
  RequestWithPrincipal,
  toToken,
  WireBinding,
  WirePresentation,
} from '../src/index'

const AUDIENCE = 'api.example.com'

/** A capability set the fake verifier grants to the produced principal. */
const GRANTED_CAPS = ['acme:deploy', 'acme:read']

/**
 * A fake verifier that consumes the real challenge then returns a fixed principal.
 *
 * It mirrors the production seam: parse the token → consume the single-use challenge from the
 * REAL store (so replay/audience are exercised) → on a live challenge return a `Principal`,
 * otherwise throw a 401 `PresentationDenied`.
 */
class FakeVerifier implements PresentationVerifier {
  constructor(
    private readonly challenges: ChallengeStore,
    private readonly caps: string[] = GRANTED_CAPS,
  ) {}

  async verify(wireToken: string, now: Date): Promise<Principal> {
    const wire: WirePresentation = JSON.parse(Buffer.from(wireToken, 'base64url').toString('utf8'))
    const nonce = 'challenge' in wire.binding ? wire.binding.challenge.nonce : wire.binding.ttl.nonce
    if (!this.challenges.consume(wire.audience, nonce, now)) {
      throw PresentationDenied.unauthorized('challenge replayed, expired, or unknown')
    }
    return {
      issuer: 'did:keri:Eissuer',
      subject: 'did:keri:Eagent',
      caps: Object.freeze([...this.caps]),
    }
  }
}

/** Build a wire token bound to `audience` carrying `nonce` (challenge binding). */
function tokenFor(audience: string, nonce: string): string {
  const binding: WireBinding = { challenge: { nonce } }
  const wire: WirePresentation = {
    credential_said: 'ECredSAID',
    audience,
    binding,
    signature_b64: Buffer.from(new Uint8Array(64)).toString('base64url'),
  }
  return toToken(wire)
}

/** A minimal app: a guarded `/v1/deploy` plus a `/v1/auth/challenge` mint route. */
function makeApp(
  challenges: ChallengeStore,
  verifier: PresentationVerifier,
  capabilityFor?: (req: Request) => string | undefined,
): express.Express {
  const app = express()
  app.use(express.json())
  app.get('/v1/auth/challenge', challengeHandler({ audience: AUDIENCE, challenges }))
  app.post('/v1/deploy', authsAuth({ verifier, ...(capabilityFor ? { capabilityFor } : {}) }), (req, res) => {
    const principal = (req as RequestWithPrincipal).principal
    res.json({ subject: principal.subject, caps: principal.caps })
  })
  return app
}

/** Issue a live nonce directly into the store (bypassing HTTP) and return it. */
function issueNonce(challenges: ChallengeStore, audience = AUDIENCE): string {
  return challenges.issue(audience, new Date()).nonce
}

describe('authsAuth middleware (fake verifier + real ChallengeStore)', () => {
  it('valid presentation -> 200 and echoes the subject', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges))
    const nonce = issueNonce(challenges)

    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)

    expect(res.status).toBe(200)
    expect(res.body.subject).toBe('did:keri:Eagent')
  })

  it('replay (same token twice) -> second is 401', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges))
    const nonce = issueNonce(challenges)
    const header = `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`

    const first = await request(app).post('/v1/deploy').set('Authorization', header)
    expect(first.status).toBe(200)

    const second = await request(app).post('/v1/deploy').set('Authorization', header)
    expect(second.status).toBe(401)
  })

  it('wrong audience -> 401 (and does not burn the real nonce)', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges))
    const nonce = issueNonce(challenges)

    const wrong = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor('evil.example.com', nonce)}`)
    expect(wrong.status).toBe(401)

    // The real audience can still consume it — a third party did not burn it.
    const ok = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)
    expect(ok.status).toBe(200)
  })

  it('expired challenge -> 401', async () => {
    const challenges = new ChallengeStore({ ttlSecs: 60 })
    const app = makeApp(challenges, new FakeVerifier(challenges))
    // Issue in the past so it is already expired by the time the request lands.
    const past = new Date(Date.now() - 120_000)
    const nonce = challenges.issue(AUDIENCE, past).nonce

    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)
    expect(res.status).toBe(401)
  })

  it('missing capability -> 403', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges, ['acme:read']), () => 'acme:deploy')
    const nonce = issueNonce(challenges)

    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)
    expect(res.status).toBe(403)
  })

  it('held capability -> 200', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges), () => 'acme:deploy')
    const nonce = issueNonce(challenges)

    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)
    expect(res.status).toBe(200)
  })

  it('store full -> 503', async () => {
    const challenges = new ChallengeStore()
    const verifier: PresentationVerifier = {
      verify() {
        throw new ChallengeStoreFullError()
      },
    }
    const app = makeApp(challenges, verifier)
    const nonce = issueNonce(challenges)

    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)
    expect(res.status).toBe(503)
  })

  it('missing Authorization header -> 401', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges))
    const res = await request(app).post('/v1/deploy')
    expect(res.status).toBe(401)
  })

  it('a forged client-supplied req.principal is stripped before verification', async () => {
    const challenges = new ChallengeStore()
    const app = express()
    app.use(express.json())
    // Inject a forged principal upstream of the auth middleware.
    app.use((req, _res, nextFn) => {
      ;(req as { principal?: unknown }).principal = {
        issuer: 'did:keri:Eattacker',
        subject: 'did:keri:Eattacker',
        caps: ['acme:deploy'],
      }
      nextFn()
    })
    // A verifier that rejects every request — so a 200 could only come from the forged principal.
    const rejecting: PresentationVerifier = {
      verify() {
        throw PresentationDenied.unauthorized('always reject')
      },
    }
    app.post('/v1/deploy', authsAuth({ verifier: rejecting }), (req, res) => {
      res.json({ subject: (req as RequestWithPrincipal).principal.subject })
    })

    const challengeStore = challenges
    const nonce = issueNonce(challengeStore)
    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)

    // The forged principal must NOT leak through: verification ran and denied → 401.
    expect(res.status).toBe(401)
  })

  it('unexpected async error is surfaced via next(err) (not swallowed)', async () => {
    const challenges = new ChallengeStore()
    const boom: PresentationVerifier = {
      verify() {
        throw new Error('boom')
      },
    }
    const app = express()
    app.post('/v1/deploy', authsAuth({ verifier: boom }), (_req, res) => res.json({ ok: true }))
    let captured: unknown
    app.use((err: unknown, _req: Request, res: express.Response, _next: express.NextFunction) => {
      captured = err
      res.status(500).json({ error: 'internal' })
    })

    const nonce = issueNonce(challenges)
    const res = await request(app)
      .post('/v1/deploy')
      .set('Authorization', `Auths-Presentation ${tokenFor(AUDIENCE, nonce)}`)

    expect(res.status).toBe(500)
    expect(captured).toBeInstanceOf(Error)
  })
})

describe('challengeHandler mint round-trip', () => {
  it('mints a fresh nonce that the store then consumes exactly once', async () => {
    const challenges = new ChallengeStore()
    const app = makeApp(challenges, new FakeVerifier(challenges))

    const minted = await request(app).get('/v1/auth/challenge')
    expect(minted.status).toBe(200)
    expect(typeof minted.body.nonce).toBe('string')
    expect(typeof minted.body.notAfter).toBe('string')

    // The minted nonce authenticates exactly once.
    const header = `Auths-Presentation ${tokenFor(AUDIENCE, minted.body.nonce)}`
    const first = await request(app).post('/v1/deploy').set('Authorization', header)
    expect(first.status).toBe(200)
    const replay = await request(app).post('/v1/deploy').set('Authorization', header)
    expect(replay.status).toBe(401)
  })

  it('returns 503 when the store is at capacity', async () => {
    const challenges = new ChallengeStore({ maxLive: 1 })
    const app = makeApp(challenges, new FakeVerifier(challenges))
    challenges.issue(AUDIENCE, new Date()) // fill the single slot

    const res = await request(app).get('/v1/auth/challenge')
    expect(res.status).toBe(503)
  })
})
