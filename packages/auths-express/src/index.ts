/**
 * `@auths/express` — drop-in Express middleware that authenticates an `Auths-Presentation`
 * request and attaches a verified {@link Principal}.
 *
 * Public surface: {@link authsAuth} (the middleware), {@link challengeHandler} +
 * {@link fetchChallenge} (the mint route + client helper), {@link ChallengeStore} (the
 * single-use store), {@link KeriPresentationVerifier} (production crypto-verify over the Node
 * binding) and the {@link PresentationVerifier} seam (inject a fake in tests), the
 * {@link Principal} types, and the {@link RequestWithPrincipal} guard for typed handlers.
 */

export { authsAuth, hasPrincipal } from './middleware'
export type {
  AuthsAuthOptions,
  AuthsAuthOptionsProduction,
  AuthsAuthOptionsWithVerifier,
  RequestWithPrincipal,
} from './middleware'

export { challengeHandler, fetchChallenge } from './challengeRoute'
export type { ChallengeHandlerOptions, ChallengeResponse } from './challengeRoute'

export {
  ChallengeStore,
  ChallengeStoreFullError,
  DEFAULT_CHALLENGE_TTL_SECS,
  DEFAULT_MAX_LIVE,
  NONCE_LEN,
} from './challengeStore'
export type { ChallengeStoreOptions, IssuedChallenge } from './challengeStore'

export { authorize, principalFromReport } from './principal'
export type { Principal } from './principal'

export { PresentationDenied } from './denied'

export { KeriPresentationVerifier, b64urlToStd } from './verifier'
export type {
  KeriVerifierOptions,
  LoadInputs,
  PresentationInputs,
  PresentationVerifier,
  WitnessPolicy,
} from './verifier'

export {
  AUTHS_PRESENTATION_SCHEME,
  bindingNonce,
  parsePresentationHeader,
  toHeader,
  toToken,
  WireError,
} from './wire'
export type { WireBinding, WirePresentation } from './wire'
