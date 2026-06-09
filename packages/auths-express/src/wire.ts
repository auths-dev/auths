/**
 * The `Authorization: Auths-Presentation <token>` wire boundary.
 *
 * Mirrors the Rust `auths_rp` wire shapes. The only exit from "wire world" is
 * {@link parsePresentationHeader} → {@link WirePresentation}: stringly-typed fields never
 * reach verification logic untyped. The header carries `Auths-Presentation` followed by one
 * space and a base64url-encoded JSON document (the {@link WirePresentation}); nonce and
 * signature inside are base64url (URL-safe, no padding).
 */

/** The `Authorization` scheme name carrying a presentation (case-sensitive). */
export const AUTHS_PRESENTATION_SCHEME = 'Auths-Presentation'

/** The fixed nonce width, in bytes. */
export const NONCE_LEN = 32

/** The challenge/TTL binding as it appears on the wire (externally-tagged, snake_case). */
export type WireBinding =
  | { challenge: { nonce: string } }
  | { ttl: { nonce: string; not_after: string } }

/** The raw presentation carried in the header — the untrusted wire shape (snake_case). */
export interface WirePresentation {
  /** The SAID (`acdc.d`) of the credential being presented. */
  credential_said: string
  /** The relying party this presentation is bound to. */
  audience: string
  /** The challenge/TTL binding. */
  binding: WireBinding
  /** base64url-encoded subject signature over the canonical presentation message. */
  signature_b64: string
}

/** A typed wire-parse failure (the caller maps all of these to a coarse 400/401). */
export class WireError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'WireError'
  }
}

/**
 * Parse an `Authorization: Auths-Presentation <token>` header value.
 *
 * The scheme is matched case-sensitively; the single-space-separated token is base64url
 * JSON. Never logs the header (it carries the nonce/signature). Returns a typed
 * {@link WireError} on any malformed input; never throws on attacker-controlled bytes.
 *
 * Args:
 * * `authorization`: The raw `Authorization` header value (or `undefined` when absent).
 *
 * Usage:
 * ```ts
 * const wire = parsePresentationHeader(req.headers.authorization)
 * ```
 */
export function parsePresentationHeader(authorization: string | undefined): WirePresentation {
  if (authorization === undefined) {
    throw new WireError('missing Authorization header')
  }
  if (!authorization.startsWith(`${AUTHS_PRESENTATION_SCHEME} `)) {
    throw new WireError('wrong Authorization scheme (expected Auths-Presentation)')
  }
  const token = authorization.slice(AUTHS_PRESENTATION_SCHEME.length + 1).trim()
  if (token.length === 0) {
    throw new WireError('missing or empty presentation token')
  }
  return parseToken(token)
}

/** Decode the base64url JSON token into a structurally-validated {@link WirePresentation}. */
function parseToken(token: string): WirePresentation {
  let json: string
  try {
    json = Buffer.from(token, 'base64url').toString('utf8')
  } catch {
    throw new WireError('invalid base64url token')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new WireError('malformed presentation JSON')
  }
  return validateWire(parsed)
}

/** Structurally validate the decoded object, rejecting anything not a `WirePresentation`. */
function validateWire(value: unknown): WirePresentation {
  if (typeof value !== 'object' || value === null) {
    throw new WireError('presentation is not an object')
  }
  const obj = value as Record<string, unknown>
  if (typeof obj.credential_said !== 'string') {
    throw new WireError('missing credential_said')
  }
  if (typeof obj.audience !== 'string' || obj.audience.length === 0) {
    throw new WireError('missing or empty audience')
  }
  if (typeof obj.signature_b64 !== 'string') {
    throw new WireError('missing signature_b64')
  }
  const binding = validateBinding(obj.binding)
  return {
    credential_said: obj.credential_said,
    audience: obj.audience,
    binding,
    signature_b64: obj.signature_b64,
  }
}

/** Validate the externally-tagged binding (`challenge` or `ttl`). */
function validateBinding(value: unknown): WireBinding {
  if (typeof value !== 'object' || value === null) {
    throw new WireError('missing binding')
  }
  const obj = value as Record<string, unknown>
  if (isStringRecord(obj.challenge) && typeof obj.challenge.nonce === 'string') {
    return { challenge: { nonce: obj.challenge.nonce } }
  }
  if (
    isStringRecord(obj.ttl) &&
    typeof obj.ttl.nonce === 'string' &&
    typeof obj.ttl.not_after === 'string'
  ) {
    return { ttl: { nonce: obj.ttl.nonce, not_after: obj.ttl.not_after } }
  }
  throw new WireError('binding must be challenge or ttl')
}

/** Narrow an unknown to a plain object (the binding inner shape). */
function isStringRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

/** The nonce of either binding mode (the value the challenge store keys on). */
export function bindingNonce(binding: WireBinding): string {
  return 'challenge' in binding ? binding.challenge.nonce : binding.ttl.nonce
}

/**
 * Build the wire token form from a {@link WirePresentation} (client side / tests).
 *
 * The inverse of {@link parsePresentationHeader}'s token decode: JSON → base64url.
 *
 * Args:
 * * `wire`: The presentation to encode.
 */
export function toToken(wire: WirePresentation): string {
  return Buffer.from(JSON.stringify(wire), 'utf8').toString('base64url')
}

/** Build a full `Authorization` header value from a {@link WirePresentation}. */
export function toHeader(wire: WirePresentation): string {
  return `${AUTHS_PRESENTATION_SCHEME} ${toToken(wire)}`
}
