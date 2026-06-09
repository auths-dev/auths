/**
 * The typed authentication/authorization failure the verifier and middleware speak.
 *
 * Mirrors the Rust `auths_rp::Denied` HTTP mapping: authentication failures (malformed,
 * missing, expired, revoked, wrong-audience, holder-not-current, replayed) are 401; an
 * authenticated principal lacking a capability is 403; a full challenge store is 503. The
 * carried `message` is a coarse reason only — it never includes the nonce or signature.
 */

/** A denial carrying the exact HTTP status the middleware should send. */
export class PresentationDenied extends Error {
  /** The HTTP status to send (401 / 403 / 503). */
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'PresentationDenied'
    this.status = status
  }

  /** An authentication failure (401): malformed/missing/expired/replayed/wrong-audience/etc. */
  static unauthorized(message: string): PresentationDenied {
    return new PresentationDenied(401, message)
  }

  /** An authenticated-but-insufficient principal (403): the required capability is missing. */
  static forbidden(message: string): PresentationDenied {
    return new PresentationDenied(403, message)
  }

  /** The challenge store is at capacity (503): back-pressure, not a client error. */
  static storeFull(message: string): PresentationDenied {
    return new PresentationDenied(503, message)
  }
}
