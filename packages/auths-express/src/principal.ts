/**
 * Verified principal — the authenticated identity a guarded handler reads.
 *
 * Mirrors the Rust `auths_rp::VerifiedPrincipal`: a `Principal` is built ONLY from a `Valid`
 * presentation report (via {@link principalFromReport}), so *possessing one is proof* the
 * holder demonstrated current control of the subject AID's key. Capabilities come from the
 * credential, never from the request. {@link authorize} answers a single capability check.
 */

import type { PresentationReport } from '@auths-dev/sdk'

import { PresentationDenied } from './denied'

/**
 * A verified principal, obtainable only from a successful presentation report.
 *
 * Constructed solely by {@link principalFromReport}; an unauthenticated path has no way to
 * fabricate one. `caps` is read-only so a handler cannot mutate the granted authority.
 */
export interface Principal {
  /** Issuer AID (`did:keri:`) that signed the credential. */
  readonly issuer: string
  /** Subject (holder) AID whose current key signed the presentation. */
  readonly subject: string
  /** Capabilities the credential granted (never silently dropped). */
  readonly caps: readonly string[]
  /** Optional informational role claim. */
  readonly role?: string
  /** Optional credential expiry (RFC-3339). */
  readonly expiresAt?: string
}

/**
 * Build a {@link Principal} from a `Valid` presentation report, or throw a typed
 * {@link PresentationDenied}.
 *
 * Every non-`Valid` status is mapped explicitly to a denial with the correct HTTP class
 * (401 for authentication failures, never a bare boolean). A new upstream status falls
 * through to `Unknown` → 401, which fails closed.
 *
 * Args:
 * * `report`: The outcome of `@auths-dev/sdk`'s `verifyPresentation`.
 *
 * Usage:
 * ```ts
 * const principal = principalFromReport(report) // throws PresentationDenied on denial
 * ```
 */
export function principalFromReport(report: PresentationReport): Principal {
  // Switch on the wire status string (the `PresentationStatus` const-enum values ARE these
  // strings). A type-only import of the binding keeps the native module off the import graph,
  // so the injectable-verifier tests run with no native binary built.
  switch (report.status as string) {
    case 'Valid':
      return {
        issuer: report.issuer ?? '',
        subject: report.subject ?? '',
        caps: Object.freeze([...(report.caps ?? [])]),
        ...(report.role !== undefined ? { role: report.role } : {}),
        ...(report.expiresAt !== undefined ? { expiresAt: report.expiresAt } : {}),
      }
    case 'HolderNotCurrentKey':
      throw PresentationDenied.unauthorized('presenter does not control the subject current key')
    case 'WrongAudience':
      throw PresentationDenied.unauthorized('presentation bound to a different audience')
    case 'NonceMismatchOrConsumed':
      throw PresentationDenied.unauthorized('challenge replayed or already consumed')
    case 'Expired':
      throw PresentationDenied.unauthorized('presentation expired')
    case 'SubjectKelInvalid':
      throw PresentationDenied.unauthorized('subject KEL invalid or unresolvable')
    case 'CredentialNotValid':
      throw PresentationDenied.unauthorized('credential not valid')
    case 'MalformedRequest':
      throw PresentationDenied.unauthorized('malformed presentation')
    case 'InputTooLarge':
      throw PresentationDenied.unauthorized('presentation input too large')
    case 'UnsupportedSchemaVersion':
      throw PresentationDenied.unauthorized('unsupported presentation schema version')
    case 'Unknown':
    default:
      throw PresentationDenied.unauthorized('presentation rejected')
  }
}

/**
 * Authorize a required capability against a principal's granted set.
 *
 * Returns `true` iff the principal holds `needed`. The middleware turns a `false` into HTTP
 * 403 (authenticated but insufficient), distinct from the 401 authentication failures.
 *
 * Args:
 * * `principal`: The verified principal.
 * * `needed`: The capability the route/tool requires.
 */
export function authorize(principal: Principal, needed: string): boolean {
  return principal.caps.includes(needed)
}
