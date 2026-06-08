/**
 * The injectable crypto-verify seam.
 *
 * Mirrors the Rust `PresentationVerifier` trait in `auths-api`'s `rp_auth`: the middleware
 * owns header parse → challenge consume → verify → pinned-roots/capability checks, while the
 * *crypto* step is injected behind {@link PresentationVerifier}. Tests substitute a fake over
 * the REAL {@link ChallengeStore}, so replay/audience are genuinely exercised with no native
 * `.node` binary; production wires {@link KeriPresentationVerifier} over the Node binding.
 *
 * Pinned roots: `.auths/roots` is DID-only — it pins *who* may issue, never *what* they may
 * grant. Capabilities always come from the credential and are enforced separately by the
 * middleware via {@link authorize}.
 */

import type { PresentationReport } from '@auths-dev/sdk'

import { ChallengeStore } from './challengeStore'
import { PresentationDenied } from './denied'
import { Principal, principalFromReport } from './principal'
import { bindingNonce, parsePresentationHeader, WireError, WirePresentation } from './wire'

/**
 * The injectable verification step: turn a raw wire token into a verified {@link Principal}.
 *
 * The verifier owns consuming the single-use challenge internally (so replay protection is
 * covered by both production and fakes) and throws a typed {@link PresentationDenied} with an
 * HTTP status on any failure — it never returns a bare boolean.
 */
export interface PresentationVerifier {
  /**
   * Verify `wireToken` (the value after the `Auths-Presentation` scheme) as of `now`.
   *
   * Args:
   * * `wireToken`: The base64url JSON token from the `Authorization` header.
   * * `now`: Verification time, injected at the HTTP boundary.
   */
  verify(wireToken: string, now: Date): Promise<Principal>
}

/** The bundled, resolved KERI inputs `verifyPresentation` needs, supplied by the app. */
export interface PresentationInputs {
  /** The credential body + the issuer's detached signature, base64 (standard). */
  credential: { acdc: unknown; signatureB64: string }
  /** The issuer identity's KEL (oldest first). */
  issuerKel: unknown[]
  /** The subject (holder) AID's KEL. */
  subjectKel: unknown[]
  /** The subject's delegator KEL, or empty for a non-delegated subject. */
  delegatorKel?: unknown[]
  /** The credential's TEL (`vcp`/`iss`/optional `rev`). */
  tel: unknown[]
  /** Witness receipts for the issuer's lifecycle anchors. */
  receipts?: unknown[]
}

/** Resolves a credential SAID to its bundled verification inputs (app-supplied). */
export type LoadInputs = (credentialSaid: string) => Promise<PresentationInputs> | PresentationInputs

/** The witness policy the verifier runs under (first-party default is `warn`). */
export type WitnessPolicy = 'warn' | 'requireWitnesses'

/** Construction options for {@link KeriPresentationVerifier}. */
export interface KeriVerifierOptions {
  /** This relying party's canonical audience — the trust source, never the wire header. */
  audience: string
  /** The single-use challenge store, shared with the mint route. */
  challenges: ChallengeStore
  /** Resolves a credential SAID to its bundled KEL/TEL inputs. */
  loadInputs: LoadInputs
  /** Trusted root `did:keri:` strings (from `.auths/roots`). DID-only; pins who may issue. */
  pinnedRoots: readonly string[]
  /** The Node binding's `verifyPresentation` (injected so tests need no native binary). */
  verifyPresentation: (requestJson: string) => PresentationReport
  /** Witness policy; first-party default is `warn`. */
  witnessPolicy?: WitnessPolicy
}

/** The schema version carried on every contract request (matches the Rust `SCHEMA_VERSION`). */
const SCHEMA_VERSION = 1

/**
 * Production verifier: KERI presentation authentication over the Node binding.
 *
 * Flow: parse the wire token → consume the single-use challenge (the only place single-use is
 * enforced) → `loadInputs(credentialSaid)` → assemble the camelCase `VerifyPresentationRequest`
 * (re-encoding the base64url wire nonce/signature to standard base64 the contract expects) →
 * `verifyPresentation(requestJson)` → enforce pinned roots → map the report to a
 * {@link Principal} or throw a typed {@link PresentationDenied}.
 */
export class KeriPresentationVerifier implements PresentationVerifier {
  private readonly audience: string
  private readonly challenges: ChallengeStore
  private readonly loadInputs: LoadInputs
  private readonly pinnedRoots: ReadonlySet<string>
  private readonly verifyPresentationFn: (requestJson: string) => PresentationReport
  private readonly witnessPolicy: WitnessPolicy

  /**
   * Build a verifier bound to one relying-party audience.
   *
   * Args:
   * * `options`: See {@link KeriVerifierOptions}.
   *
   * Usage:
   * ```ts
   * const verifier = new KeriPresentationVerifier({
   *   audience: 'api.example.com',
   *   challenges,
   *   loadInputs,
   *   pinnedRoots: ['did:keri:Eroot'],
   *   verifyPresentation,
   * })
   * ```
   */
  constructor(options: KeriVerifierOptions) {
    this.audience = options.audience
    this.challenges = options.challenges
    this.loadInputs = options.loadInputs
    this.pinnedRoots = new Set(options.pinnedRoots)
    this.verifyPresentationFn = options.verifyPresentation
    this.witnessPolicy = options.witnessPolicy ?? 'warn'
  }

  async verify(wireToken: string, now: Date): Promise<Principal> {
    let wire: WirePresentation
    try {
      wire = parsePresentationHeader(`Auths-Presentation ${wireToken}`)
    } catch (err) {
      if (err instanceof WireError) {
        throw PresentationDenied.unauthorized('malformed presentation')
      }
      throw err
    }

    const nonceB64url = bindingNonce(wire.binding)
    if (!this.challenges.consume(wire.audience, nonceB64url, now)) {
      throw PresentationDenied.unauthorized('challenge replayed, expired, or unknown')
    }

    const inputs = await this.loadInputs(wire.credential_said)
    const requestJson = this.buildRequest(wire, nonceB64url, inputs, now)
    const report = this.verifyPresentationFn(requestJson)

    const principal = principalFromReport(report)
    this.enforcePinnedRoots(principal)
    return principal
  }

  /**
   * Assemble the camelCase `VerifyPresentationRequest` JSON the contract expects.
   *
   * The wire nonce/signature are base64url (URL-safe, no padding), but the contract's
   * `nonceB64` / `signatureB64` / `expectedChallengeB64` fields are STANDARD base64 — so each
   * is decoded base64url → raw bytes → re-encoded standard base64 here.
   */
  private buildRequest(
    wire: WirePresentation,
    nonceB64url: string,
    inputs: PresentationInputs,
    now: Date,
  ): string {
    const expectedChallengeStd = b64urlToStd(nonceB64url)
    const request = {
      schemaVersion: SCHEMA_VERSION,
      envelope: {
        credentialSaid: wire.credential_said,
        audience: wire.audience,
        binding: wireBindingToContract(wire),
        signatureB64: b64urlToStd(wire.signature_b64),
      },
      credential: inputs.credential,
      issuerKel: inputs.issuerKel,
      subjectKel: inputs.subjectKel,
      delegatorKel: inputs.delegatorKel ?? [],
      tel: inputs.tel,
      receipts: inputs.receipts ?? [],
      witnessPolicy: this.witnessPolicy,
      audience: this.audience,
      expectedChallengeB64: expectedChallengeStd,
      now: now.toISOString(),
    }
    return JSON.stringify(request)
  }

  /**
   * Deny unless the report's issuer is a pinned root.
   *
   * `.auths/roots` pins *who* may issue (DID-only). The credential carries *what* it grants;
   * capabilities are enforced by the middleware, not here. An empty `pinnedRoots` set denies
   * everything (fail-closed), so an unconfigured relying party never trusts an arbitrary issuer.
   */
  private enforcePinnedRoots(principal: Principal): void {
    if (!this.pinnedRoots.has(principal.issuer)) {
      throw PresentationDenied.unauthorized('issuer is not a pinned root')
    }
  }
}

/** Translate the parsed wire binding into the contract's `{ mode, nonceB64, notAfter? }` shape. */
function wireBindingToContract(
  wire: WirePresentation,
): { mode: 'challenge'; nonceB64: string } | { mode: 'ttl'; nonceB64: string; notAfter: string } {
  if ('challenge' in wire.binding) {
    return { mode: 'challenge', nonceB64: b64urlToStd(wire.binding.challenge.nonce) }
  }
  return {
    mode: 'ttl',
    nonceB64: b64urlToStd(wire.binding.ttl.nonce),
    notAfter: wire.binding.ttl.not_after,
  }
}

/**
 * Re-encode a base64url (URL-safe, no padding) string as STANDARD base64.
 *
 * The wire carries base64url; the cross-language contract request expects standard base64
 * (with `+`/`/` and `=` padding). Decode to raw bytes, then re-encode.
 *
 * Args:
 * * `b64url`: The base64url-encoded value from the wire.
 */
export function b64urlToStd(b64url: string): string {
  return Buffer.from(b64url, 'base64url').toString('base64')
}
