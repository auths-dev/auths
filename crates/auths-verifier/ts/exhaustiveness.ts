/**
 * Compile-time exhaustiveness guard for the verdict unions.
 *
 * Each `switch` handles every `kind` and ends in a `never` arm. If a Rust variant is added
 * to `contract.rs` and mirrored into `verdict.ts` without a matching `case` here, the
 * assignment `const _exhaustive: never = v` stops compiling — `tsc --noEmit` (run in CI and
 * via the package test) then fails the build. This is the mechanism that keeps the TS union
 * from silently drifting from the Rust wire contract.
 */

import type { CredentialVerdict, PresentationVerdict } from "./verdict";

/** Narrow a presentation verdict to a label, proving every variant is handled. */
export function describePresentation(verdict: PresentationVerdict): string {
  switch (verdict.kind) {
    case "valid":
      return `valid: ${verdict.subject} (${verdict.caps.join(",")})`;
    case "holderNotCurrentKey":
      return "holder is not the current key";
    case "wrongAudience":
      return "bound to a different audience";
    case "nonceMismatchOrConsumed":
      return "challenge mismatched or already consumed";
    case "expired":
      return "presentation TTL expired";
    case "subjectKelInvalid":
      return "subject KEL could not be replayed";
    case "credentialNotValid":
      return `credential not valid: ${describeCredential(verdict.credential)}`;
    case "malformedRequest":
      return `malformed request: ${verdict.message}`;
    case "kelUnauthenticated":
      return `KEL unauthenticated: ${verdict.field} (${verdict.detail})`;
    case "inputTooLarge":
      return `input too large: ${verdict.field} (${verdict.count} > ${verdict.limit})`;
    case "unsupportedSchemaVersion":
      return `unsupported schema version ${verdict.got} (want ${verdict.expected})`;
    default: {
      const _exhaustive: never = verdict;
      return _exhaustive;
    }
  }
}

/** Narrow a credential verdict to a label, proving every variant is handled. */
export function describeCredential(verdict: CredentialVerdict): string {
  switch (verdict.kind) {
    case "valid":
      return `valid as-of ${verdict.asOf}`;
    case "saidMismatch":
      return "SAID mismatch";
    case "schemaInvalid":
      return "schema invalid";
    case "issuerSignatureInvalid":
      return "issuer signature invalid";
    case "registryNotEstablished":
      return "registry not established";
    case "credentialRevoked":
      return `revoked at ${verdict.revokedAt}`;
    case "expired":
      return `expired at ${verdict.expiredAt}`;
    case "witnessQuorumNotMet":
      return `${verdict.event} quorum ${verdict.collected}/${verdict.required}`;
    case "issuerKelDuplicitous":
      return "issuer KEL is duplicitous";
    case "malformedRequest":
      return `malformed request: ${verdict.message}`;
    case "kelUnauthenticated":
      return `KEL unauthenticated: ${verdict.field} (${verdict.detail})`;
    case "inputTooLarge":
      return `input too large: ${verdict.field}`;
    case "unsupportedSchemaVersion":
      return `unsupported schema version ${verdict.got}`;
    default: {
      const _exhaustive: never = verdict;
      return _exhaustive;
    }
  }
}
