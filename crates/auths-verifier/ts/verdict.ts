/**
 * Branded TypeScript union for the cross-boundary verify contract.
 *
 * Mirrors the Rust wire verdict produced by `auths_verifier::contract`
 * (`verifyPresentationJson` / `verifyCredentialJson` in the WASM build). The WASM
 * exports return the verdict as a JSON **string**; parse it and assert it as the
 * matching envelope:
 *
 * ```ts
 * import { verifyPresentationJson } from "auths-verifier";
 * import type { PresentationVerdictEnvelope } from "auths-verifier/ts/verdict";
 * const verdict = JSON.parse(verifyPresentationJson(bundle)) as PresentationVerdictEnvelope;
 * if (verdict.kind === "valid") {
 *   // verdict.subject and verdict.caps are now available, fully typed
 * }
 * ```
 *
 * The `kind` discriminants are byte-for-byte the Rust wire tags. Keep this file in
 * lock-step with `crates/auths-verifier/src/contract.rs`; the exhaustiveness `switch`
 * in `exhaustiveness.ts` fails the TS build if a Rust variant is added without a TS arm.
 */

/** A `did:keri:` / `did:key:` identifier — a string, branded so a bare string cannot be passed where a DID is required. */
export type CanonicalDid = string & { readonly __brand: "CanonicalDid" };

/** A capability token (e.g. `"sign"`) — a branded string for the same reason. */
export type Capability = string & { readonly __brand: "Capability" };

/** Request-layer failures shared by both verdict unions (never a verification outcome). */
export type RequestError =
  | { kind: "malformedRequest"; message: string }
  | { kind: "kelUnauthenticated"; field: string; detail: string }
  | { kind: "inputTooLarge"; field: string; count: number; limit: number }
  | { kind: "unsupportedSchemaVersion"; got: number; expected: number };

/** The outcome of `verifyCredentialJson` — `verify_credential` in Rust. */
export type CredentialVerdict =
  | {
      kind: "valid";
      issuer: CanonicalDid;
      subject: CanonicalDid;
      caps: readonly Capability[];
      asOf: number;
    }
  | { kind: "saidMismatch" }
  | { kind: "schemaInvalid" }
  | { kind: "issuerSignatureInvalid" }
  | { kind: "registryNotEstablished" }
  | { kind: "credentialRevoked"; revokedAt: number }
  | { kind: "expired"; expiredAt: string; now: string }
  | { kind: "witnessQuorumNotMet"; event: string; collected: number; required: number }
  | { kind: "issuerKelDuplicitous" }
  | RequestError;

/** The outcome of `verifyPresentationJson` — `verify_presentation` in Rust. */
export type PresentationVerdict =
  | {
      kind: "valid";
      issuer: CanonicalDid;
      subject: CanonicalDid;
      caps: readonly Capability[];
      role: string | null;
      expiresAt: string | null;
    }
  | { kind: "holderNotCurrentKey" }
  | { kind: "wrongAudience" }
  | { kind: "nonceMismatchOrConsumed" }
  | { kind: "expired" }
  | { kind: "subjectKelInvalid" }
  | { kind: "credentialNotValid"; credential: CredentialVerdict }
  | RequestError;

/** Every verdict carries the schema version it was produced under (the one schema to version). */
export type VerdictEnvelope<V> = { schemaVersion: number } & V;

/** The parsed return type of `verifyPresentationJson`. */
export type PresentationVerdictEnvelope = VerdictEnvelope<PresentationVerdict>;

/** The parsed return type of `verifyCredentialJson`. */
export type CredentialVerdictEnvelope = VerdictEnvelope<CredentialVerdict>;
