import native from './native'
import { mapNativeError, AuthsError } from './errors'

/**
 * Authorization outcome from a policy evaluation.
 *
 * Values match the Rust `Outcome` enum in `auths-policy/src/decision.rs`.
 */
export const Outcome = {
  Allow: 'Allow',
  Deny: 'Deny',
  Indeterminate: 'Indeterminate',
  RequiresApproval: 'RequiresApproval',
  MissingCredential: 'MissingCredential',
} as const
export type Outcome = (typeof Outcome)[keyof typeof Outcome]

/**
 * Machine-readable reason code for stable logging and alerting.
 *
 * Values match the Rust `ReasonCode` enum in `auths-policy/src/decision.rs`.
 */
export const ReasonCode = {
  Unconditional: 'Unconditional',
  AllChecksPassed: 'AllChecksPassed',
  CapabilityPresent: 'CapabilityPresent',
  CapabilityMissing: 'CapabilityMissing',
  IssuerMatch: 'IssuerMatch',
  IssuerMismatch: 'IssuerMismatch',
  Revoked: 'Revoked',
  Expired: 'Expired',
  InsufficientTtl: 'InsufficientTtl',
  IssuedTooLongAgo: 'IssuedTooLongAgo',
  RoleMismatch: 'RoleMismatch',
  ScopeMismatch: 'ScopeMismatch',
  ChainTooDeep: 'ChainTooDeep',
  DelegationMismatch: 'DelegationMismatch',
  AttrMismatch: 'AttrMismatch',
  MissingField: 'MissingField',
  RecursionExceeded: 'RecursionExceeded',
  ShortCircuit: 'ShortCircuit',
  CombinatorResult: 'CombinatorResult',
  WorkloadMismatch: 'WorkloadMismatch',
  WitnessQuorumNotMet: 'WitnessQuorumNotMet',
  SignerTypeMatch: 'SignerTypeMatch',
  SignerTypeMismatch: 'SignerTypeMismatch',
  ApprovalRequired: 'ApprovalRequired',
  ApprovalGranted: 'ApprovalGranted',
  ApprovalExpired: 'ApprovalExpired',
  ApprovalAlreadyUsed: 'ApprovalAlreadyUsed',
  ApprovalRequestMismatch: 'ApprovalRequestMismatch',
} as const
export type ReasonCode = (typeof ReasonCode)[keyof typeof ReasonCode]

/** Result of evaluating a policy against a context. */
export interface PolicyDecision {
  /** Raw outcome string (`'allow'` or `'deny'`). */
  outcome: string
  /** Machine-readable reason code. */
  reason: string
  /** Human-readable explanation of the decision. */
  message: string
  /** Convenience: `true` when `outcome === 'allow'`. */
  allowed: boolean
  /** Convenience: `true` when `outcome === 'deny'`. */
  denied: boolean
}

/** A commit verification result (from Git commit verification). */
export interface CommitResultLike {
  /** Git commit SHA. */
  commitSha: string
  /** Whether the commit signature is valid. */
  isValid: boolean
  /** Hex-encoded public key of the signer, if identified. */
  signer?: string | null
}

/**
 * Build an EvalContext options object from a commit verification result.
 *
 * Extracts the signer hex from the commit result and converts it to a
 * `did:key:` DID for use as the `subject` field.
 *
 * @param commitResult - A commit verification result with a `signer` hex field.
 * @param issuer - The issuer DID (`did:keri:...`).
 * @param capabilities - Optional capability list to include.
 * @returns An EvalContextOpts suitable for `evaluatePolicy()`.
 *
 * @example
 * ```typescript
 * const ctx = evalContextFromCommitResult(cr, org.orgDid, ['sign_commit'])
 * const decision = evaluatePolicy(compiled, ctx)
 * ```
 */
export function evalContextFromCommitResult(
  commitResult: CommitResultLike,
  issuer: string,
  capabilities?: string[],
): EvalContextOpts {
  const subject = commitResult.signer
    ? `did:key:z${commitResult.signer}`
    : 'unknown'
  const ctx: EvalContextOpts = { issuer, subject }
  if (capabilities) ctx.capabilities = capabilities
  return ctx
}

/**
 * Context for policy evaluation.
 *
 * **DID format requirements:**
 * - `issuer`: Must be a valid DID. Typically `did:keri:E...` for identity DIDs
 *   (organizations, individuals) or `did:key:z...` for device DIDs.
 * - `subject`: Same format rules as `issuer`. For device attestations, this is
 *   usually a `did:key:z...` device DID.
 *
 * Both `issuer` and `subject` are parsed into `CanonicalDid` values by the
 * Rust policy engine. The engine accepts both `did:keri:` and `did:key:` formats.
 * Invalid DID strings will cause evaluation to fail with a parse error.
 *
 * @example
 * ```typescript
 * const ctx: EvalContextOpts = {
 *   issuer: 'did:keri:EOrg123',      // organization identity
 *   subject: 'did:key:z6MkDevice',   // device key
 *   capabilities: ['sign_commit'],
 * }
 * ```
 */
export interface EvalContextOpts {
  /**
   * DID of the attestation issuer.
   *
   * Must be a valid `did:keri:` or `did:key:` DID string.
   * Typically the organization or identity that issued the attestation.
   */
  issuer: string
  /**
   * DID of the attestation subject.
   *
   * Must be a valid `did:keri:` or `did:key:` DID string.
   * For device attestations, this is the device's `did:key:z...` DID.
   */
  subject: string
  /** Capabilities held by the subject. */
  capabilities?: string[]
  /** Role of the subject (e.g. `'admin'`, `'member'`). */
  role?: string
  /** Whether the attestation has been revoked. */
  revoked?: boolean
  /** Expiration timestamp (RFC 3339). */
  expiresAt?: string
  /** Repository scope (e.g. `'org/repo'`). */
  repo?: string
  /** Deployment environment (e.g. `'production'`). */
  environment?: string
  /** Signer type constraint. */
  signerType?: 'human' | 'agent' | 'workload'
  /** DID of the delegating identity. */
  delegatedBy?: string
  /** Depth of the attestation chain. */
  chainDepth?: number
}

type Predicate = Record<string, unknown>

/**
 * Fluent builder for composing authorization policies.
 *
 * Policies are built by chaining predicates, then compiled and evaluated
 * against an attestation context to produce an allow/deny decision.
 *
 * @example
 * ```typescript
 * import { PolicyBuilder } from '@auths-dev/sdk'
 *
 * // Quick standard policy
 * const policy = PolicyBuilder.standard('sign_commit')
 * const decision = policy.evaluate({
 *   issuer: 'did:keri:EOrg',
 *   subject: 'did:key:zDevice',
 *   capabilities: ['sign_commit'],
 * })
 * console.log(decision.allowed) // true
 *
 * // Complex composed policy
 * const ciPolicy = new PolicyBuilder()
 *   .notRevoked()
 *   .notExpired()
 *   .requireCapability('sign')
 *   .requireAgent()
 *   .requireRepo('org/repo')
 *   .build()
 * ```
 */
export class PolicyBuilder {
  private predicates: Predicate[] = []

  /** All available predicate method names. */
  static readonly AVAILABLE_PREDICATES: string[] = [
    'notRevoked',
    'notExpired',
    'expiresAfter',
    'issuedWithin',
    'requireCapability',
    'requireAllCapabilities',
    'requireAnyCapability',
    'requireIssuer',
    'requireIssuerIn',
    'requireSubject',
    'requireDelegatedBy',
    'requireAgent',
    'requireHuman',
    'requireWorkload',
    'requireRepo',
    'requireRepoIn',
    'requireEnv',
    'requireEnvIn',
    'refMatches',
    'pathAllowed',
    'maxChainDepth',
    'attrEquals',
    'attrIn',
    'workloadIssuerIs',
    'workloadClaimEquals',
  ]

  /** Built-in preset policy names. */
  static readonly AVAILABLE_PRESETS: string[] = ['standard']

  /** Returns the list of available predicate method names. */
  static availablePredicates(): string[] {
    return [...PolicyBuilder.AVAILABLE_PREDICATES]
  }

  /** Returns the list of available preset policy names. */
  static availablePresets(): string[] {
    return [...PolicyBuilder.AVAILABLE_PRESETS]
  }

  /**
   * Creates a standard policy requiring not-revoked, not-expired, and a capability.
   *
   * @param capability - Required capability string.
   * @returns A new builder with the standard predicates.
   *
   * @example
   * ```typescript
   * const policy = PolicyBuilder.standard('sign_commit')
   * ```
   */
  static standard(capability: string): PolicyBuilder {
    return new PolicyBuilder()
      .notRevoked()
      .notExpired()
      .requireCapability(capability)
  }

  /**
   * Reconstructs a PolicyBuilder from a JSON policy expression.
   *
   * @param jsonStr - JSON string from `toJson()` or config files.
   * @returns A new builder with the parsed predicates.
   */
  static fromJson(jsonStr: string): PolicyBuilder {
    const expr = JSON.parse(jsonStr) as Record<string, unknown>
    const result = new PolicyBuilder()
    if (expr.op === 'And' && Array.isArray(expr.args)) {
      result.predicates = expr.args as Predicate[]
    } else {
      result.predicates = [expr as Predicate]
    }
    return result
  }

  /**
   * Creates a policy that passes if any of the given policies pass.
   *
   * @param builders - Policies to OR together.
   * @returns A new builder combining the policies.
   */
  static anyOf(...builders: PolicyBuilder[]): PolicyBuilder {
    const result = new PolicyBuilder()
    const orArgs = builders.map(b => ({ op: 'And', args: b.predicates }))
    result.predicates = [{ op: 'Or', args: orArgs }]
    return result
  }

  /** Requires the attestation to not be revoked. */
  notRevoked(): PolicyBuilder {
    this.predicates.push({ op: 'NotRevoked' })
    return this
  }

  /** Requires the attestation to not be expired. */
  notExpired(): PolicyBuilder {
    this.predicates.push({ op: 'NotExpired' })
    return this
  }

  /**
   * Requires the attestation to expire after the given number of seconds from now.
   *
   * @param seconds - Minimum remaining lifetime in seconds.
   */
  expiresAfter(seconds: number): PolicyBuilder {
    this.predicates.push({ op: 'ExpiresAfter', args: seconds })
    return this
  }

  /**
   * Requires the attestation to have been issued within the given time window.
   *
   * @param seconds - Maximum age in seconds.
   */
  issuedWithin(seconds: number): PolicyBuilder {
    this.predicates.push({ op: 'IssuedWithin', args: seconds })
    return this
  }

  /**
   * Requires the subject to hold a specific capability.
   *
   * @param cap - Capability string (e.g. `'sign'`, `'sign_commit'`).
   */
  requireCapability(cap: string): PolicyBuilder {
    this.predicates.push({ op: 'HasCapability', args: cap })
    return this
  }

  /**
   * Requires the subject to hold all of the given capabilities.
   *
   * @param caps - Array of required capability strings.
   */
  requireAllCapabilities(caps: string[]): PolicyBuilder {
    for (const cap of caps) {
      this.requireCapability(cap)
    }
    return this
  }

  /**
   * Requires the subject to hold at least one of the given capabilities.
   *
   * @param caps - Array of acceptable capability strings.
   */
  requireAnyCapability(caps: string[]): PolicyBuilder {
    const orArgs = caps.map(c => ({ op: 'HasCapability', args: c }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  /**
   * Requires the issuer to match a specific DID.
   *
   * @param did - Required issuer DID.
   */
  requireIssuer(did: string): PolicyBuilder {
    this.predicates.push({ op: 'IssuerIs', args: did })
    return this
  }

  /**
   * Requires the issuer to be one of the given DIDs.
   *
   * @param dids - Acceptable issuer DIDs.
   */
  requireIssuerIn(dids: string[]): PolicyBuilder {
    const orArgs = dids.map(d => ({ op: 'IssuerIs', args: d }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  /**
   * Requires the subject to match a specific DID.
   *
   * @param did - Required subject DID.
   */
  requireSubject(did: string): PolicyBuilder {
    this.predicates.push({ op: 'SubjectIs', args: did })
    return this
  }

  /**
   * Requires the attestation to have been delegated by a specific identity.
   *
   * @param did - DID of the required delegator.
   */
  requireDelegatedBy(did: string): PolicyBuilder {
    this.predicates.push({ op: 'DelegatedBy', args: did })
    return this
  }

  /** Requires the signer to be an agent. */
  requireAgent(): PolicyBuilder {
    this.predicates.push({ op: 'IsAgent' })
    return this
  }

  /** Requires the signer to be a human. */
  requireHuman(): PolicyBuilder {
    this.predicates.push({ op: 'IsHuman' })
    return this
  }

  /** Requires the signer to be a workload identity. */
  requireWorkload(): PolicyBuilder {
    this.predicates.push({ op: 'IsWorkload' })
    return this
  }

  /**
   * Requires the operation to target a specific repository.
   *
   * @param repo - Repository identifier (e.g. `'org/repo'`).
   */
  requireRepo(repo: string): PolicyBuilder {
    this.predicates.push({ op: 'RepoIs', args: repo })
    return this
  }

  /**
   * Requires the operation to target one of the given repositories.
   *
   * @param repos - Acceptable repository identifiers.
   */
  requireRepoIn(repos: string[]): PolicyBuilder {
    const orArgs = repos.map(r => ({ op: 'RepoIs', args: r }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  /**
   * Requires a specific deployment environment.
   *
   * @param env - Environment name (e.g. `'production'`).
   */
  requireEnv(env: string): PolicyBuilder {
    this.predicates.push({ op: 'EnvIs', args: env })
    return this
  }

  /**
   * Requires one of the given deployment environments.
   *
   * @param envs - Acceptable environment names.
   */
  requireEnvIn(envs: string[]): PolicyBuilder {
    const orArgs = envs.map(e => ({ op: 'EnvIs', args: e }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  /**
   * Requires the Git ref to match a pattern.
   *
   * @param pattern - Ref pattern (e.g. `'refs/heads/main'`).
   */
  refMatches(pattern: string): PolicyBuilder {
    this.predicates.push({ op: 'RefMatches', args: pattern })
    return this
  }

  /**
   * Restricts allowed file paths.
   *
   * @param patterns - Glob patterns for allowed paths.
   */
  pathAllowed(patterns: string[]): PolicyBuilder {
    this.predicates.push({ op: 'PathAllowed', args: patterns })
    return this
  }

  /**
   * Limits the maximum attestation chain depth.
   *
   * @param depth - Maximum allowed chain depth.
   */
  maxChainDepth(depth: number): PolicyBuilder {
    this.predicates.push({ op: 'MaxChainDepth', args: depth })
    return this
  }

  /**
   * Requires an attestation attribute to equal a specific value.
   *
   * @param key - Attribute key.
   * @param value - Required attribute value.
   */
  attrEquals(key: string, value: string): PolicyBuilder {
    this.predicates.push({ op: 'AttrEquals', args: { key, value } })
    return this
  }

  /**
   * Requires an attestation attribute to be one of the given values.
   *
   * @param key - Attribute key.
   * @param values - Acceptable attribute values.
   */
  attrIn(key: string, values: string[]): PolicyBuilder {
    this.predicates.push({ op: 'AttrIn', args: { key, values } })
    return this
  }

  /**
   * Requires the workload attestation issuer to match a specific DID.
   *
   * @param did - Required workload issuer DID.
   */
  workloadIssuerIs(did: string): PolicyBuilder {
    this.predicates.push({ op: 'WorkloadIssuerIs', args: did })
    return this
  }

  /**
   * Requires a workload attestation claim to equal a specific value.
   *
   * @param key - Claim key.
   * @param value - Required claim value.
   */
  workloadClaimEquals(key: string, value: string): PolicyBuilder {
    this.predicates.push({ op: 'WorkloadClaimEquals', args: { key, value } })
    return this
  }

  /**
   * Combines this policy with another using OR logic.
   *
   * @param other - The other policy builder.
   * @returns A new builder that passes if either policy passes.
   */
  orPolicy(other: PolicyBuilder): PolicyBuilder {
    return PolicyBuilder.anyOf(this, other)
  }

  /**
   * Negates this policy — passes when the original would deny, and vice versa.
   *
   * @returns A new negated builder.
   */
  negate(): PolicyBuilder {
    const result = new PolicyBuilder()
    result.predicates = [{ op: 'Not', args: { op: 'And', args: this.predicates } }]
    return result
  }

  /**
   * Serializes the policy to JSON without compiling.
   *
   * @returns JSON string representation of the policy expression.
   * @throws Error if the policy has no predicates.
   */
  toJson(): string {
    if (this.predicates.length === 0) {
      throw new Error('Cannot export an empty policy.')
    }
    const expr = { op: 'And', args: this.predicates }
    return JSON.stringify(expr)
  }

  /**
   * Compiles the policy for evaluation using the native policy engine.
   *
   * @returns Compiled policy JSON string.
   * @throws {@link AuthsError} if compilation fails.
   * @throws Error if the policy has no predicates.
   */
  build(): string {
    if (this.predicates.length === 0) {
      throw new Error(
        'Cannot build an empty policy. Add at least one predicate, ' +
        'or use PolicyBuilder.standard("capability") for the common case.'
      )
    }
    const json = this.toJson()
    try {
      return native.compilePolicy(json)
    } catch (err) {
      throw mapNativeError(err, AuthsError)
    }
  }

  /**
   * Builds and evaluates the policy against a context in one step.
   *
   * @param context - The evaluation context.
   * @returns The policy decision.
   * @throws {@link AuthsError} if compilation or evaluation fails.
   *
   * @example
   * ```typescript
   * const decision = PolicyBuilder.standard('sign').evaluate({
   *   issuer: 'did:keri:EOrg',
   *   subject: 'did:key:zDevice',
   *   capabilities: ['sign'],
   * })
   * console.log(decision.allowed) // true
   * ```
   */
  evaluate(context: EvalContextOpts): PolicyDecision {
    const compiledJson = this.build()
    return evaluatePolicy(compiledJson, context)
  }
}

/**
 * Compiles a raw policy JSON string for use with {@link evaluatePolicy}.
 *
 * @param policyJson - JSON string of the policy expression.
 * @returns Compiled policy JSON.
 * @throws {@link AuthsError} if the policy is invalid.
 */
export function compilePolicy(policyJson: string): string {
  try {
    return native.compilePolicy(policyJson)
  } catch (err) {
    throw mapNativeError(err, AuthsError)
  }
}

/**
 * Evaluates a compiled policy against an attestation context.
 *
 * @param compiledPolicyJson - Compiled policy from {@link compilePolicy} or {@link PolicyBuilder.build}.
 * @param context - The evaluation context.
 * @returns The policy decision with `allowed`/`denied` convenience booleans.
 * @throws {@link AuthsError} if evaluation fails.
 *
 * @example
 * ```typescript
 * import { compilePolicy, evaluatePolicy } from '@auths-dev/sdk'
 *
 * const compiled = compilePolicy(policyJson)
 * const decision = evaluatePolicy(compiled, {
 *   issuer: 'did:keri:EOrg',
 *   subject: 'did:key:zDevice',
 * })
 * ```
 */
export function evaluatePolicy(compiledPolicyJson: string, context: EvalContextOpts): PolicyDecision {
  try {
    const result = native.evaluatePolicy(
      compiledPolicyJson,
      context.issuer,
      context.subject,
      context.capabilities ?? null,
      context.role ?? null,
      context.revoked ?? null,
      context.expiresAt ?? null,
      context.repo ?? null,
      context.environment ?? null,
      context.signerType ?? null,
      context.delegatedBy ?? null,
      context.chainDepth ?? null,
    )
    return {
      outcome: result.outcome,
      reason: result.reason,
      message: result.message,
      allowed: result.outcome === 'allow',
      denied: result.outcome === 'deny',
    }
  } catch (err) {
    throw mapNativeError(err, AuthsError)
  }
}
