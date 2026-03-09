import native from './native'
import { mapNativeError, AuthsError } from './errors'

export interface PolicyDecision {
  outcome: string
  reason: string
  message: string
  allowed: boolean
  denied: boolean
}

export interface EvalContextOpts {
  issuer: string
  subject: string
  capabilities?: string[]
  role?: string
  revoked?: boolean
  expiresAt?: string
  repo?: string
  environment?: string
  signerType?: 'human' | 'agent' | 'workload'
  delegatedBy?: string
  chainDepth?: number
}

type Predicate = Record<string, unknown>

export class PolicyBuilder {
  private predicates: Predicate[] = []

  static standard(capability: string): PolicyBuilder {
    return new PolicyBuilder()
      .notRevoked()
      .notExpired()
      .requireCapability(capability)
  }

  static anyOf(...builders: PolicyBuilder[]): PolicyBuilder {
    const result = new PolicyBuilder()
    const orArgs = builders.map(b => ({ op: 'And', args: b.predicates }))
    result.predicates = [{ op: 'Or', args: orArgs }]
    return result
  }

  notRevoked(): PolicyBuilder {
    this.predicates.push({ op: 'NotRevoked' })
    return this
  }

  notExpired(): PolicyBuilder {
    this.predicates.push({ op: 'NotExpired' })
    return this
  }

  expiresAfter(seconds: number): PolicyBuilder {
    this.predicates.push({ op: 'ExpiresAfter', args: seconds })
    return this
  }

  issuedWithin(seconds: number): PolicyBuilder {
    this.predicates.push({ op: 'IssuedWithin', args: seconds })
    return this
  }

  requireCapability(cap: string): PolicyBuilder {
    this.predicates.push({ op: 'HasCapability', args: cap })
    return this
  }

  requireAllCapabilities(caps: string[]): PolicyBuilder {
    for (const cap of caps) {
      this.requireCapability(cap)
    }
    return this
  }

  requireAnyCapability(caps: string[]): PolicyBuilder {
    const orArgs = caps.map(c => ({ op: 'HasCapability', args: c }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  requireIssuer(did: string): PolicyBuilder {
    this.predicates.push({ op: 'IssuerIs', args: did })
    return this
  }

  requireIssuerIn(dids: string[]): PolicyBuilder {
    const orArgs = dids.map(d => ({ op: 'IssuerIs', args: d }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  requireSubject(did: string): PolicyBuilder {
    this.predicates.push({ op: 'SubjectIs', args: did })
    return this
  }

  requireDelegatedBy(did: string): PolicyBuilder {
    this.predicates.push({ op: 'DelegatedBy', args: did })
    return this
  }

  requireAgent(): PolicyBuilder {
    this.predicates.push({ op: 'IsAgent' })
    return this
  }

  requireHuman(): PolicyBuilder {
    this.predicates.push({ op: 'IsHuman' })
    return this
  }

  requireWorkload(): PolicyBuilder {
    this.predicates.push({ op: 'IsWorkload' })
    return this
  }

  requireRepo(repo: string): PolicyBuilder {
    this.predicates.push({ op: 'RepoIs', args: repo })
    return this
  }

  requireRepoIn(repos: string[]): PolicyBuilder {
    const orArgs = repos.map(r => ({ op: 'RepoIs', args: r }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  requireEnv(env: string): PolicyBuilder {
    this.predicates.push({ op: 'EnvIs', args: env })
    return this
  }

  requireEnvIn(envs: string[]): PolicyBuilder {
    const orArgs = envs.map(e => ({ op: 'EnvIs', args: e }))
    this.predicates.push({ op: 'Or', args: orArgs })
    return this
  }

  refMatches(pattern: string): PolicyBuilder {
    this.predicates.push({ op: 'RefMatches', args: pattern })
    return this
  }

  pathAllowed(patterns: string[]): PolicyBuilder {
    this.predicates.push({ op: 'PathAllowed', args: patterns })
    return this
  }

  maxChainDepth(depth: number): PolicyBuilder {
    this.predicates.push({ op: 'MaxChainDepth', args: depth })
    return this
  }

  attrEquals(key: string, value: string): PolicyBuilder {
    this.predicates.push({ op: 'AttrEquals', args: { key, value } })
    return this
  }

  attrIn(key: string, values: string[]): PolicyBuilder {
    this.predicates.push({ op: 'AttrIn', args: { key, values } })
    return this
  }

  workloadIssuerIs(did: string): PolicyBuilder {
    this.predicates.push({ op: 'WorkloadIssuerIs', args: did })
    return this
  }

  workloadClaimEquals(key: string, value: string): PolicyBuilder {
    this.predicates.push({ op: 'WorkloadClaimEquals', args: { key, value } })
    return this
  }

  orPolicy(other: PolicyBuilder): PolicyBuilder {
    return PolicyBuilder.anyOf(this, other)
  }

  negate(): PolicyBuilder {
    const result = new PolicyBuilder()
    result.predicates = [{ op: 'Not', args: { op: 'And', args: this.predicates } }]
    return result
  }

  toJson(): string {
    if (this.predicates.length === 0) {
      throw new Error('Cannot export an empty policy.')
    }
    const expr = { op: 'And', args: this.predicates }
    return JSON.stringify(expr)
  }

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

  evaluate(context: EvalContextOpts): PolicyDecision {
    const compiledJson = this.build()
    return evaluatePolicy(compiledJson, context)
  }
}

export function compilePolicy(policyJson: string): string {
  try {
    return native.compilePolicy(policyJson)
  } catch (err) {
    throw mapNativeError(err, AuthsError)
  }
}

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
