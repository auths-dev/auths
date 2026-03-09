import { describe, it, expect } from 'vitest'
import { PolicyBuilder, compilePolicy, evaluatePolicy } from '../lib/policy'

describe('PolicyBuilder', () => {
  it('standard factory creates not_revoked + not_expired + capability', () => {
    const json = PolicyBuilder.standard('sign_commit').toJson()
    const parsed = JSON.parse(json)
    expect(parsed.op).toBe('And')
    expect(parsed.args).toHaveLength(3)
    expect(parsed.args[0].op).toBe('NotRevoked')
    expect(parsed.args[1].op).toBe('NotExpired')
    expect(parsed.args[2].op).toBe('HasCapability')
    expect(parsed.args[2].args).toBe('sign_commit')
  })

  it('fluent chaining builds correct expression', () => {
    const json = new PolicyBuilder()
      .notRevoked()
      .requireCapability('sign')
      .requireIssuer('did:keri:EOrg')
      .requireHuman()
      .maxChainDepth(3)
      .toJson()
    const parsed = JSON.parse(json)
    expect(parsed.op).toBe('And')
    expect(parsed.args).toHaveLength(5)
  })

  it('anyOf creates OR combinator', () => {
    const a = PolicyBuilder.standard('admin')
    const b = PolicyBuilder.standard('superadmin')
    const json = PolicyBuilder.anyOf(a, b).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.op).toBe('And')
    expect(parsed.args[0].op).toBe('Or')
    expect(parsed.args[0].args).toHaveLength(2)
  })

  it('negate wraps in Not', () => {
    const json = new PolicyBuilder().notRevoked().negate().toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args[0].op).toBe('Not')
  })

  it('orPolicy combines two builders', () => {
    const a = new PolicyBuilder().requireCapability('admin')
    const b = new PolicyBuilder().requireCapability('superadmin')
    const json = a.orPolicy(b).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args[0].op).toBe('Or')
  })

  it('empty builder throws on build', () => {
    expect(() => new PolicyBuilder().build()).toThrow('empty policy')
  })

  it('empty builder throws on toJson', () => {
    expect(() => new PolicyBuilder().toJson()).toThrow('empty policy')
  })

  it('expiresAfter adds correct predicate', () => {
    const json = new PolicyBuilder().expiresAfter(3600).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args[0].op).toBe('ExpiresAfter')
    expect(parsed.args[0].args).toBe(3600)
  })

  it('issuedWithin adds correct predicate', () => {
    const json = new PolicyBuilder().issuedWithin(86400).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args[0].op).toBe('IssuedWithin')
    expect(parsed.args[0].args).toBe(86400)
  })

  it('requireAllCapabilities adds multiple HasCapability', () => {
    const json = new PolicyBuilder().requireAllCapabilities(['sign', 'deploy']).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args).toHaveLength(2)
    expect(parsed.args[0].op).toBe('HasCapability')
    expect(parsed.args[1].op).toBe('HasCapability')
  })

  it('requireAnyCapability creates OR', () => {
    const json = new PolicyBuilder().requireAnyCapability(['sign', 'deploy']).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args[0].op).toBe('Or')
    expect(parsed.args[0].args).toHaveLength(2)
  })

  it('requireIssuerIn creates OR of IssuerIs', () => {
    const json = new PolicyBuilder().requireIssuerIn(['did:keri:A', 'did:keri:B']).toJson()
    const parsed = JSON.parse(json)
    expect(parsed.args[0].op).toBe('Or')
  })

  it('signer type predicates', () => {
    expect(JSON.parse(new PolicyBuilder().requireAgent().toJson()).args[0].op).toBe('IsAgent')
    expect(JSON.parse(new PolicyBuilder().requireHuman().toJson()).args[0].op).toBe('IsHuman')
    expect(JSON.parse(new PolicyBuilder().requireWorkload().toJson()).args[0].op).toBe('IsWorkload')
  })

  it('scope predicates', () => {
    expect(JSON.parse(new PolicyBuilder().requireRepo('org/repo').toJson()).args[0].op).toBe('RepoIs')
    expect(JSON.parse(new PolicyBuilder().requireEnv('production').toJson()).args[0].op).toBe('EnvIs')
    expect(JSON.parse(new PolicyBuilder().refMatches('refs/heads/*').toJson()).args[0].op).toBe('RefMatches')
    expect(JSON.parse(new PolicyBuilder().pathAllowed(['src/**']).toJson()).args[0].op).toBe('PathAllowed')
  })

  it('attribute predicates', () => {
    expect(JSON.parse(new PolicyBuilder().attrEquals('team', 'infra').toJson()).args[0].op).toBe('AttrEquals')
    expect(JSON.parse(new PolicyBuilder().attrIn('team', ['infra', 'platform']).toJson()).args[0].op).toBe('AttrIn')
  })
})

describe('compilePolicy', () => {
  it('compiles a valid policy expression', () => {
    const result = compilePolicy('{"op":"NotRevoked"}')
    expect(result).toBeDefined()
    expect(typeof result).toBe('string')
  })

  it('rejects invalid JSON', () => {
    expect(() => compilePolicy('not json')).toThrow()
  })

  it('rejects unknown op', () => {
    expect(() => compilePolicy('{"op":"BogusOp"}')).toThrow()
  })
})

describe('evaluatePolicy', () => {
  it('allows when policy is True', () => {
    const compiled = compilePolicy('{"op":"True"}')
    const decision = evaluatePolicy(compiled, {
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
    })
    expect(decision.outcome).toBe('allow')
    expect(decision.allowed).toBe(true)
    expect(decision.denied).toBe(false)
  })

  it('denies when policy is False', () => {
    const compiled = compilePolicy('{"op":"False"}')
    const decision = evaluatePolicy(compiled, {
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
    })
    expect(decision.outcome).toBe('deny')
    expect(decision.allowed).toBe(false)
    expect(decision.denied).toBe(true)
  })

  it('checks capability present', () => {
    const compiled = compilePolicy('{"op":"HasCapability","args":"sign_commit"}')
    const decision = evaluatePolicy(compiled, {
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
      capabilities: ['sign_commit'],
    })
    expect(decision.allowed).toBe(true)
  })

  it('checks capability missing', () => {
    const compiled = compilePolicy('{"op":"HasCapability","args":"sign_commit"}')
    const decision = evaluatePolicy(compiled, {
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
      capabilities: ['read'],
    })
    expect(decision.denied).toBe(true)
  })

  it('checks NotRevoked passes', () => {
    const compiled = compilePolicy('{"op":"NotRevoked"}')
    const decision = evaluatePolicy(compiled, {
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
      revoked: false,
    })
    expect(decision.allowed).toBe(true)
  })

  it('checks NotRevoked denied when revoked', () => {
    const compiled = compilePolicy('{"op":"NotRevoked"}')
    const decision = evaluatePolicy(compiled, {
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
      revoked: true,
    })
    expect(decision.denied).toBe(true)
  })

  it('PolicyBuilder.evaluate convenience method', () => {
    const decision = PolicyBuilder.standard('sign_commit').evaluate({
      issuer: 'did:keri:ETest',
      subject: 'did:key:zTest',
      capabilities: ['sign_commit'],
    })
    expect(decision.allowed).toBe(true)
  })
})
