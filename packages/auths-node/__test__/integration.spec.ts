import { describe, it, expect, beforeAll } from 'vitest'
import { execSync } from 'child_process'
import { mkdtempSync, writeFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { Auths } from '../lib/client'
import type { Identity } from '../lib/identity'

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), 'auths-test-'))
}

function makeClient(dir?: string): Auths {
  const repoPath = dir ?? makeTmpDir()
  return new Auths({ repoPath, passphrase: 'Test-pass-123' })
}

function initGitRepo(dir: string): void {
  mkdirSync(dir, { recursive: true })
  execSync('git init', { cwd: dir, stdio: 'pipe' })
  execSync('git config user.name "Test User"', { cwd: dir, stdio: 'pipe' })
  execSync('git config user.email "test@example.com"', { cwd: dir, stdio: 'pipe' })
  execSync('git config commit.gpgsign false', { cwd: dir, stdio: 'pipe' })
  writeFileSync(join(dir, 'README.md'), '# Test Repo\n')
  execSync('git add .', { cwd: dir, stdio: 'pipe' })
  execSync('git commit -m "initial commit"', { cwd: dir, stdio: 'pipe' })
}

describe('identity lifecycle', () => {
  let auths: Auths
  let identity: Identity

  beforeAll(() => {
    auths = makeClient()
    identity = auths.identities.create({ keyAlias: 'test-key' })
  })

  it('creates identity with did:keri prefix', () => {
    expect(identity.did).toMatch(/^did:keri:/)
    expect(identity.keyAlias).toBeDefined()
    expect(identity.publicKeyHex).toBeDefined()
    expect(identity.publicKeyHex.length).toBe(64)
  })

  it('getPublicKey returns hex string', () => {
    const pk = auths.getPublicKey({ identityDid: identity.did })
    expect(pk).toBe(identity.publicKeyHex)
  })

  it('delegates an agent', () => {
    const agent = auths.identities.delegateAgent({
      identityDid: identity.did,
      agentName: 'ci-bot',
      capabilities: ['sign'],
    })
    expect(agent.agentDid).toMatch(/^did:key:/)
    expect(agent.keyAlias).toBeDefined()
    expect(agent.attestationJson).toBeDefined()
  })

  it('creates standalone agent', () => {
    const agent = auths.identities.createAgent({
      agentName: 'standalone',
      capabilities: ['sign'],
    })
    expect(agent.agentDid).toMatch(/^did:keri:/)
    expect(agent.keyAlias).toBeDefined()
  })
})

describe('device lifecycle', () => {
  it('link and revoke device', () => {
    const auths = makeClient()
    const identity = auths.identities.create({ keyAlias: 'dev-test' })

    const device = auths.devices.link({
      identityDid: identity.did,
      capabilities: ['sign'],
      expiresInDays: 90,
    })
    expect(device.deviceDid).toMatch(/^did:key:/)
    expect(device.attestationId).toBeDefined()

    auths.devices.revoke({
      deviceDid: device.deviceDid,
      identityDid: identity.did,
      note: 'test revocation',
    })
  })

  it('extend device authorization', () => {
    const auths = makeClient()
    const identity = auths.identities.create({ keyAlias: 'ext-test' })
    const device = auths.devices.link({
      identityDid: identity.did,
      capabilities: ['sign'],
      expiresInDays: 30,
    })

    const ext = auths.devices.extend({
      deviceDid: device.deviceDid,
      identityDid: identity.did,
      days: 60,
    })
    expect(ext.deviceDid).toBe(device.deviceDid)
    expect(ext.newExpiresAt).toBeDefined()
  })
})

describe('signing', () => {
  let auths: Auths
  let identity: Identity

  beforeAll(() => {
    auths = makeClient()
    identity = auths.identities.create({ keyAlias: 'sign-test' })
  })

  it('sign as identity returns signature', () => {
    const result = auths.signAs({
      message: Buffer.from('hello world'),
      identityDid: identity.did,
    })
    expect(result.signature).toBeDefined()
    expect(result.signerDid).toBeDefined()
  })

  it('sign action as identity returns envelope', () => {
    const result = auths.signActionAs({
      actionType: 'tool_call',
      payloadJson: '{"tool":"read_file"}',
      identityDid: identity.did,
    })
    expect(result.envelopeJson).toBeDefined()
    expect(result.signatureHex).toBeDefined()
    expect(result.signerDid).toBeDefined()
  })
})

describe('trust', () => {
  it('pin and list', () => {
    const auths = makeClient()
    const identity = auths.identities.create({ keyAlias: 'trust-test' })

    const entry = auths.trust.pin({ did: identity.did, label: 'my-peer' })
    expect(entry.did).toBe(identity.did)
    expect(entry.label).toBe('my-peer')
    expect(entry.trustLevel).toBeDefined()

    const entries = auths.trust.list()
    expect(entries.length).toBeGreaterThanOrEqual(1)
    expect(entries.some(e => e.did === identity.did)).toBe(true)
  })

  it('remove pinned identity', () => {
    const auths = makeClient()
    const identity = auths.identities.create({ keyAlias: 'trust-rm' })
    auths.trust.pin({ did: identity.did })
    auths.trust.remove(identity.did)
    const result = auths.trust.get(identity.did)
    expect(result).toBeNull()
  })

  it('get returns null for unknown', () => {
    const auths = makeClient()
    const result = auths.trust.get('did:keri:ENOTREAL')
    expect(result).toBeNull()
  })
})

describe('witness', () => {
  it('add and list witnesses', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'witness-test' })

    const w = auths.witnesses.add({ url: 'http://witness.example.com:3333' })
    expect(w.url).toBe('http://witness.example.com:3333/')

    const witnesses = auths.witnesses.list()
    expect(witnesses.length).toBe(1)
  })

  it('remove witness', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'witness-rm' })

    auths.witnesses.add({ url: 'http://witness.example.com:3333' })
    auths.witnesses.remove('http://witness.example.com:3333/')

    expect(auths.witnesses.list().length).toBe(0)
  })

  it('duplicate add is idempotent', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'witness-dup' })

    auths.witnesses.add({ url: 'http://witness.example.com:3333' })
    auths.witnesses.add({ url: 'http://witness.example.com:3333' })

    expect(auths.witnesses.list().length).toBe(1)
  })
})

describe('attestations', () => {
  it('list returns array', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'att-test' })
    const atts = auths.attestations.list()
    expect(Array.isArray(atts)).toBe(true)
  })
})

describe('audit', () => {
  it('generates report for unsigned repo', () => {
    const auths = makeClient()
    const gitDir = join(makeTmpDir(), 'git-repo')
    initGitRepo(gitDir)

    const report = auths.audit.report({ targetRepoPath: gitDir })
    expect(report.summary.total_commits).toBe(1)
    expect(report.summary.unsigned_commits).toBe(1)
    expect(report.summary.signed_commits).toBe(0)
    expect(Array.isArray(report.commits)).toBe(true)
  })

  it('isCompliant returns false for unsigned', () => {
    const auths = makeClient()
    const gitDir = join(makeTmpDir(), 'git-repo')
    initGitRepo(gitDir)
    expect(auths.audit.isCompliant({ targetRepoPath: gitDir })).toBe(false)
  })
})

describe('org', () => {
  it('creates organization', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'org-admin' })

    const org = auths.orgs.create({ label: 'my-team' })
    expect(org.orgDid).toMatch(/^did:keri:/)
    expect(org.label).toBe('my-team')
  })

  it('add and list members', () => {
    const adminDir = makeTmpDir()
    const admin = makeClient(adminDir)
    admin.identities.create({ keyAlias: 'admin' })
    const org = admin.orgs.create({ label: 'team' })

    const devDir = makeTmpDir()
    const devClient = makeClient(devDir)
    const devId = devClient.identities.create({ keyAlias: 'dev' })

    const member = admin.orgs.addMember({
      orgDid: org.orgDid,
      memberDid: devId.did,
      role: 'member',
      memberPublicKeyHex: devId.publicKeyHex,
    })
    expect(member.memberDid).toBe(devId.did)
    expect(member.role).toBe('member')
    expect(member.revoked).toBe(false)

    const members = admin.orgs.listMembers({ orgDid: org.orgDid })
    expect(members.length).toBeGreaterThanOrEqual(1)
  })
})

describe('doctor', () => {
  it('returns diagnostics string', () => {
    const auths = makeClient()
    const result = auths.doctor()
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(0)
  })
})

describe('version', () => {
  it('returns version string', () => {
    const { version } = require('../lib/index')
    expect(typeof version()).toBe('string')
    expect(version()).toMatch(/^\d+\.\d+\.\d+/)
  })
})

describe('pairing', () => {
  it('creates session and stops cleanly', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'pair-test' })

    const session = auths.pairing.createSession({
      bindAddress: '127.0.0.1',
      enableMdns: false,
      capabilities: ['sign:commit'],
    })
    expect(session.shortCode.length).toBe(6)
    expect(session.endpoint).toMatch(/^http:\/\/127\.0\.0\.1:/)
    expect(session.controllerDid).toMatch(/^did:keri:/)

    auths.pairing.stop()
  })

  it('stop is idempotent', () => {
    const auths = makeClient()
    auths.identities.create({ keyAlias: 'pair-stop' })

    auths.pairing.createSession({
      bindAddress: '127.0.0.1',
      enableMdns: false,
    })
    auths.pairing.stop()
    auths.pairing.stop()
  })
})
