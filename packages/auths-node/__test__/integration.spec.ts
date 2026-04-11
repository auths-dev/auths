import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execSync } from 'child_process'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { Auths } from '../lib/client'
import type { Identity } from '../lib/identity'

const tmpDirs: string[] = []

function makeTmpDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'auths-test-'))
  tmpDirs.push(dir)
  return dir
}

afterAll(() => {
  for (const dir of tmpDirs) {
    rmSync(dir, { recursive: true, force: true })
  }
})

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
    identity = auths.identities.create({ label: 'test-key' })
  })

  it('creates identity with did:keri prefix', () => {
    expect(identity.did).toMatch(/^did:keri:/)
    expect(identity.keyAlias).toBeDefined()
    expect(identity.publicKey).toBeDefined()
    // 64 hex chars (Ed25519, 32 bytes) or 66 hex chars (P-256 compressed, 33 bytes)
    expect([64, 66]).toContain(identity.publicKey.length)
  })

  it('getPublicKey returns hex string', () => {
    const pk = auths.getPublicKey({ identityDid: identity.did })
    expect(pk).toBe(identity.publicKey)
  })

  it('delegates an agent', () => {
    const agent = auths.identities.delegateAgent({
      identityDid: identity.did,
      name: 'ci-bot',
      capabilities: ['sign'],
    })
    expect(agent.did).toMatch(/^did:key:/)
    expect(agent.keyAlias).toBeDefined()
    expect(agent.attestation).toBeDefined()
  })

  it('creates standalone agent', () => {
    const agent = auths.identities.createAgent({
      name: 'standalone',
      capabilities: ['sign'],
    })
    expect(agent.did).toMatch(/^did:keri:/)
    expect(agent.keyAlias).toBeDefined()
  })
})

describe('device lifecycle', () => {
  it('link and revoke device', () => {
    const auths = makeClient()
    const identity = auths.identities.create({ label: 'dev-test' })

    const device = auths.devices.link({
      identityDid: identity.did,
      capabilities: ['sign'],
      expiresInDays: 90,
    })
    expect(device.did).toMatch(/^did:key:/)
    expect(device.attestationId).toBeDefined()

    auths.devices.revoke({
      deviceDid: device.did,
      identityDid: identity.did,
      note: 'test revocation',
    })
  })

  it('extend device authorization', () => {
    const auths = makeClient()
    const identity = auths.identities.create({ label: 'ext-test' })
    const device = auths.devices.link({
      identityDid: identity.did,
      capabilities: ['sign'],
      expiresInDays: 30,
    })

    const ext = auths.devices.extend({
      deviceDid: device.did,
      identityDid: identity.did,
      days: 60,
    })
    expect(ext.deviceDid).toBe(device.did)
    expect(ext.newExpiresAt).toBeDefined()
  })
})

describe('signing', () => {
  let auths: Auths
  let identity: Identity

  beforeAll(() => {
    auths = makeClient()
    identity = auths.identities.create({ label: 'sign-test' })
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
    const identity = auths.identities.create({ label: 'trust-test' })

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
    const identity = auths.identities.create({ label: 'trust-rm' })
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
    auths.identities.create({ label: 'witness-test' })

    const w = auths.witnesses.add({ url: 'http://witness.example.com:3333' })
    expect(w.url).toBe('http://witness.example.com:3333')

    const witnesses = auths.witnesses.list()
    expect(witnesses.length).toBe(1)
  })

  it('remove witness', () => {
    const auths = makeClient()
    auths.identities.create({ label: 'witness-rm' })

    auths.witnesses.add({ url: 'http://witness.example.com:3333' })
    auths.witnesses.remove('http://witness.example.com:3333')

    expect(auths.witnesses.list().length).toBe(0)
  })

  it('duplicate add is idempotent', () => {
    const auths = makeClient()
    auths.identities.create({ label: 'witness-dup' })

    auths.witnesses.add({ url: 'http://witness.example.com:3333' })
    auths.witnesses.add({ url: 'http://witness.example.com:3333' })

    expect(auths.witnesses.list().length).toBe(1)
  })
})

describe('attestations', () => {
  it('list returns array', () => {
    const auths = makeClient()
    auths.identities.create({ label: 'att-test' })
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
    auths.identities.create({ label: 'org-admin' })

    const org = auths.orgs.create({ label: 'my-team' })
    expect(org.orgDid).toMatch(/^did:keri:/)
    expect(org.label).toBe('my-team')
  })

  it('add and list members', () => {
    const adminDir = makeTmpDir()
    const admin = makeClient(adminDir)
    admin.identities.create({ label: 'admin' })
    const org = admin.orgs.create({ label: 'team' })

    const devDir = makeTmpDir()
    const devClient = makeClient(devDir)
    const devId = devClient.identities.create({ label: 'dev' })

    const member = admin.orgs.addMember({
      orgDid: org.orgDid,
      memberDid: devId.did,
      role: 'member',
      memberPublicKeyHex: devId.publicKey,
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
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const native = require('../index.js')
    expect(typeof native.version()).toBe('string')
    expect(native.version()).toMatch(/^\d+\.\d+\.\d+/)
  })
})

describe('pairing', () => {
  it('creates session and stops cleanly', async () => {
    const auths = makeClient()
    auths.identities.create({ label: 'pair-test' })

    const session = await auths.pairing.createSession({
      bindAddress: '127.0.0.1',
      enableMdns: false,
      capabilities: ['sign:commit'],
    })
    expect(session.shortCode.length).toBe(6)
    expect(session.endpoint).toMatch(/^http:\/\/127\.0\.0\.1:/)
    expect(session.controllerDid).toMatch(/^did:keri:/)

    await auths.pairing.stop()
  })

  it('stop is idempotent', async () => {
    const auths = makeClient()
    auths.identities.create({ label: 'pair-stop' })

    await auths.pairing.createSession({
      bindAddress: '127.0.0.1',
      enableMdns: false,
    })
    await auths.pairing.stop()
    await auths.pairing.stop()
  })

  it('multiple concurrent sessions on separate clients', async () => {
    const auths1 = makeClient()
    auths1.identities.create({ label: 'pair-multi-1' })

    const auths2 = makeClient()
    auths2.identities.create({ label: 'pair-multi-2' })

    const session1 = await auths1.pairing.createSession({
      bindAddress: '127.0.0.1',
      enableMdns: false,
    })
    const session2 = await auths2.pairing.createSession({
      bindAddress: '127.0.0.1',
      enableMdns: false,
    })

    expect(session1.endpoint).not.toBe(session2.endpoint)
    expect(session1.shortCode).not.toBe(session2.shortCode)

    await auths1.pairing.stop()
    await auths2.pairing.stop()
  })

  it('waitForResponse without session throws', async () => {
    const auths = makeClient()
    auths.identities.create({ label: 'pair-no-session' })

    await expect(auths.pairing.waitForResponse()).rejects.toThrow(
      /No active pairing session/,
    )
  })

  it('complete without session throws', async () => {
    const auths = makeClient()
    auths.identities.create({ label: 'pair-no-session-complete' })

    await expect(
      auths.pairing.complete({
        deviceDid: 'did:key:fake',
        devicePublicKeyHex: 'a'.repeat(64),
      }),
    ).rejects.toThrow(/No active pairing session/)
  })
})

describe('verify async', () => {
  it('verifyAttestation returns a Promise', async () => {
    const { verifyAttestation } = await import('../lib/verify')
    const result = verifyAttestation('{}', 'a'.repeat(64))
    expect(result).toBeInstanceOf(Promise)
    const resolved = await result
    expect(resolved.valid).toBe(false)
  })

  it('verifyChain returns a Promise', async () => {
    const { verifyChain } = await import('../lib/verify')
    const result = verifyChain([], 'a'.repeat(64))
    expect(result).toBeInstanceOf(Promise)
    const resolved = await result
    expect(resolved.status).toBeDefined()
  })
})

describe('agent attestation', () => {
  it('createAgent produces a signed attestation with required fields', () => {
    const auths = makeClient()
    auths.identities.create({ label: 'agent-att-test' })
    const agent = auths.identities.createAgent({
      name: 'test-bot',
      capabilities: ['sign'],
    })
    expect(agent.attestation).toBeDefined()
    const att = JSON.parse(agent.attestation)
    expect(att.issuer).toBeDefined()
    expect(att.subject).toBeDefined()
    expect(att.device_signature).toBeDefined()
    expect(att.identity_signature).toBeDefined()
    expect(att.rid).toBeDefined()
    expect(att.version).toBeDefined()
    expect(att.device_public_key).toBeDefined()
  })
})
