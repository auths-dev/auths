import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

// eslint-disable-next-line @typescript-eslint/no-var-requires
const native = require('../index.js')

// A minimal activity/v1-shaped document that PARSES (so verification reaches the
// registry path rather than the "not activity/v1-shaped" early return). Its
// as_of is in the past, so the future-rejection guard does not fire.
const shapedDoc = JSON.stringify({
  version: 'activity/v1',
  suite: 'json-canon/ed25519',
  subject: { root: 'did:keri:Eroot', agent: 'did:keri:Eagent' },
  head: '11'.repeat(32),
  count: 1,
  cumulative_cents: 100,
  as_of: { ts: '2020-01-01T00:00:00Z' },
  signature: 'AAAA',
})

describe('verifyActivityAttestation', () => {
  it('is exported', () => {
    expect(typeof native.verifyActivityAttestation).toBe('function')
  })

  it('returns a JSON verdict (not a throw) for malformed input', () => {
    const v = JSON.parse(native.verifyActivityAttestation('{not json', '/nonexistent'))
    expect(v.ok).toBe(false)
    expect(typeof v.reason).toBe('string')
  })

  it('accepts the options argument and returns a parseable verdict', () => {
    const dir = mkdtempSync(join(tmpdir(), 'auths-activity-'))
    // No resolvable KEL at this path, so the verdict is a clean ok:false — the
    // point is that passing options does not throw at the binding boundary.
    const v = JSON.parse(
      native.verifyActivityAttestation(shapedDoc, dir, {
        requireWitness: true,
        witnessTipIndex: 5,
      }),
    )
    expect(v.ok).toBe(false)
    expect(typeof v.reason).toBe('string')
  })

  // The verdict SHAPE now carries the anchor tier and freshness bound a relying
  // party gates on — locked here against the shipped type contract so a
  // regression that drops a field goes red even without a live registry (the
  // valid-verdict field VALUES are exercised by the Rust attestation battery).
  it('the shipped contract declares anchor, freshness, and headBound', () => {
    const dts = readFileSync(new URL('../index.d.ts', import.meta.url), 'utf8')
    expect(dts).toContain('VerifyActivityOpts')
    expect(dts).toMatch(/requireWitness\?/)
    expect(dts).toMatch(/witnessTipIndex\?/)
    expect(dts).toMatch(/anchor/)
    expect(dts).toMatch(/freshness/)
    expect(dts).toMatch(/headBound/)
  })
})
