/**
 * Cross-language conformance: shared fixture vectors emitted by the Rust verifier.
 *
 * Mirrors packages/auths-verifier-go/verifier_fixtures_test.go — loads the same
 * committed fixtures from crates/auths-verifier/tests/fixtures/ and asserts this
 * binding's verdicts match the canonical Rust verdicts (valid / revoked / malformed),
 * proving the WASM build does not diverge.
 *
 * Follows the conditional-skip pattern of verifier.test.ts: tests no-op when the
 * WASM artifact is absent, cannot load under jest's CJS runtime, or predates the
 * `verifyPresentationJson`/`verifyCredentialJson` exports (run `npm run build:wasm`).
 * They also no-op when the fixtures are unavailable (package vendored outside the
 * monorepo), matching the Go test's skip behaviour.
 */

import { readFileSync } from 'fs';
import { join } from 'path';

interface FixtureVerdict {
  schemaVersion: number;
  kind: string;
  subject?: string;
  caps?: string[];
  revokedAt?: number;
  message?: string;
}

type VerifyJsonFn = (bundleJson: string) => string;

interface WasmVerifyExports {
  verifyPresentationJson?: VerifyJsonFn;
  verifyCredentialJson?: VerifyJsonFn;
}

const FIXTURE_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  'crates',
  'auths-verifier',
  'tests',
  'fixtures'
);

let verifyPresentationJson: VerifyJsonFn | null = null;
let verifyCredentialJson: VerifyJsonFn | null = null;

beforeAll(async () => {
  let wasm: WasmVerifyExports;
  try {
    wasm = (await import('../wasm/auths_verifier.js')) as unknown as WasmVerifyExports;
  } catch {
    console.warn('WASM module not available, skipping fixture conformance tests');
    console.warn('Run `npm run build:wasm` to build the WASM module');
    return;
  }

  if (
    typeof wasm.verifyPresentationJson !== 'function' ||
    typeof wasm.verifyCredentialJson !== 'function'
  ) {
    console.warn(
      'WASM artifact predates verifyPresentationJson/verifyCredentialJson; ' +
        'run `npm run build:wasm` to regenerate. Skipping fixture conformance tests.'
    );
    return;
  }

  verifyPresentationJson = wasm.verifyPresentationJson;
  verifyCredentialJson = wasm.verifyCredentialJson;
});

function readFixture(name: string): string | null {
  try {
    return readFileSync(join(FIXTURE_DIR, name), 'utf8');
  } catch {
    return null;
  }
}

function parseVerdict(fn: VerifyJsonFn, input: string): FixtureVerdict {
  return JSON.parse(fn(input)) as FixtureVerdict;
}

describe('fixture conformance (shared Rust vectors)', () => {
  it('returns a valid verdict for the valid presentation fixture', () => {
    const fixture = readFixture('presentation_valid.json');
    if (!verifyPresentationJson || fixture === null) return;

    const verdict = parseVerdict(verifyPresentationJson, fixture);
    expect(verdict.schemaVersion).toBe(1);
    expect(verdict.kind).toBe('valid');
    expect(verdict.subject).toMatch(/^did:keri:/);
    expect(verdict.caps).toEqual(['sign']);
  });

  it('returns a valid verdict for the valid credential fixture', () => {
    const fixture = readFixture('credential_valid.json');
    if (!verifyCredentialJson || fixture === null) return;

    const verdict = parseVerdict(verifyCredentialJson, fixture);
    expect(verdict.schemaVersion).toBe(1);
    expect(verdict.kind).toBe('valid');
    expect(verdict.caps).toEqual(['sign']);
  });

  it('rejects the revoked credential fixture with a revocation verdict', () => {
    const fixture = readFixture('credential_revoked.json');
    if (!verifyCredentialJson || fixture === null) return;

    const verdict = parseVerdict(verifyCredentialJson, fixture);
    expect(verdict.kind).toBe('credentialRevoked');
    expect(verdict.kind).not.toBe('valid');
    expect(typeof verdict.revokedAt).toBe('number');
  });

  it('returns a typed malformedRequest verdict (not a throw) for garbage input', () => {
    if (!verifyPresentationJson) return;

    const verdict = parseVerdict(verifyPresentationJson, '{not json');
    expect(verdict.kind).toBe('malformedRequest');
    expect(verdict.message).toBeTruthy();
  });
});
