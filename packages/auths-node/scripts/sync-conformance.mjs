#!/usr/bin/env node
/**
 * Sync the conformance surface into the package: the golden verify vectors
 * (the exact fixtures the Rust verifier tests against) and the canonical
 * status lists (parsed from the generated declarations, so they cannot drift
 * from the enums).
 *
 * Runs on build and prepublish; consumers assert against `conformance/` from
 * the installed package, which pins the contract to the version they run.
 */

import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const pkg = resolve(import.meta.dirname, '..');
const fixtures = resolve(pkg, '../../crates/auths-verifier/tests/fixtures');
const out = join(pkg, 'conformance');
mkdirSync(out, { recursive: true });

const VECTORS = ['presentation_valid.json', 'credential_valid.json', 'credential_revoked.json'];
for (const name of VECTORS) {
  copyFileSync(join(fixtures, name), join(out, name));
}

// The verdict manifest, generated in the workspace by `xtask gen-contracts`
// from the source `code()` methods and gated against drift in CI. Shipping it
// here lets a JS/TS consumer assert every verdict string against the exact
// contract the SDK version they installed was built from.
copyFileSync(resolve(pkg, '../../schemas/contracts-v1.json'), join(out, 'verdicts.json'));

const dts = readFileSync(join(pkg, 'index.d.ts'), 'utf8');
function enumValues(name) {
  const match = dts.match(new RegExp(`export declare const enum ${name} \\{([\\s\\S]*?)\\n\\}`));
  if (!match) throw new Error(`enum ${name} not found in index.d.ts`);
  return [...match[1].matchAll(/= '([^']+)'/g)].map((m) => m[1]);
}

writeFileSync(
  join(out, 'statuses.json'),
  JSON.stringify(
    {
      presentationStatuses: enumValues('PresentationStatus'),
      credentialStatuses: enumValues('CredentialStatus'),
    },
    null,
    2,
  ) + '\n',
);

console.log(`conformance synced: ${VECTORS.length} vectors + statuses.json`);
