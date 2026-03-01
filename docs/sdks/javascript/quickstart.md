# JavaScript SDK

TypeScript/JavaScript library for verifying Auths attestations using WASM.

## Installation

```bash
npm install @auths/verifier
```

Requirements: Node.js 18+

## Quick start

```typescript
import { init, verifyAttestation, verifyChain } from '@auths/verifier';

// Initialize WASM module (required once)
await init();

// Verify a single attestation
const result = verifyAttestation(attestationJson, issuerPublicKeyHex);
if (result.valid) {
  console.log('Attestation is valid!');
} else {
  console.error('Verification failed:', result.error);
}
```

## Verify a chain

```typescript
const report = verifyChain(attestationsArray, rootPublicKeyHex);
if (report.status.type === 'Valid') {
  console.log('Chain verified!');
} else {
  console.error('Chain verification failed:', report.status);
}

// Check individual links
report.chain.forEach((link, i) => {
  console.log(`Link ${i}: ${link.valid ? 'OK' : link.error}`);
});
```

## API reference

### Functions

#### `init(): Promise<void>`

Initialize the WASM module. Must be called once before any verification.

#### `verifyAttestation(json, pkHex): VerificationResult`

Verify a single attestation.

```typescript
interface VerificationResult {
  valid: boolean;
  error?: string;
}
```

#### `verifyChain(attestations, rootPkHex): VerificationReport`

Verify a chain of attestations. Accepts JSON strings or objects.

```typescript
interface VerificationReport {
  status: VerificationStatus;
  chain: ChainLink[];
  warnings: string[];
}

type VerificationStatus =
  | { type: "Valid" }
  | { type: "Expired"; at: string }
  | { type: "Revoked"; at?: string }
  | { type: "InvalidSignature"; step: number }
  | { type: "BrokenChain"; missing_link: string };
```

#### `verifyAttestationOrThrow(json, pkHex): void`

Same as `verifyAttestation` but throws on failure.

#### `isInitialized(): boolean`

Check if the WASM module has been initialized.

#### `isVerificationValid(report): boolean`

Helper to check if a report indicates success.

## Browser usage

```html
<script type="module">
import init, { verifyAttestation } from './pkg/auths_verifier.js';

await init();
const result = verifyAttestation(json, pkHex);
</script>
```

The WASM module works in modern browsers with ES module support.

## Web Component

For a drop-in verification badge (no code required), use the [`auths-verify`](https://www.npmjs.com/package/auths-verify) web component:

```html
<script type="module" src="https://unpkg.com/auths-verify/dist/auths-verify.mjs"></script>

<auths-verify
  attestation='{"version":1,...}'
  public-key="aabbccdd..."
></auths-verify>
```

It wraps `@auths/verifier` WASM in a custom element with badge, detail, and tooltip display modes. See the [GitHub repo](https://github.com/bordumb/auths-verify-widget) and [npm package](https://www.npmjs.com/package/auths-verify) for full documentation.

## Building from source

```bash
npm install
npm run build:wasm   # Requires Rust and wasm-pack
npm run build:ts
npm run build        # Build everything
npm test
```
