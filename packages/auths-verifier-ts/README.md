# @auths/verifier

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

// Verify a chain of attestations
const report = verifyChain(attestationsArray, rootPublicKeyHex);
if (report.status.type === 'Valid') {
  console.log('Chain verified!');
}
```

## API reference

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `init()` | `Promise<void>` | Initialize WASM module (call once) |
| `verifyAttestation(json, pkHex)` | `VerificationResult` | Verify single attestation |
| `verifyChain(attestations, rootPkHex)` | `VerificationReport` | Verify attestation chain |
| `verifyAttestationOrThrow(json, pkHex)` | `void` | Verify or throw on failure |
| `isInitialized()` | `boolean` | Check WASM init state |
| `isVerificationValid(report)` | `boolean` | Helper for report status |

### Types

```typescript
interface VerificationResult {
  valid: boolean;
  error?: string;
}

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

## Browser usage

```html
<script type="module">
import init, { verifyAttestation } from './pkg/auths_verifier.js';

await init();
const result = verifyAttestation(json, pkHex);
</script>
```

## Building from source

```bash
npm install
npm run build:wasm   # Requires Rust and wasm-pack
npm run build:ts
npm run build        # Build everything
npm test
```

## License

MIT -- see [LICENSE](../../LICENSE).

## Links

- [Documentation](https://github.com/auths-dev/auths/tree/main/packages/auths-verifier-ts)
- [Repository](https://github.com/auths-dev/auths)
