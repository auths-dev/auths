# WASM Embedding

The `auths-verifier` crate compiles to WebAssembly for browser and edge-runtime verification. The TypeScript wrapper package `@auths/verifier` provides a typed API on top of the raw WASM exports.

## Installation

```bash
npm install @auths/verifier
```

Requirements: Node.js 18+

## Quick start

```typescript
import { init, verifyAttestation, verifyChain } from '@auths/verifier';

// Initialize WASM module (required once, before any verification)
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

## Building from source

Building requires the Rust toolchain and `wasm-pack`:

```bash
# Install wasm-pack
cargo install wasm-pack

# Build the WASM module (from the packages/auths-verifier-ts directory)
npm run build:wasm

# Build the TypeScript wrapper
npm run build:ts

# Or build everything at once
npm run build
```

The `build:wasm` script runs:

```bash
cd crates/auths-verifier && wasm-pack build --target bundler --features wasm \
  --out-dir ../../packages/auths-verifier-ts/wasm
```

The WASM crate must be built from inside `crates/auths-verifier` because the workspace uses resolver = "3", which rejects `--features` from the workspace root.

## WASM exports

The `wasm` feature flag enables these `wasm_bindgen` exports. All verification functions are `async` because the underlying Ed25519 operations use the Web Crypto API.

### `verifyAttestationJson`

Verify a single attestation. Throws a `JsValue` error string on failure.

```typescript
// WASM export (raw)
async function verifyAttestationJson(
  attestationJson: string,
  issuerPkHex: string
): Promise<void>;
```

### `verifyAttestationWithResult`

Verify a single attestation and return a JSON result string instead of throwing.

```typescript
// WASM export (raw)
async function verifyAttestationWithResult(
  attestationJson: string,
  issuerPkHex: string
): Promise<string>;  // JSON: {"valid": true} or {"valid": false, "error": "..."}
```

### `verifyArtifactSignature`

Verify a detached Ed25519 signature over a file hash. All inputs are hex-encoded.

```typescript
// WASM export (raw)
async function verifyArtifactSignature(
  fileHashHex: string,
  signatureHex: string,
  publicKeyHex: string
): Promise<boolean>;
```

### `verifyChainJson`

Verify an ordered attestation chain. Returns a JSON `VerificationReport` string.

```typescript
// WASM export (raw)
async function verifyChainJson(
  attestationsJsonArray: string,
  rootPkHex: string
): Promise<string>;  // JSON VerificationReport
```

### `verifyChainWithWitnesses`

Verify a chain with witness quorum checking.

```typescript
// WASM export (raw)
async function verifyChainWithWitnesses(
  chainJson: string,
  rootPkHex: string,
  receiptsJson: string,
  witnessKeysJson: string,
  threshold: number
): Promise<string>;  // JSON VerificationReport
```

The `witnessKeysJson` parameter is a JSON array of `{"did": "...", "pk_hex": "..."}` objects.

## TypeScript wrapper API

The `@auths/verifier` package wraps the raw WASM exports with typed functions. You must call `init()` before using any verification function.

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `init()` | `Promise<void>` | Initialize WASM module (call once) |
| `isInitialized()` | `boolean` | Check WASM init state |
| `verifyAttestation(json, pkHex)` | `VerificationResult` | Verify single attestation |
| `verifyAttestationOrThrow(json, pkHex)` | `void` | Verify or throw on failure |
| `verifyChain(attestations, rootPkHex)` | `VerificationReport` | Verify attestation chain |
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
  | { type: "Revoked"; at?: string | null }
  | { type: "InvalidSignature"; step: number }
  | { type: "BrokenChain"; missing_link: string };

interface ChainLink {
  issuer: string;
  subject: string;
  valid: boolean;
  error?: string | null;
}

interface Attestation {
  version: number;
  rid: string;
  issuer: string;
  subject: string;
  device_public_key: string;
  identity_signature: string;
  device_signature: string;
  revoked: boolean;
  expires_at?: string | null;
  timestamp?: string | null;
  note?: string | null;
  payload?: unknown;
}
```

## Usage examples

### Verify a single attestation

```typescript
import { init, verifyAttestation } from '@auths/verifier';

await init();

const result = verifyAttestation(
  JSON.stringify(attestation),
  'a1b2c3d4e5f6...'  // 64 hex characters (32-byte Ed25519 public key)
);

if (result.valid) {
  console.log('Attestation is valid!');
} else {
  console.error('Invalid:', result.error);
}
```

### Verify a chain of attestations

```typescript
import { init, verifyChain } from '@auths/verifier';

await init();

// Accepts JSON strings or plain objects
const report = verifyChain(
  [rootToDeviceAttestation, deviceToSubDeviceAttestation],
  rootPublicKeyHex
);

if (report.status.type === 'Valid') {
  console.log('Chain verified!');
} else {
  console.error('Chain invalid:', report.status);
}

// Inspect individual links
report.chain.forEach((link, i) => {
  console.log(`Link ${i}: ${link.valid ? 'OK' : link.error}`);
});
```

### Throw-on-failure pattern

```typescript
import { init, verifyAttestationOrThrow } from '@auths/verifier';

await init();

try {
  verifyAttestationOrThrow(attestationJson, issuerPkHex);
  console.log('Valid!');
} catch (error) {
  console.error('Verification failed:', error.message);
}
```

### Browser usage

```html
<script type="module">
import init, {
  verifyAttestationJson,
  verifyChainJson
} from './wasm/auths_verifier.js';

// Initialize the WASM module
await init();

// Verify directly with the raw WASM exports
try {
  await verifyAttestationJson(attestationJson, issuerPkHex);
  console.log('Valid!');
} catch (error) {
  console.error('Invalid:', error);
}
</script>
```

## Bundle size

The WASM binary is approximately 200-300 KB (uncompressed) depending on the build profile. With gzip or Brotli compression, expect 80-120 KB transferred. The crate is designed with minimal dependencies to keep the WASM output small:

- No `git2` or heavy native dependencies
- Uses `ring` for Ed25519 (compiled to WASM) via `auths-crypto`
- `getrandom` configured with `wasm_js` feature for browser entropy

To check the exact size after building:

```bash
ls -lh packages/auths-verifier-ts/wasm/auths_verifier_bg.wasm
```

## Size limits

The WASM layer enforces the same input size limits as the native FFI:

| Limit | Value | Applies to |
|-------|-------|------------|
| `MAX_ATTESTATION_JSON_SIZE` | 64 KB | Single attestation JSON |
| `MAX_JSON_BATCH_SIZE` | 1 MB | Chain JSON arrays, witness receipts |

Inputs exceeding these limits are rejected with descriptive error messages before any cryptographic operations are attempted.

## Module formats

The `@auths/verifier` package ships with both ESM and CJS builds:

| Format | Entry point |
|--------|------------|
| ESM (`import`) | `dist/esm/index.js` |
| CJS (`require`) | `dist/cjs/index.js` |
| Types | `dist/types/index.d.ts` |
