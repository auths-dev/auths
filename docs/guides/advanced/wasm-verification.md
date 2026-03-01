# WASM Verification

The `auths-verifier` crate compiles to WebAssembly, enabling attestation and signature verification directly in browsers and edge runtimes. The WASM module is a thin wrapper around the same verification logic used by the native library -- no separate implementation, no feature gaps.

## Prerequisites

- Rust toolchain with the `wasm32-unknown-unknown` target
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) for building and packaging

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## Building with wasm-pack

The WASM feature must be built from inside the crate directory. The workspace resolver rejects `--features` passed from the workspace root.

```bash
cd crates/auths-verifier
wasm-pack build --target web --no-default-features --features wasm
```

This produces a `pkg/` directory containing:

- `auths_verifier_bg.wasm` -- the compiled WASM binary
- `auths_verifier.js` -- JavaScript glue code with async function wrappers
- `auths_verifier.d.ts` -- TypeScript type definitions
- `package.json` -- ready for npm publishing or local linking

### Build targets

| Target | Usage |
|--------|-------|
| `--target web` | Direct ESM import in browsers. Requires calling `init()` to load the WASM binary. |
| `--target bundler` | For webpack, Rollup, or other bundlers that handle WASM loading. |
| `--target nodejs` | For Node.js environments (uses `require()` style loading). |

## Feature flags

The `wasm` feature in `auths-verifier/Cargo.toml` enables:

- `wasm-bindgen` -- binds Rust functions to JavaScript
- `wasm-bindgen-futures` -- bridges Rust async to JavaScript Promises
- `getrandom/wasm_js` -- entropy source via Web Crypto API (`crypto.getRandomValues`)
- `getrandom_02/js` -- entropy for ring's transitive dependency on getrandom v0.2
- `auths-crypto/wasm` -- WebCrypto-backed cryptographic provider

The `native` feature (which pulls in `ring` for Ed25519) is excluded. In the WASM build, the `WebCryptoProvider` handles all signature verification through the browser's Web Crypto API.

## WASM API reference

All functions are async (they return JavaScript Promises). Public key and signature inputs are hex-encoded strings.

### verifyAttestationJson

Verifies a single attestation against an explicit issuer public key. Throws a JavaScript error string on failure.

```javascript
import init, { verifyAttestationJson } from './pkg/auths_verifier.js';

await init();

try {
  await verifyAttestationJson(attestationJsonString, issuerPublicKeyHex);
  console.log('Attestation is valid');
} catch (error) {
  console.error('Verification failed:', error);
}
```

**Parameters:**

- `attestation_json_str` (`string`) -- JSON-serialized attestation object. Maximum size: 64 KB.
- `issuer_pk_hex` (`string`) -- hex-encoded Ed25519 public key (32 bytes, 64 hex characters).

**Returns:** `Promise<void>` -- resolves on success, rejects with an error message on failure.

### verifyAttestationWithResult

Same verification as `verifyAttestationJson`, but returns a structured JSON result instead of throwing.

```javascript
import init, { verifyAttestationWithResult } from './pkg/auths_verifier.js';

await init();

const resultJson = await verifyAttestationWithResult(attestationJsonString, issuerPublicKeyHex);
const result = JSON.parse(resultJson);

if (result.valid) {
  console.log('Attestation verified');
} else {
  console.error('Verification failed:', result.error);
}
```

**Parameters:** Same as `verifyAttestationJson`.

**Returns:** `Promise<string>` -- JSON string with the structure:

```json
{
  "valid": true
}
```

Or on failure:

```json
{
  "valid": false,
  "error": "Invalid issuer public key hex: ..."
}
```

### verifyArtifactSignature

Verifies a detached Ed25519 signature over a file hash. All inputs are hex-encoded.

```javascript
import init, { verifyArtifactSignature } from './pkg/auths_verifier.js';

await init();

const isValid = await verifyArtifactSignature(fileHashHex, signatureHex, publicKeyHex);

if (isValid) {
  console.log('Artifact signature valid');
}
```

**Parameters:**

- `file_hash_hex` (`string`) -- hex-encoded hash of the file content.
- `signature_hex` (`string`) -- hex-encoded Ed25519 signature.
- `public_key_hex` (`string`) -- hex-encoded Ed25519 public key (32 bytes).

**Returns:** `Promise<boolean>` -- `true` if the signature is valid, `false` otherwise. Returns `false` (not an error) for malformed inputs.

### verifyChainJson

Verifies a chain of attestations and returns a full verification report.

```javascript
import init, { verifyChainJson } from './pkg/auths_verifier.js';

await init();

const reportJson = await verifyChainJson(attestationsJsonArray, rootPublicKeyHex);
const report = JSON.parse(reportJson);

if (report.status.type === 'Valid') {
  console.log('Chain verified, links:', report.chain.length);
} else {
  console.warn('Chain verification failed:', report.status);
}
```

**Parameters:**

- `attestations_json_array` (`string`) -- JSON array of attestation objects. Maximum size: 1 MB.
- `root_pk_hex` (`string`) -- hex-encoded root identity public key (32 bytes).

**Returns:** `Promise<string>` -- JSON string containing a `VerificationReport`:

```json
{
  "status": {"type": "Valid"},
  "chain": [
    {"issuer": "did:keri:...", "subject": "did:key:...", "valid": true},
    {"issuer": "did:key:...", "subject": "did:key:...", "valid": true}
  ],
  "warnings": []
}
```

Possible status types: `Valid`, `Expired`, `Revoked`, `InvalidSignature`, `BrokenChain`, `InsufficientWitnesses`.

### verifyChainWithWitnesses

Verifies an attestation chain with witness quorum checking.

```javascript
import init, { verifyChainWithWitnesses } from './pkg/auths_verifier.js';

await init();

const witnessKeys = JSON.stringify([
  { did: 'did:key:zWitness1...', pk_hex: 'aabb...' },
  { did: 'did:key:zWitness2...', pk_hex: 'ccdd...' }
]);

const receipts = JSON.stringify([
  { witness_did: 'did:key:zWitness1...', signature_hex: 'eeff...' , event_hash: '1122...'}
]);

const reportJson = await verifyChainWithWitnesses(
  chainJson,
  rootPublicKeyHex,
  receipts,
  witnessKeys,
  2  // threshold: require 2 witness signatures
);
const report = JSON.parse(reportJson);
```

**Parameters:**

- `chain_json` (`string`) -- JSON array of attestations. Maximum size: 1 MB.
- `root_pk_hex` (`string`) -- hex-encoded root public key.
- `receipts_json` (`string`) -- JSON array of witness receipts. Maximum size: 1 MB.
- `witness_keys_json` (`string`) -- JSON array of `{"did": "...", "pk_hex": "..."}` entries. Maximum size: 1 MB.
- `threshold` (`number`) -- minimum number of witness signatures required.

**Returns:** `Promise<string>` -- JSON `VerificationReport` with an additional `witness_quorum` field when witness verification is performed.

## Embedding in web applications

### Vanilla JavaScript (ESM)

```html
<script type="module">
  import init, {
    verifyAttestationJson,
    verifyChainJson
  } from './pkg/auths_verifier.js';

  async function verify() {
    await init();

    const response = await fetch('/api/attestation');
    const { attestation, issuer_pk } = await response.json();

    try {
      await verifyAttestationJson(
        JSON.stringify(attestation),
        issuer_pk
      );
      document.getElementById('status').textContent = 'Verified';
    } catch (e) {
      document.getElementById('status').textContent = `Failed: ${e}`;
    }
  }

  verify();
</script>
```

### With a bundler (webpack / Vite)

```javascript
// verification.js
import init, { verifyAttestationWithResult } from 'auths-verifier';

let initialized = false;

export async function verifyAttestation(attestationJson, issuerPkHex) {
  if (!initialized) {
    await init();
    initialized = true;
  }

  const resultJson = await verifyAttestationWithResult(attestationJson, issuerPkHex);
  return JSON.parse(resultJson);
}
```

For webpack, install the `@aspect-build/rules_js` or configure `experiments.asyncWebAssembly = true` in your webpack config. For Vite, WASM imports work out of the box with the `--target bundler` build.

### React component pattern

```jsx
import { useEffect, useState } from 'react';
import init, { verifyAttestationWithResult } from 'auths-verifier';

function AttestationBadge({ attestationJson, issuerPkHex }) {
  const [status, setStatus] = useState('loading');

  useEffect(() => {
    let cancelled = false;

    async function check() {
      await init();
      const resultJson = await verifyAttestationWithResult(attestationJson, issuerPkHex);
      const result = JSON.parse(resultJson);

      if (!cancelled) {
        setStatus(result.valid ? 'verified' : 'invalid');
      }
    }

    check().catch(() => {
      if (!cancelled) setStatus('error');
    });

    return () => { cancelled = true; };
  }, [attestationJson, issuerPkHex]);

  return <span className={`badge badge-${status}`}>{status}</span>;
}
```

## Bundle size considerations

The WASM binary size depends on optimization settings. Typical sizes:

| Configuration | Approximate size |
|---------------|-----------------|
| Debug build | 2-4 MB |
| Release build (`wasm-pack build`) | 300-600 KB |
| Release + `wasm-opt -Oz` | 200-400 KB |
| Gzipped release | 80-150 KB |

### Reducing bundle size

**Use release mode.** The default `wasm-pack build` uses release optimizations. For additional size reduction, add to `Cargo.toml`:

```toml
[profile.release]
opt-level = "z"      # Optimize for size
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization, slower compile
strip = true         # Strip debug symbols
```

**Run wasm-opt.** After building, apply Binaryen optimizations:

```bash
wasm-opt -Oz -o pkg/auths_verifier_bg_opt.wasm pkg/auths_verifier_bg.wasm
```

**Lazy load the module.** The WASM binary does not need to block initial page load. Load it on demand when verification is first needed:

```javascript
let verifier = null;

async function getVerifier() {
  if (!verifier) {
    const module = await import('./pkg/auths_verifier.js');
    await module.default();
    verifier = module;
  }
  return verifier;
}
```

**Use `--target bundler` with code splitting.** Modern bundlers can split the WASM binary into a separate chunk that loads asynchronously, keeping the critical rendering path fast.

## Verifying the WASM build compiles

Before a full `wasm-pack build`, you can do a quick compilation check:

```bash
cd crates/auths-verifier
cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

This catches type errors and missing feature gates without the overhead of wasm-pack packaging.

## Input size limits

The WASM bindings enforce the same size limits as the native library to prevent memory exhaustion in the browser:

| Input | Maximum size |
|-------|-------------|
| Single attestation JSON | 64 KB |
| Attestation chain JSON array | 1 MB |
| Witness receipts JSON | 1 MB |
| Witness keys JSON | 1 MB |

Exceeding these limits returns an error before any parsing or verification occurs.
