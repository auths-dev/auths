# TransparencyLog Port Trait Design

## 1. Trait Shape

The `TransparencyLog` trait abstracts the operation of appending data to a transparency log and retrieving proofs. It lives in `auths-core/src/ports/transparency_log.rs` and uses `#[async_trait]` for object safety (`Arc<dyn TransparencyLog>`).

```rust
#[async_trait]
pub trait TransparencyLog: Send + Sync {
    /// Submit a leaf to the log and receive an inclusion proof.
    ///
    /// The adapter is responsible for wrapping `leaf_data` in whatever
    /// envelope the backend requires (DSSE, hashedrekord, raw append).
    /// `public_key` and `signature` are provided for backends that
    /// verify entry signatures on submission (e.g., Rekor).
    async fn submit(
        &self,
        leaf_data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<LogSubmission, LogError>;

    /// Fetch the log's current signed checkpoint.
    async fn get_checkpoint(&self) -> Result<SignedCheckpoint, LogError>;

    /// Fetch an inclusion proof for a leaf at `leaf_index` in a tree of `tree_size`.
    async fn get_inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, LogError>;

    /// Fetch a consistency proof between two tree sizes.
    async fn get_consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, LogError>;

    /// Return metadata about this log (ID, origin, public key).
    fn metadata(&self) -> LogMetadata;
}
```

**Why each method exists:**

- `submit()` — The core write operation. Every log must accept a leaf and return a proof that it was included. The return includes the inclusion proof and checkpoint at the time of inclusion, so the caller can immediately verify and embed in a bundle.
- `get_checkpoint()` — Allows verification clients to fetch the current tree state without submitting. Used for checkpoint caching and freshness checks.
- `get_inclusion_proof()` — Re-fetch a proof for a previously-logged leaf. Used when a client has a stale checkpoint and needs to verify against the current tree.
- `get_consistency_proof()` — Proves that a smaller tree is a prefix of a larger tree. Used for checkpoint cache updates: "I cached tree-size-100, now I see tree-size-200, prove they're consistent."
- `metadata()` — Sync because it's static configuration. Returns the log's stable ID, origin string, and public key for trust root registration.

**Result types:**

```rust
pub struct LogSubmission {
    pub leaf_index: u64,
    pub inclusion_proof: InclusionProof,
    pub signed_checkpoint: SignedCheckpoint,
}

pub struct LogMetadata {
    pub log_id: String,
    pub log_origin: LogOrigin,
    pub log_public_key: Ed25519PublicKey,
    pub api_url: Option<String>,
}
```

All types from `auths-transparency` (`InclusionProof`, `SignedCheckpoint`, `ConsistencyProof`, `LogOrigin`) and `auths-verifier` (`Ed25519PublicKey`). No parallel types.

## 2. Backend Matrix

| Backend | `submit()` | `get_checkpoint()` | `get_inclusion_proof()` | `get_consistency_proof()` | Notes |
|---|---|---|---|---|---|
| **Rekor public** | POST `/api/v1/log/entries` hashedrekord | GET `/api/v1/log` signed tree head | From v1 entry response `verification.inclusionProof` | GET `/api/v1/log/proof` | Uses ECDSA P-256 checkpoint sig (production shard) |
| **Rekor self-hosted** | Same API, different `api_url` | Same | Same | Same | User supplies key + origin |
| **Sunlight (future)** | POST to sunlight write endpoint | Fetch `/checkpoint` tile | Compute from tiles | Compute from tiles | Pure tlog-tiles, Ed25519 |
| **Native (future)** | Direct Merkle tree append | Local state or file | Local computation | Local computation | No network; self-hosted log |
| **None / Noop** | Returns `LogError::Unavailable` | Returns `LogError::Unavailable` | Returns `LogError::Unavailable` | Returns `LogError::Unavailable` | For `--allow-unlogged` and `auths demo` |

## 3. Legitimate Backend Differences

**Leaf format:** Rekor requires a `hashedrekord` or `dsse` envelope wrapping the raw data. Sunlight and native logs may accept raw bytes. The trait takes raw `leaf_data` + `public_key` + `signature` — each adapter wraps these into its backend-specific envelope at the adapter boundary. The core never sees envelope formats.

**Rate limits:** Rekor rate-limits by IP (HTTP 429 with `Retry-After`). Other backends may not. The trait surfaces `LogError::RateLimited { retry_after_secs }` and the caller (CLI) decides the retry policy. The SDK does not retry.

**Witness models:** Witnesses are checkpoint properties, not log operations. They appear as cosignatures on `SignedCheckpoint`. The trait does not include witness methods — the verifier handles witnesses through existing `auths-transparency` code.

**Checkpoint signature algorithm:** Rekor's production shard uses ECDSA P-256; the 2025 shard uses Ed25519. The trait returns `SignedCheckpoint` which carries the signature; the verifier checks it against the trust config's public key. Algorithm differences are handled at verification time, not in the trait.

## 4. Error Taxonomy

```rust
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// The log rejected the submitted entry (malformed, too large, policy violation).
    #[error("submission rejected: {reason}")]
    SubmissionRejected { reason: String },

    /// Network or connection error reaching the log.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Log returned HTTP 429; caller should wait and retry.
    #[error("rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Log returned an unparseable or unexpected response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Requested entry not found in the log.
    #[error("entry not found")]
    EntryNotFound,

    /// Consistency or inclusion proof verification failed.
    #[error("consistency violation: {0}")]
    ConsistencyViolation(String),

    /// Log is temporarily or permanently unavailable (HTTP 500/503, noop backend).
    #[error("log unavailable: {0}")]
    Unavailable(String),
}
```

**Rekor HTTP code mapping:**

| HTTP Status | `LogError` Variant |
|---|---|
| 201 Created | Success |
| 409 Conflict | Idempotent success: fetch existing entry, return `LogSubmission` |
| 400 Bad Request | `SubmissionRejected { reason }` |
| 413 Payload Too Large | `SubmissionRejected { reason: "payload too large" }` |
| 422 Unprocessable Entity | `SubmissionRejected { reason }` |
| 429 Too Many Requests | `RateLimited { retry_after_secs }` (parse `Retry-After` header) |
| 500 Internal Server Error | `Unavailable("server error")` |
| 503 Service Unavailable | `Unavailable("service unavailable")` |
| Connection refused / timeout | `NetworkError(details)` |

**`AuthsErrorInfo` codes:** `AUTHS-E9001` through `AUTHS-E9007` (one per variant). The E40xx-E49xx ranges are taken by existing crates.

## 5. Ed25519 vs DSSE Decision

**Decision: Use `hashedrekord` with the existing pure Ed25519 signature on the Rekor v1 API.**

**Rationale:**

The earlier concern about Ed25519 incompatibility with `hashedrekord` was based on the assumption that Rekor must verify the signature against a hash. Investigation reveals:

1. Rekor v1.3.6+ accepts `PKIX_ED25519` in hashedrekord entries. The server stores the entry without requiring prehash verification for Ed25519 — it validates the key format and signature structure, not the signature-over-hash binding.
2. The `dsse` entry type would require wrapping the attestation in a DSSE envelope, adding complexity for no security benefit — the attestation is already signed.
3. `hashedrekord` is the dominant entry type (>99% of Rekor entries) with the most stable API surface.

The adapter submits:
- `spec.data.hash.algorithm`: `"sha256"`
- `spec.data.hash.value`: hex SHA-256 of the attestation JSON
- `spec.signature.content`: base64 of the attestation's `identity_signature`
- `spec.signature.publicKey.content`: base64 of the issuer's Ed25519 public key in PKIX DER format

**Mandatory pre-implementation validation:** Before writing any adapter code beyond a minimal submission function, submit one test entry to production Rekor with a throwaway key and verify it using the official `rekor-cli verify` tool. If `rekor-cli verify` fails or returns warnings, switch to `dsse` entry type and re-test. This is a one-hour validation that de-risks the entire adapter. See fn-111.5 task spec.

**Fallback:** If testing reveals that Rekor rejects pure Ed25519 hashedrekord entries on the production instance or they cannot be verified by standard tooling, switch to `dsse`. The adapter boundary isolates this decision — no core code changes needed.

### Sigstore Compatibility Validation

The Rekor adapter wraps raw public keys in SPKI DER before submission (see `wrap_pubkey_in_spki_der` in `auths-infra-rekor/src/client.rs`). This makes entries verifiable by standard Sigstore tooling. No Fulcio or OIDC is needed — auths bootstraps its own identity model onto Sigstore's public log.

**Manual validation steps (run once before launch):**

```bash
# 1. Install Sigstore CLI tools
go install github.com/sigstore/rekor/cmd/rekor-cli@latest
go install github.com/sigstore/cosign/cmd/cosign@latest

# 2. Create a P-256 identity and sign an artifact
cargo install --path crates/auths-cli
auths init
echo "test artifact" > /tmp/test-artifact.txt
auths artifact sign --log sigstore-rekor /tmp/test-artifact.txt

# 3. Note the log index from the output (e.g. "Logged at index 12345678")

# 4. Verify the entry exists in Rekor
rekor-cli get --log-index <INDEX> --rekor_server https://rekor.sigstore.dev

rekor-cli get --log-index 1271709852 --rekor_server https://rekor.sigstore.dev

# 5. Verify the entry is well-formed (public key parses, signature structure valid)
rekor-cli get --log-index 1271709852 --rekor_server https://rekor.sigstore.dev --format json | jq .

# 6. Search by public key (confirms key format is recognized)
# Export the device public key in PEM:
auths key export --key-alias main --passphrase 'Seamus4444$!' --format pem | openssl ec -pubin -outform DER | base64

# Then:
rekor-cli search --public-key <base64-der-key> --rekor_server https://rekor.sigstore.dev
```

**What "success" looks like:**
- Step 4 returns the entry without errors
- Step 5 shows `hashedrekord` with `spec.signature.publicKey.content` that decodes to valid SPKI DER
- Step 6 returns the entry's UUID (proves Rekor indexed the key correctly)

**What "failure" looks like and what to do:**
- Step 4 returns 404 → submission didn't land; check `auths artifact sign --log` output for errors
- Step 5 shows the entry but key is raw bytes (not DER) → `wrap_pubkey_in_spki_der` isn't being called; check the adapter code path
- Step 6 returns empty → Rekor couldn't index the key format; switch to `dsse` entry type per the fallback plan above

## 6. Rekor API Version Commitment

**Decision: Target Rekor v1 API for entry submission.**

**Rationale:**

Production investigation revealed:
- `rekor.sigstore.dev` serves the **v1 API** (`/api/v1/log/entries` returns 422, `/api/v2/log/entries` returns 404)
- `log2025-1.rekor.sigstore.dev` is a **tlog-tiles read-only shard** (static S3 bucket serving tiles and checkpoints, no write API)
- Rekor v2 (rekor-tiles write endpoint) is not deployed on the production instance as of 2026-04-09

**Endpoints used:**

| Operation | Endpoint | Method |
|---|---|---|
| Submit entry | `{api_url}/api/v1/log/entries` | POST |
| Get log info | `{api_url}/api/v1/log` | GET |
| Get entry by UUID | `{api_url}/api/v1/log/entries/{uuid}` | GET |
| Get consistency proof | `{api_url}/api/v1/log/proof?firstSize={m}&lastSize={n}` | GET |
| Get checkpoint (tlog-tiles) | `{tiles_url}/checkpoint` | GET |

**v1 response shape for POST `/api/v1/log/entries`:**
```json
{
  "<uuid>": {
    "body": "<base64 canonicalized entry>",
    "integratedTime": 1712678400,
    "logID": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
    "logIndex": 12345678,
    "verification": {
      "inclusionProof": {
        "checkpoint": "rekor.sigstore.dev - 1193050959916656506\n...",
        "hashes": ["abcd...", "ef01..."],
        "logIndex": 12345678,
        "rootHash": "1107f839...",
        "treeSize": 1141633759
      },
      "signedEntryTimestamp": "<base64 SET>"
    }
  }
}
```

**When Rekor v2 lands on production:** Switch the adapter to v2 endpoints. Pre-launch, zero users — no backward compatibility concerns.

## 7. Bundle Format

The `.auths.json` attestation gains an optional `transparency` section:

```json
{
  "version": 1,
  "rid": "sha256:abcdef...",
  "issuer": "did:key:z6MkrTQ...",
  "subject": "did:key:z6MkrTQ...",
  "device_public_key": "abcdef...",
  "identity_signature": "base64...",
  "device_signature": "base64...",
  "capabilities": ["sign_release"],
  "signer_type": "workload",
  "commit_sha": "abc123def456...",
  "payload": {
    "artifact_type": "file",
    "digest": { "algorithm": "sha256", "hex": "abcdef..." },
    "name": "release.tar.gz",
    "size": 12345678
  },
  "transparency": {
    "log_id": "sigstore-rekor",
    "leaf_index": 12345678,
    "inclusion_proof": {
      "index": 12345678,
      "size": 1141633759,
      "root": "<base64 32-byte hash>",
      "hashes": ["<base64>", "<base64>"]
    },
    "signed_checkpoint": {
      "checkpoint": {
        "origin": "rekor.sigstore.dev - 1193050959916656506",
        "size": 1141633759,
        "root": "<base64 32-byte hash>",
        "timestamp": "2026-04-09T12:00:00Z"
      },
      "log_signature": "<base64 64-byte sig>",
      "log_public_key": "<base64 32-byte key>",
      "witnesses": []
    }
  }
}
```

**When `transparency` is present:** Verifier looks up `log_id` in `TrustConfig`, verifies inclusion proof and checkpoint signature.

**When `transparency` is absent:** Verifier treats the attestation as unlogged. Rejected by default; accepted only with `--allow-unlogged`.

**Old `offline_bundle` format:** Unsupported and removed. Pre-launch, zero users. No migration path. Document in launch notes.

## 8. Trust Config Changes

`TrustRoot` (existing, kept as-is) becomes the per-log entry. New `TrustConfig` wraps multiple logs:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    pub default_log: Option<String>,
    pub logs: HashMap<String, TrustRoot>,
}
```

**JSON format (`~/.auths/trust_config.json`):**

```json
{
  "default_log": "sigstore-rekor",
  "logs": {
    "sigstore-rekor": {
      "log_public_key": "<hex 32 bytes>",
      "log_origin": "rekor.sigstore.dev - 1193050959916656506",
      "witnesses": []
    }
  }
}
```

**Edge case behaviors:**

| Scenario | Behavior |
|---|---|
| File doesn't exist (first run) | Use compiled-in defaults. Do NOT create file. |
| File exists but malformed JSON | Hard fail with parse error. No fallback to defaults. |
| `default_log` references a log ID not in `logs` | Hard fail at load time via `TrustConfig::validate()`. Not a silent `None` at lookup. |
| User overrides a compiled-in log's trust material | User config wins. Print warning: `"Note: trust material for 'sigstore-rekor' overridden by ~/.auths/trust_config.json"` |
| `auths trust log add` with no existing file | Create `~/.auths/` if missing (fail if not writable). Write file with ALL compiled-in defaults plus new entry. |

**`TrustConfig::validate()`** is called at load time and checks that `default_log` (if `Some`) references a key in `logs`. Returns `Err(TransparencyError)` on misconfiguration.

## 9. Dependency Graph

Verified via `cargo tree`:

```
auths-core → auths-crypto, auths-verifier, auths-keri, auths-pairing-protocol
auths-transparency → auths-crypto, auths-verifier
```

Neither depends on the other. Adding `auths-core → auths-transparency` introduces no cycle.

The `TransparencyLog` trait in `auths-core` uses types from `auths-transparency` (`InclusionProof`, `SignedCheckpoint`, `ConsistencyProof`, `LogOrigin`) and from `auths-verifier` (`Ed25519PublicKey`). Both are already `auths-core` dependencies (auths-verifier directly, auths-transparency will be added).

## 10. Async Boundary

**Decision: Follow the established per-command `Runtime::new().block_on()` pattern.**

**Rationale:**

The CLI entry point (`main.rs:11`) is `fn main()` — synchronous, not `#[tokio::main]`. Every command that needs async creates `tokio::runtime::Runtime::new()?` and calls `rt.block_on(...)`. This pattern is used in 15+ places across the CLI (`verify_commit.rs:928`, `id/claim.rs:109`, `id/register.rs:39`, `scim.rs:236`, `utils.rs:116`).

Making the signing path async end-to-end would require either adding `#[tokio::main]` to `main.rs` (changing every command's execution model) or converting all `ExecutableCommand::execute()` impls to async (a large refactor touching every command). Pre-launch, the per-command runtime pattern works and is understood.

**Note:** `artifact sign --ci` is fully sync today — it does no async work. Adding transparency log submission introduces the first async call in this code path. Each `Runtime::new()` spins up the reactor, creates worker threads, and tears them down — measurable overhead (~10-50ms) for a single network call.

**Implementation:** The `artifact sign --ci` handler creates a `Runtime` via `once_cell::sync::Lazy<Runtime>` (lazy global, created once per process, reused across all commands that need async). This eliminates both the per-call overhead and the nested-runtime risk (if the CLI is ever called from within an async context). The lazy runtime is defined in the CLI factory and used by all command handlers that need `block_on()`.

**Escape hatch:** If the lazy global causes issues (test isolation, thread-local state), fall back to per-command `Runtime::new()`. This is a localized change in the factory and does not affect the trait or adapter code.

**Future improvement:** When the CLI moves to `#[tokio::main]` (a separate refactor), the lazy global and all `block_on()` calls can be removed.

## 11. Security: GHSA-whqx-f9j3-ch6m

**Background:** [GHSA-whqx-f9j3-ch6m](https://github.com/sigstore/cosign/security/advisories/GHSA-whqx-f9j3-ch6m) was a vulnerability in Cosign where the client accepted any valid Rekor entry without confirming it matched the artifact being verified. An attacker could substitute a valid-but-unrelated Rekor entry during verification.

**Countermeasure:** The SDK function `submit_attestation_to_log()` verifies the Rekor response before returning. Three explicit checks, each a distinct security property:

1. **Hash check:** Compute `SHA-256(leaf_data)` client-side (where `leaf_data` is the canonicalized attestation JSON bytes — the same bytes over which the Ed25519 signature was computed). Compare against the entry's `spec.data.hash.value` from the Rekor response. Must match. This proves Rekor stored the correct hash for the submitted content.
2. **Public key check:** Compare the entry's `spec.signature.publicKey.content` against the submitted `public_key` (base64 of the PKIX DER). Must match. This proves the entry is attributed to the correct signer.
3. **Signature check:** Compare the entry's `spec.signature.content` against the submitted `signature` (base64 of the Ed25519 signature). Must match. This is the core security property — if Rekor returned a different signature than what was submitted, either Rekor is buggy or an attacker is substituting entries.

If any check fails, return `LogError::ConsistencyViolation("returned entry does not match submitted data: {which_field} mismatch")`.

**Where in the call graph:** This check lives in `submit_attestation_to_log()` in `auths-sdk/src/workflows/log_submit.rs`, immediately after the `log.submit()` call returns and before the `LogSubmissionBundle` is constructed. The check is a precondition of the function returning `Ok` — callers cannot accidentally skip it.

**Regression guard:** fn-111.6 includes a dedicated test that mocks a content-mismatched response and asserts the check catches it.

## 12. Retry Policy

**SDK layer (`submit_attestation_to_log()`):** Does NOT retry. Returns `LogError::RateLimited { retry_after_secs }` to the caller. The SDK is a library — retry policy is a composition-root decision.

**CLI layer (artifact sign handler):**

```
On LogError::RateLimited { retry_after_secs }:
  1. Print: "Rate limited by transparency log. Retrying in {retry_after_secs}s..."
  2. Sleep retry_after_secs
  3. Retry once
  4. On second RateLimited: fail with exit code 4

On any other LogError:
  Fail immediately with appropriate exit code
```

## 13. Rekor as Trust Dependency

v1 default configuration depends on Sigstore's production Rekor instance (`rekor.sigstore.dev`). Users accepting this default are accepting Sigstore's operational security and Linux Foundation's governance of Rekor. This is a deliberate choice to leverage shared public-good infrastructure rather than build and operate a parallel log. Users who cannot accept this dependency should run a private Rekor, wait for the native log operator, or use --allow-unlogged for isolated environments.

## 14. Rekor Origin Strings

Fetched from production endpoints on 2026-04-09:

**Production shard (active):**
- Origin: `rekor.sigstore.dev - 1193050959916656506`
- Source: `GET https://rekor.sigstore.dev/api/v1/log` → `signedTreeHead` field, first line
- Checkpoint signature: ECDSA P-256

**2025 read shard:**
- Origin: `log2025-1.rekor.sigstore.dev`
- Source: `GET https://log2025-1.rekor.sigstore.dev/checkpoint`, first line
- Checkpoint signature: Ed25519

**For v1 adapter:** Entries are submitted to `rekor.sigstore.dev` (production shard, v1 API). The inclusion proof in the response references the production shard's checkpoint with origin `rekor.sigstore.dev - 1193050959916656506`.

**Compiled-in default trust config uses:**
- Log ID: `"sigstore-rekor"`
- Origin: `"rekor.sigstore.dev - 1193050959916656506"`
- Public key: The production shard's ECDSA P-256 key (`wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=` is the log ID / key hash; the actual DER public key is `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==`)

**ECDSA P-256 for checkpoint signatures:** The production shard uses ECDSA P-256, not Ed25519. Adding ECDSA P-256 verification to `auths-verifier` is required for v1 (see Section 16). `ring` already supports P-256 (`ring::signature::ECDSA_P256_SHA256_ASN1`). A dedicated task (fn-111.2b) adds this before the Rekor adapter is built.

**Rekor v2 migration:** Pre-launch, zero users. When Rekor v2 write API becomes available on production, switch the adapter to v2 endpoints. No backward compatibility concerns — just replace the adapter implementation.

## 15. CLI Error Taxonomy

| Exit Code | Meaning | When |
|---|---|---|
| 0 | Success | Sign/verify completed |
| 1 | Verification failed | Bundle invalid, signature mismatch, proof failed |
| 2 | General error | Parse error, I/O error, unexpected failure |
| 3 | Network error | Log unreachable, connection refused, DNS failure |
| 4 | Rate limited | Retry exhausted after one attempt |
| 5 | Submission rejected | Entry malformed, payload too large, policy violation |
| 6 | Unknown log ID | `log_id` not in trust config, setup needed |

Each exit code produces a distinct stderr message. Scripts can `case $?` on these codes.

## 16. ECDSA P-256 Support in auths-verifier

**Decision: Add ECDSA P-256 signature verification to `auths-verifier` as part of this epic.** This is required for verifying Rekor production checkpoint signatures. Cryptographic verification of checkpoint signatures is not optional — shipping a transparency log integration without it would be incomplete.

**Implementation approach:**

The `auths-verifier` crate currently uses `Ed25519PublicKey` and `Ed25519Signature` types throughout. Adding ECDSA P-256 requires:

1. A `SignatureAlgorithm` enum: `Ed25519`, `EcdsaP256` — configurable per-log in the trust config
2. An `EcdsaP256PublicKey` newtype wrapping the DER-encoded PKIX key
3. An `EcdsaP256Signature` newtype wrapping the ASN.1 DER signature
4. A `verify_checkpoint_signature()` function that dispatches on algorithm
5. Updates to `SignedCheckpoint` verification to accept either algorithm

**Scope:** Only checkpoint signature verification needs ECDSA P-256. Attestation signatures remain Ed25519. The ECDSA support is narrowly scoped to the transparency log verification path.

**ring support:** `ring::signature::ECDSA_P256_SHA256_ASN1` already exists. The DER public key from Rekor's trust root (`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+...`) is a standard PKIX SubjectPublicKeyInfo — `ring::signature::UnparsedPublicKey` can consume it directly.

**Configurability:** The trust config's `TrustRoot` gains an optional `signature_algorithm` field (defaults to `Ed25519` for backward compatibility). The Rekor production shard entry specifies `EcdsaP256`. When verifying a checkpoint, the verifier looks up the algorithm from the trust config.

**Task:** fn-111.2b "Add ECDSA P-256 support to auths-verifier" — placed between fn-111.2 (port trait) and fn-111.5 (Rekor adapter).
