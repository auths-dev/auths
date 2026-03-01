# Competitive Roadmap: Eight Questions an Acquirer Will Ask

This document identifies exactly what an acquirer's security team will probe during due diligence, maps each question to the current state of the codebase, and specifies the gap — if any — with implementation plan, code, and tests.

---

## Question 1: Is the cryptographic core correct?

### Current State

`verify_kel` in `crates/auths-verifier/src/keri.rs` correctly verifies:

- Ed25519 signatures at every event type (inception self-signed with declared key, rotation signed by new key proving pre-rotation commitment, interaction signed by current key)
- SAID integrity via Blake3 hash (`verify_event_said`, line 337)
- Chain linkage via previous-SAID comparison (lines 243-250, 285-292)
- Sequence ordering via enumeration index (lines 235-240, 277-282)
- Pre-rotation commitment verification via Blake3 hash of public key (lines 258-265, 387-396)
- Canonical serialization before signing prevents signature malleability (`serialize_for_signing`)

All error paths return typed `KeriVerifyError` variants with `thiserror`. No `unwrap()` in production verification paths except the sequence parser.

### Gap

**`KeriEvent::sequence()` silently coerces malformed sequence numbers to 0.**

File: `crates/auths-verifier/src/keri.rs`, line 78:
```rust
s.parse().unwrap_or(0)
```

File: `crates/auths-verifier/src/keri.rs`, line 420:
```rust
return Some(ixn.s.parse().unwrap_or(0));
```

A malformed sequence field (e.g. `"abc"`, `"0x01"`, `"-1"`) becomes 0 instead of returning `KeriVerifyError::InvalidSequence`. The current comparison logic (`actual_seq != expected_seq`) rejects most corruption by accident, but this violates fail-fast principles on untrusted input in a security-critical path.

### Implementation Plan

**File:** `crates/auths-verifier/src/keri.rs`

1. Change `KeriEvent::sequence()` return type from `u64` to `Result<u64, KeriVerifyError>`.
2. Propagate the error with a new variant or reuse `InvalidSequence` with sentinel values.
3. Update all call sites in `verify_kel` to use `?`.
4. Fix `find_seal_in_kel` to return `Result<Option<u64>, KeriVerifyError>` or filter with `.ok()`.

**Function signatures after fix:**

```rust
impl KeriEvent {
    pub fn sequence(&self) -> Result<u64, KeriVerifyError> {
        let s = match self {
            KeriEvent::Inception(e) => &e.s,
            KeriEvent::Rotation(e) => &e.s,
            KeriEvent::Interaction(e) => &e.s,
        };
        s.parse::<u64>().map_err(|_| KeriVerifyError::InvalidSequence {
            expected: 0,
            actual: 0,
        })
    }
}
```

Note: A more precise approach would add a `KeriVerifyError::MalformedSequence { raw: String }` variant to preserve the unparseable value for diagnostics.

**Call site changes in `verify_kel`:**

Every `event.sequence()` becomes `event.sequence()?`. The function already returns `Result<KeriKeyState, KeriVerifyError>`, so propagation is mechanical.

**`find_seal_in_kel` change:**

```rust
pub fn find_seal_in_kel(events: &[KeriEvent], digest: &str) -> Option<u64> {
    for event in events {
        if let KeriEvent::Interaction(ixn) = event {
            for seal in &ixn.a {
                if seal.d == digest {
                    return ixn.s.parse::<u64>().ok();
                }
            }
        }
    }
    None
}
```

### Tests

**File:** `crates/auths-verifier/src/keri.rs` (append to existing test module)

```rust
#[test]
fn rejects_malformed_sequence_number() {
    let mut events = valid_inception_and_rotation(); // helper from existing tests
    // Corrupt the rotation event's sequence field
    if let KeriEvent::Rotation(ref mut rot) = events[1] {
        rot.s = "not_a_number".to_string();
    }
    let result = verify_kel(&events);
    assert!(matches!(result, Err(KeriVerifyError::InvalidSequence { .. }))
        || matches!(result, Err(KeriVerifyError::MalformedSequence { .. })));
}

#[test]
fn rejects_negative_sequence_number() {
    let mut events = valid_inception_and_rotation();
    if let KeriEvent::Rotation(ref mut rot) = events[1] {
        rot.s = "-1".to_string();
    }
    let result = verify_kel(&events);
    assert!(result.is_err());
}

#[test]
fn rejects_hex_sequence_number() {
    let mut events = valid_inception_and_rotation();
    if let KeriEvent::Rotation(ref mut rot) = events[1] {
        rot.s = "0x01".to_string();
    }
    let result = verify_kel(&events);
    assert!(result.is_err());
}
```

---

## Question 2: Does the witness network actually exist?

### Current State

The witness infrastructure is substantially implemented (~75% complete, 2,831 lines across 11 files in `crates/auths-core/src/witness/`):

- **`AsyncWitnessProvider` trait** (`async_provider.rs`, lines 52-157): Full definition with `submit_event`, `observe_identity_head`, `get_receipt`, `quorum`, `timeout_ms`, `is_available`.
- **`NoOpAsyncWitness`** (`async_provider.rs`, lines 159-202): No-op implementation for testing.
- **`WitnessServerState` + HTTP server** (`server.rs`, 485 lines): Axum-based server with endpoints:
  - `POST /witness/{prefix}/event` — submit event for witnessing
  - `GET /witness/{prefix}/head` — get latest observed sequence
  - `GET /witness/{prefix}/receipt/{said}` — retrieve issued receipt
  - `GET /health` — health check
- **`ReceiptCollector`** (`collector.rs`, 391 lines): Parallel k-of-n receipt collection with timeout enforcement and duplicity detection during collection.
- **`WitnessStorage`** (`storage.rs`, 352 lines): SQLite-based persistence with `first_seen` and `receipts` tables.
- **`DuplicityDetector`** (`duplicity.rs`, 355 lines): First-seen-always-seen policy enforcement. Returns `DuplicityEvidence` with witness reports when same (prefix, sequence) arrives with different SAID.
- **`Receipt`** type (`receipt.rs`, 288 lines): Full KERI receipt format with Ed25519 signing/verification.
- **`WitnessError`** enum (`error.rs`, 173 lines): Covers `Network`, `Duplicity`, `Rejected`, `Timeout`, `InvalidSignature`, `InsufficientReceipts`, `SaidMismatch`, `Storage`, `Serialization`.
- **`EventReceipts`** in `auths-id` (`crates/auths-id/src/keri/event.rs`): Stores receipts linked to event SAID with threshold checking.
- **Feature flag** `witness-server` in `crates/auths-core/Cargo.toml` gates server and storage modules.

### Gap

**`HttpWitnessClient` does not exist.** The trait `AsyncWitnessProvider` is defined, the server is implemented, but no HTTP client connects to it. The only concrete implementation is `NoOpAsyncWitness`. The `HttpWitness` in `async_provider.rs` lines 16-44 is a doc comment with `todo!()`.

This is the gap that most directly differentiates Auths from Sigstore. Until `HttpWitnessClient` exists and the `auths id create` command submits to witnesses before returning, the KERI security claim is theoretical — it's the difference between "we have the parts" and "the system actually works as described." The end-to-end flow is currently untestable.

Additionally:
- No `auths witness serve` CLI command wraps the existing server
- No integration of witness receipt collection into `auths id rotate`

### Implementation Plan

**1. HttpWitnessClient** — `crates/auths-core/src/witness/http_client.rs`

```rust
use reqwest::Client;
use async_trait::async_trait;
use crate::witness::{
    AsyncWitnessProvider, Receipt, WitnessError, EventHash,
};

pub struct HttpWitnessClient {
    base_url: String,
    client: Client,
    timeout: std::time::Duration,
    witness_id: String,
    quorum_size: usize,
}

impl HttpWitnessClient {
    pub fn new(base_url: impl Into<String>, quorum: usize) -> Self;
    pub fn with_timeout(self, timeout: std::time::Duration) -> Self;
}

#[async_trait]
impl AsyncWitnessProvider for HttpWitnessClient {
    async fn submit_event(&self, prefix: &str, event_json: &[u8])
        -> Result<Receipt, WitnessError>;
    async fn observe_identity_head(&self, prefix: &str)
        -> Result<Option<EventHash>, WitnessError>;
    async fn get_receipt(&self, prefix: &str, event_said: &str)
        -> Result<Option<Receipt>, WitnessError>;
    fn quorum(&self) -> usize;
    fn timeout_ms(&self) -> u64;
    async fn is_available(&self) -> Result<bool, WitnessError>;
}
```

**2. CLI command** — `crates/auths-cli/src/commands/witness.rs`

```rust
#[derive(Subcommand, Debug)]
pub enum WitnessSubcommand {
    /// Start a witness server
    Serve {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: SocketAddr,
        #[arg(long)]
        witness_key_alias: Option<String>,
        #[arg(long, default_value = "witness.db")]
        db_path: PathBuf,
    },
}
```

**3. Integration into rotation** — Update `crates/auths-id/src/keri/rotation.rs` to accept optional `Vec<Arc<dyn AsyncWitnessProvider>>` and call `ReceiptCollector::collect()` after appending the rotation event.

### Tests

**File:** `crates/auths-core/tests/witness_integration.rs`

```rust
#[tokio::test]
async fn http_witness_submit_and_retrieve_receipt() {
    // Start witness server on random port
    // Create HttpWitnessClient pointed at server
    // Submit an inception event
    // Verify receipt is returned and signature is valid
    // Retrieve receipt by SAID
    // Verify retrieved receipt matches
}

#[tokio::test]
async fn http_witness_detects_duplicity() {
    // Start witness server
    // Submit event A at (prefix, seq=1, said=X)
    // Submit event B at (prefix, seq=1, said=Y)
    // Verify second submission returns WitnessError::Duplicity
    // Verify DuplicityEvidence contains both SAIDs
}

#[tokio::test]
async fn receipt_collector_reaches_quorum() {
    // Start 3 witness servers
    // Create ReceiptCollector with quorum=2
    // Submit event to collector
    // Verify at least 2 receipts returned
}
```

---

## Question 3: Is there a threat model?

### Current State

**A comprehensive threat model exists at `docs/notes/THREAT_MODEL.md` (374 lines).** It covers:

- **Assets protected:** Attestation integrity, identity binding, capability authorization, chain validity, temporal validity
- **Threat actors:** Malicious contributor, compromised CI, stolen device, network attacker, supply chain attacker, insider threat
- **8 attack vectors with mitigations and residual risk:**
  1. Signature bypass (Low — Ed25519/ring)
  2. Capability escalation (Low — cryptographic binding)
  3. Timestamp attacks (Medium — clock skew tolerance)
  4. FFI buffer overflow (Medium — caller responsible)
  5. JSON parsing DoS (Medium — no size limits)
  6. DID parsing attacks (Low — explicit validation)
  7. Chain linkage attacks (Low — explicit validation)
  8. Revocation bypass (Medium — boolean-only revocation)
- **Known limitations:** Boolean revocation, no rate limiting, no size limits, clock dependency
- **Security recommendations for integrators:** 9 practices
- **Dependency analysis:** ring, serde_json, bs58, chrono, json-canon audit status
- **Audit checklist** for reviewers
- **KEL State Cache** design and threat scenarios

Additional security documentation:
- `docs/contributing/security-notes.md` — Key handling practices, unsafe code restrictions, canonical JSON policy, dependency policy, vulnerability reporting
- `docs/concepts/key-rotation.md` — Pre-rotation security properties explained in adversarial terms
- `docs/examples/failure-modes.md` — Recovery procedures for expired attestations, revoked attestations, invalid signatures, broken chains

### Gap

**The `InMemorySessionStore` in `crates/auths-auth-server/src/adapters/memory_store.rs` is not explicitly called out in the threat model as a production limitation.** The auth server uses `InMemorySessionStore` (line 66 of `main.rs`), which is a `RwLock<HashMap<Uuid, AuthSession>>`. Sessions are lost on restart and are unbounded in memory.

### Implementation Plan

Append the following sections to `docs/notes/THREAT_MODEL.md`:

```markdown
### 6.4 Registry Append Path

The registry append path calls `validate_kel()` before accepting any event — forged
signatures, invalid pre-rotation commitments, and broken chains are rejected at the API
boundary.

### 6.5 Auth Server Session Storage

The `InMemorySessionStore` (`crates/auths-auth-server/src/adapters/memory_store.rs`) is
appropriate for development and demonstration. Production deployments MUST replace it with
a persistent implementation of the `SessionStore` trait (`crates/auths-auth-server/src/ports/session_store.rs`).

**Risks of InMemorySessionStore in production:**
- Sessions lost on server restart (authentication interruption)
- No session eviction (memory exhaustion under sustained load)
- No horizontal scaling (sessions not shared across instances)

**Recommended production replacements:**
- Redis-backed `SessionStore` for multi-instance deployments
- SQLite-backed `SessionStore` for single-instance deployments

The `SessionStore` trait is designed for this substitution — all session operations go
through the trait interface with no direct dependency on the in-memory implementation.
```

This is a documentation-only change. No code is missing — the trait abstraction already exists and the limitation is architectural, not a bug.

---

## Question 4: Can I verify a real commit from a real CI system?

### Current State

**Yes. This is fully implemented.**

**GitHub Action:** `.github/actions/verify-action/`
- `action.yml` — Composite action definition with inputs: `allowed-signers`, `commit-range`, `auths-version`, `fail-on-unsigned`
- `src/main.ts` — TypeScript entry point detecting PR vs push context, auto-determining commit range
- `src/verifier.ts` — Invokes `auths verify-commit` CLI with JSON output, falls back to per-commit verification
- `scripts/verify.sh` — Shell-based verification script for environments without Node.js
- `package.json` — `@auths/verify-action` with `@actions/core`, `@actions/exec`, `@actions/github`, `@actions/tool-cache`

**CLI command:** `crates/auths-cli/src/commands/verify_commit.rs`
```bash
auths verify-commit [<REF>] [--allowed-signers <PATH>] [--identity-bundle <PATH>] [--json]
```
- Supports single commits, ranges (`HEAD~5..HEAD`), and `HEAD` default
- `--identity-bundle` enables stateless verification in CI (no identity repo access needed)
- `--json` produces machine-readable output
- Exit codes: 0=valid, 1=invalid/unsigned, 2=error

**CI workflow examples:** `examples/ci/github-actions/`
- `verify-commits.yml` — Standard push/PR verification with identity bundle
- `verify-signatures-python.yml` — Python SDK-based verification
- `auths-verify-reusable.yml` — Reusable workflow for organizations with `mode: warn|enforce`

**WASM verification:** CI runs `cargo check --package auths_verifier --target wasm32-unknown-unknown --features wasm` on every push.

### Gap

None. The GitHub Action, CLI command, CI examples, and stateless identity bundle verification are all implemented. An acquirer can clone the repo, run the action, and verify commits end-to-end.

---

## Question 5: Can AI agents use this today?

### Current State

**Python bindings exist via PyO3 in `packages/auths-verifier-python/`:**

**Package:** `auths-verifier` (installable via `pip install auths-verifier`)
- Build system: maturin (`pyproject.toml`)
- Module: `auths_verifier._native` (Rust) + `auths_verifier.git` (pure Python)
- Publish workflow: `.github/workflows/publish-python.yml`

**Exposed PyO3 functions (5):**
1. `verify_attestation(attestation_json: str, issuer_pk_hex: str) -> VerificationResult`
2. `verify_chain(attestations_json: list[str], root_pk_hex: str) -> VerificationReport`
3. `is_device_listed(identity_did: str, device_did: str, attestations_json: list[str]) -> bool`
4. `is_device_authorized(...)` — deprecated, redirects to `verify_device_authorization`
5. `verify_device_authorization(identity_did: str, device_did: str, attestations_json: list[str], identity_pk_hex: str) -> VerificationReport`

**Pure Python functions:**
- `verify_commit_range(range: str, identity_bundle: str, mode: str) -> VerifyResult`
- `discover_layout() -> LayoutInfo`

**PyClasses:** `VerificationResult`, `VerificationStatus`, `ChainLink`, `VerificationReport`

**Type stubs:** `python/auths_verifier/__init__.pyi` with `py.typed` PEP 561 marker

**Documentation:** `docs/sdks/python/quickstart.md`

### Gap

**No `sign_action` function exists in Python.** The Python bindings are verification-only. Signing capabilities exist in Rust (`SecureSigner` trait in `crates/auths-core/src/signing.rs`) but are not exposed to Python.

**No LangChain integration or AI agent example exists.** There are no agent-specific patterns, tool definitions, or end-to-end examples showing an AI agent signing and verifying.

### Implementation Plan

**1. Create `docs/reference/action-envelope.md`** (do this FIRST, before touching any Rust or Python code)

The envelope format becomes a protocol commitment. Whatever JSON structure `sign_action` returns must be what `verify_attestation` accepts. This contract must be written down and reviewed before any implementation begins.

The file must specify:

```json
{
  "version": "1.0",
  "type": "<action_type>",
  "identity": "<did:keri:...>",
  "payload": { /* arbitrary JSON, canonicalized with json-canon */ },
  "timestamp": "<RFC3339>",
  "signature": "<hex-encoded Ed25519 signature over canonical(version + type + identity + payload + timestamp)>"
}
```

The canonical signing input is `json_canon::to_string()` of the envelope without the `signature` field. This matches the existing attestation pattern where `serialize_for_signing` strips the signature before canonicalization.

The document must also specify:
- Which fields are required vs optional
- Exact canonicalization procedure (field ordering, whitespace, encoding)
- How `verify_attestation` validates an action envelope (signature check, identity resolution)
- Versioning strategy (what happens when the format changes)

**2. Sign function for Python** — `packages/auths-verifier-python/src/lib.rs` (only after step 1 is reviewed)

This requires careful design. The `SecureSigner` trait in `auths-core` depends on `PassphraseProvider` and `KeyStorage`, which involve platform keychains. For AI agent use, a simpler approach is needed — agents manage their own key material in secure enclaves or secret managers:

```rust
/// Sign a payload with a raw Ed25519 private key.
/// For AI agents that manage their own key material.
#[pyfunction]
fn sign_bytes(
    private_key_hex: &str,
    message: &[u8],
) -> PyResult<String> {
    // Decode private key from hex
    // Create Ed25519KeyPair from seed
    // Sign message
    // Return hex-encoded signature
}

/// Sign an action payload and return a verifiable envelope.
/// The returned JSON conforms to the action envelope contract
/// (docs/reference/action-envelope.md) and is accepted by
/// verify_attestation().
#[pyfunction]
fn sign_action(
    private_key_hex: &str,
    action_type: &str,
    payload_json: &str,
    identity_did: &str,
) -> PyResult<String> {
    // Build canonical action envelope per contract spec
    // Canonicalize with json-canon (excluding signature field)
    // Sign with Ed25519
    // Return JSON envelope with signature
}
```

**3. AI agent example** — `examples/agent/langchain_tool.py`

```python
"""LangChain tool for Auths identity verification."""
from auths_verifier import verify_attestation, verify_chain, sign_action

# Example: Agent verifies another agent's action
def verify_agent_action(action_envelope_json: str, issuer_pk_hex: str) -> bool:
    result = verify_attestation(action_envelope_json, issuer_pk_hex)
    return result.valid

# Example: Agent signs its own action
def sign_agent_action(
    private_key_hex: str,
    action: str,
    payload: dict,
    agent_did: str,
) -> str:
    import json
    return sign_action(private_key_hex, action, json.dumps(payload), agent_did)
```

### Tests

**File:** `packages/auths-verifier-python/tests/test_signing.py`

```python
def test_sign_and_verify_roundtrip():
    """Sign a payload, then verify it with the public key."""
    from auths_verifier import sign_bytes, verify_attestation
    # Generate keypair (in test fixture)
    # Sign message
    # Verify signature matches
    pass

def test_sign_action_produces_valid_envelope():
    """sign_action returns JSON that verify_attestation accepts."""
    pass
```

---

## Question 6: What happens under load?

### Current State

**Read path:** O(1) via redb read-through cache (`crates/auths-id/src/storage/registry/cache.rs`).
- 5 redb tables: `EVENTS`, `KEY_STATE`, `TIP`, `ATTESTATIONS`, `CACHE_META`
- Sentinel file `.stale` for fast Git hook invalidation
- OID-based validity checking — if Git ref advances, cache rebuilds
- Re-entrancy guard (`AtomicBool`) prevents infinite recursion during population

**Write path:** Single-writer with advisory lock + CAS (`crates/auths-id/src/storage/registry/packed.rs`).
- `AdvisoryLock` using `fs2::FileExt::lock_exclusive()` (lines 75-102)
- CAS: re-reads ref OID before `set_target`, aborts on mismatch (lines 311-374)
- 6 constraints enforced on append: file uniqueness, prefix match, sequence monotonicity, inception-first, chain linkage, SAID integrity
- 3 files written per event: event JSON, tip.json, state.json
- Cache invalidated after successful write

**Sharding:** 2-level directory sharding (`crates/auths-id/src/storage/registry/shard.rs`) limits directory fanout to ~4096 entries per level.

**Existing benchmarks:** `crates/auths-core/benches/crypto.rs` benchmarks Ed25519 keygen, signing (64B-16KB), verification, key encryption/decryption using Criterion.

### Gap

**No registry-level benchmarks exist.** The crypto benchmarks test Ed25519 primitives but not the end-to-end read/write paths through the registry. No concurrent write testing exists — the single-writer assumption is documented but not stress-tested.

**The write throughput ceiling is not stated.** An acquirer won't just run benchmarks — they'll ask "what's the write throughput ceiling and why?" The single-writer advisory lock model means write throughput is bounded by Git commit latency on the underlying filesystem (typically 1-10ms per commit depending on fsync behavior and storage medium). That number needs to be stated explicitly alongside benchmark results, along with the architectural reason (Git integrity guarantees require sequential commits) and the mitigation (read scaling is horizontal via redb cache replication — each instance maintains a local cache). Without that framing, the benchmark results raise more questions than they answer.

### Implementation Plan

**1. Registry read benchmark** — `crates/auths-id/benches/registry_read.rs`

```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_cached_key_state_lookup(c: &mut Criterion) {
    // Setup: create registry with N identities, populate cache
    // Benchmark: random key state lookups via get_key_state()
    // Measure: latency at N=100, N=1000, N=10000
}

fn bench_cache_cold_start(c: &mut Criterion) {
    // Setup: create registry with N identities, invalidate cache
    // Benchmark: first read triggers full rebuild
    // Measure: rebuild time at N=100, N=1000
}

fn bench_event_append(c: &mut Criterion) {
    // Setup: create identity
    // Benchmark: append interaction events sequentially
    // Measure: append latency per event
}

criterion_group!(benches, bench_cached_key_state_lookup, bench_cache_cold_start, bench_event_append);
criterion_main!(benches);
```

**2. Concurrent write test** — `crates/auths-id/tests/concurrent_writes.rs`

```rust
#[test]
fn concurrent_appends_to_same_identity_are_serialized() {
    // Create identity at seq 0
    // Spawn 10 threads, each attempting to append interaction at seq 1
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();
    assert_eq!(successes.len(), 1);
    assert_eq!(failures.len(), 9);
    for f in &failures {
        assert!(matches!(f, Err(RegistryError::ConcurrentModification)));
    }
    // Final KEL should have exactly 2 events (inception + 1 interaction)
}

#[test]
fn concurrent_appends_to_different_identities_succeed() {
    // Create 10 identities
    // Spawn 10 threads, each appending to a different identity
    // All should succeed (advisory lock serializes but doesn't reject)
    // Each KEL should have 2 events
}
```

**3. Performance documentation** — Add to `docs/notes/THREAT_MODEL.md` or new `docs/reference/performance.md`:

```markdown
## Performance Characteristics

### Read Path
- Cache hit: Single redb transaction (~microseconds)
- Cache miss: Full Git tree traversal + redb rebuild (proportional to identity count)
- Cache invalidation: Sentinel file touch (nanoseconds)

### Write Path
- Advisory lock acquisition: Single flock() syscall
- Event append: Git blob + tree + commit creation (~milliseconds)
- CAS verification: Single ref read + compare
- Concurrent writes to same identity: Serialized via advisory lock, CAS rejects stale reads
- Concurrent writes to different identities: Serialized via advisory lock (single-writer)

### Write Throughput Ceiling

Write throughput is bounded by Git commit latency on the underlying filesystem.
Each event append requires a blob write, tree update, and commit creation with
fsync. On typical SSDs this is 1-10ms per commit; on networked/shared
filesystems it may be higher.

**Why this ceiling exists:** Git's integrity guarantees (content-addressable
storage, atomic ref updates) require sequential commits. The advisory lock
ensures exactly one writer at a time, and CAS (compare-and-swap) on the ref
OID prevents lost updates. This is a deliberate architectural choice — Git
integrity guarantees require it.

**Mitigation:** Read scaling is horizontal via cache replication. Each instance
maintains a local redb cache populated from Git. Adding read replicas requires
only cloning the Git repository and running a cache-warming read. Write
throughput can be increased by sharding identities across multiple Git
repositories, though this is not currently implemented.

### Scaling Limits
- Single-writer model: Designed for moderate write throughput (~100-1000 events/sec)
- Read scaling: Horizontal via cache replication (each instance has local redb)
- Directory sharding: ~4096 entries per level, supports millions of identities
```

---

## Question 7: How does an identity recover from key compromise?

### Current State

**Pre-rotation is fully implemented and tested.**

**Inception** (`crates/auths-id/src/keri/inception.rs`):
- Generates two Ed25519 keypairs: current (active) and next (pre-committed)
- Inception event includes `n: vec![next_commitment]` where commitment = `E{base64url(blake3(next_public_key))}`
- Inception event signed by current key, stored in Git KEL

**Rotation** (`crates/auths-id/src/keri/rotation.rs`):
- Loads current state from KEL
- Checks `state.can_rotate()` (not abandoned, has next commitment)
- **Verifies** `verify_commitment(next_keypair.public_key(), &state.next_commitment[0])` — attacker without pre-committed key fails here
- Generates new next keypair for future rotation
- Rotation event signed by new key (the former next key)
- New `n` field commits to the freshly generated next-next key

**Abandonment** (`crates/auths-id/src/keri/rotation.rs`, lines 163-237):
- Final rotation with empty next commitment (`n: vec![], nt: "0"`)
- Still requires the pre-committed next key
- After abandonment, `state.can_rotate()` returns false

**Verification** (`crates/auths-verifier/src/keri.rs`):
- `verify_kel` replays every event, checking commitment at each rotation
- `verify_commitment` compares `blake3(new_public_key)` against stored commitment
- Rejects rotation if commitment doesn't match

**CLI commands:**
- `auths id rotate` — Standard rotation with key alias management
- `auths emergency rotate-now` — Force immediate rotation on compromise
- `auths emergency revoke-device` — Revoke a specific compromised device
- `auths emergency freeze` — Temporarily disable all signing
- `auths emergency report` — Generate incident report
- `auths doctor` — Health check after recovery

**Tests confirming security claims:**
- `rotation_verifies_commitment` — Wrong key fails with `RotationError::CommitmentMismatch`
- `abandoned_identity_cannot_rotate` — Abandoned identity rejects further rotation
- `rejects_rot_signed_with_old_key` — Old key cannot sign valid rotation event (verifier test, line 760)
- `rotation_requires_commitment` — Integration test in `crates/auths-id/tests/keri_integration.rs`

**Documentation:**
- `docs/concepts/key-rotation.md` — Pre-rotation security model explained
- `docs/cli/commands/auths-emergency.md` — Full emergency response procedures

### Gap

**No single end-to-end documented recovery walkthrough exists** that shows the exact sequence of CLI commands from "key compromised" to "identity recovered and verified." The concepts and commands exist but are not stitched together into a demonstrable flow.

### Implementation Plan

**1. Recovery walkthrough document** — `docs/examples/key-compromise-recovery.md`

```markdown
# Key Compromise Recovery Walkthrough

This document demonstrates the complete recovery flow when an identity's
current signing key is compromised.

## Setup: Create an identity

    auths id create --alias alice
    # Output: Identity created with DID did:keri:EAbcd...
    # Two keys generated: current (active) and next (pre-committed)

## Scenario: Current key is compromised

The attacker has the current signing key but NOT the pre-committed next key.

### Step 1: Freeze signing (optional, buys time)

    auths emergency freeze --duration 24h --yes

### Step 2: Verify the attacker cannot rotate

The pre-rotation commitment in the inception event binds the next key.
The attacker would need to call:

    auths id rotate --alias alice

This fails because `rotate_keys()` calls `verify_commitment()` which
compares `blake3(attacker_key)` against the stored commitment. The
attacker's key does not match — rotation is rejected.

### Step 3: Rotate with the legitimate next key

    auths emergency rotate-now --reason "Current key compromised" --yes

This succeeds because:
1. The legitimate holder has the pre-committed next key (stored in keychain)
2. `verify_commitment(next_key, state.next_commitment)` passes
3. A new rotation event is created, signed by the next key
4. A new next-next key is generated and pre-committed

### Step 4: Re-authorize devices

    auths device link --identity-key-alias alice-rotated-20260214 \
        --device-key-alias macbook \
        --device-did "did:key:z6Mk..."

### Step 5: Verify recovery

    auths doctor
    # Output: Identity healthy, key rotated, N devices linked

### Step 6: Verify the full KEL

    auths id inspect --alias alice-rotated-20260214

This replays the entire KEL, verifying every event's signature,
SAID integrity, chain linkage, and pre-rotation commitment.

## What the attacker can and cannot do

| Action | Attacker can? | Why |
|--------|--------------|-----|
| Sign with old key | Yes (until rotation) | They have the current key |
| Rotate to their key | No | Pre-rotation commitment doesn't match |
| Create fake events | No | SAID integrity check fails |
| Reorder events | No | Sequence + chain linkage verification |
| Replay old events | No | SAID chain breaks |
```

**2. Integration test demonstrating the claim** — `crates/auths-id/tests/recovery_flow.rs`

```rust
#[test]
fn attacker_cannot_rotate_without_precommitted_key() {
    let (_dir, repo) = setup_repo();
    let init = create_keri_identity(&repo).unwrap();

    // Attacker generates their own key
    let rng = SystemRandom::new();
    let attacker_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Attacker attempts rotation — MUST fail
    let result = rotate_keys(&repo, &init.prefix, attacker_pkcs8.as_ref());
    assert!(matches!(result, Err(RotationError::CommitmentMismatch)));

    // Legitimate holder rotates — MUST succeed
    let result = rotate_keys(&repo, &init.prefix, &init.next_keypair_pkcs8);
    assert!(result.is_ok());

    // Verify KEL is valid after rotation
    let kel = GitKel::new(&repo, &init.prefix);
    let events = kel.get_events().unwrap();
    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 1);
}

#[test]
fn full_recovery_flow_end_to_end() {
    let (_dir, repo) = setup_repo();
    let init = create_keri_identity(&repo).unwrap();

    // Step 1: Legitimate rotation (simulating emergency rotate-now)
    let rotation = rotate_keys(&repo, &init.prefix, &init.next_keypair_pkcs8).unwrap();
    assert_eq!(rotation.sequence, 1);

    // Step 2: Second rotation with the new next key
    let rotation2 = rotate_keys(&repo, &init.prefix, &rotation.new_next_keypair_pkcs8).unwrap();
    assert_eq!(rotation2.sequence, 2);

    // Step 3: Verify full KEL integrity
    let kel = GitKel::new(&repo, &init.prefix);
    let events = kel.get_events().unwrap();
    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 2);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());
}
```

---

## Question 8: Does the registry verify signatures before accepting events?

### Current State

The registry server (`crates/auths-registry-server/`) exposes an HTTP API for appending events to identity KELs.

**Signature extractor** (`crates/auths-registry-server/src/extractors/signature.rs`):
- Extracts `X-Auths-Signature`, `X-Auths-Public-Key`, `X-Auths-Timestamp` headers from HTTP requests
- **Does NOT verify the signature against the request body** — contains a `TODO` comment indicating this is unimplemented

**Append handler** (`crates/auths-registry-server/src/routes/identity.rs`):
- `POST /v1/identities/:prefix/kel` accepts JSON event payload
- Validates prefix matches path parameter
- Delegates to `backend.append_event()` with comment: "backend validates signatures and sequence"
- **Does NOT use the signature extractor** — no request-level signature verification

**Backend validation** (`crates/auths-id/src/storage/registry/packed.rs`, `append_event()` lines 448-575):
- **CONSTRAINT 1:** Refuse if event file already exists (append-only)
- **CONSTRAINT 2:** Event prefix must match argument
- **CONSTRAINT 3:** Sequence must be monotonic (no gaps)
- **CONSTRAINT 4:** First event must be inception
- **CONSTRAINT 5:** Non-inception events must chain to previous SAID
- **CONSTRAINT 6:** Verify SAID matches computed hash (`verify_event_said`)

### Gap

**The backend does NOT call `verify_kel()` or verify event signatures before appending.** It verifies structural integrity (SAID hash, chain linkage, sequence ordering) but not cryptographic integrity (Ed25519 signatures, pre-rotation commitments).

This means an attacker can submit events via the HTTP API that:
- Have valid SAIDs (self-addressing integrity passes)
- Reference the correct previous event SAID (chain linkage passes)
- Have monotonic sequence numbers (ordering passes)
- **But have forged, invalid, or missing signatures**

This breaks the self-authenticating write path claim. The `validate_kel()` function in `crates/auths-id/src/keri/validate.rs` already performs full signature verification — it exists but is not called in the append path.

**What cannot be exploited** (existing constraints prevent):
- Breaking the SAID chain (CONSTRAINT 6)
- Creating sequence gaps (CONSTRAINT 3)
- Overwriting existing events (CONSTRAINT 1)
- Submitting events with wrong prefix (CONSTRAINT 2)

### Implementation Plan

**1. Add signature verification to append path** — `crates/auths-id/src/storage/registry/packed.rs`

After the existing 6 constraints pass, add a 7th:

```rust
// CONSTRAINT 7: Verify cryptographic integrity of the new event
// against the existing KEL + the new event
let mut all_events = existing_events.clone();
all_events.push(new_event.clone());
validate_kel(&all_events).map_err(|e| RegistryError::InvalidEvent {
    reason: format!("KEL validation failed: {}", e),
})?;
```

This verifies:
- The new event is signed by the correct key (current key for interactions, next key for rotations)
- Rotation events satisfy pre-rotation commitments
- Inception events are self-signed with the declared key

**2. Implement request-level signature verification** — `crates/auths-registry-server/src/extractors/signature.rs`

Complete the TODO to verify that the `X-Auths-Signature` header contains a valid signature over the request body using the `X-Auths-Public-Key`.

**3. Add middleware** — `crates/auths-registry-server/src/middleware/`

```rust
/// Reject requests to append events unless the request signature
/// matches a key authorized in the existing KEL for that prefix.
pub async fn verify_request_authorization(
    // Extract prefix from path
    // Load current key state for prefix
    // Verify request signature against current key
    // Or: verify the event signature within the body directly
) -> Result<Next, StatusCode> { ... }
```

### Tests

**File:** `crates/auths-registry-server/tests/append_verification.rs`

```rust
#[tokio::test]
async fn rejects_event_with_forged_signature() {
    // Start registry server
    // Create valid inception event
    // Submit inception (should succeed)
    // Create interaction event with wrong signature
    // Submit interaction (should fail with signature error)
}

#[tokio::test]
async fn rejects_rotation_without_precommitted_key() {
    // Start registry server
    // Submit valid inception
    // Create rotation event signed by random key (not pre-committed)
    // Submit rotation (should fail with commitment mismatch)
}

#[tokio::test]
async fn accepts_valid_event_sequence() {
    // Start registry server
    // Submit valid inception
    // Submit valid interaction signed by inception key
    // Submit valid rotation signed by pre-committed next key
    // All should succeed
}
```

---

## Summary: Gap Priority Matrix

| # | Question | Status | Gap Severity | Effort |
|---|----------|--------|-------------|--------|
| 1 | Crypto core correct? | 95% — one silent coercion | Medium (correctness) | Small (2h) |
| 2 | Witness network exists? | 75% — server done, client missing | **Critical** (security claim, key differentiator vs Sigstore) | Medium (1-2d) |
| 3 | Threat model? | 95% — exists, minor InMemorySessionStore gap | Low (documentation) | Trivial (30m) |
| 4 | CI commit verification? | 100% — fully implemented | None | None |
| 5 | AI agent usable? | 70% — verification only, no signing | Medium (market story) | Medium (1-2d) |
| 6 | Performance under load? | 60% — no registry benchmarks, throughput ceiling unstated | Medium (due diligence) | Medium (1d) |
| 7 | Key compromise recovery? | 90% — implemented, needs walkthrough | Low (documentation) | Small (2h) |
| 8 | Registry verifies before appending? | 70% — structural checks only, no signature verification | **Critical** (self-authenticating write path claim) | Medium (1d) |

### Critical Path for Due Diligence

1. **Fix sequence coercion** (Q1) — Correctness fix, blocks nothing, do first
2. **Add signature verification to registry append path** (Q8) — The self-authenticating write path claim is broken without this. The `validate_kel()` function already exists; it just needs to be called in the append path
3. **Implement HttpWitnessClient** (Q2) — The single highest-value gap. The witness server and trait exist; closing the loop with a client makes the KERI security claim demonstrable end-to-end
4. **Define sign_action envelope contract** (Q5 prerequisite) — The envelope format becomes a protocol commitment; specify before implementing
5. **Add registry benchmarks with throughput framing** (Q6) — Proves the system works under real conditions and explicitly states the write throughput ceiling with architectural justification
6. **Add Python signing + agent example** (Q5) — Proves the AI agent market story
7. **Write recovery walkthrough** (Q7) — Documentation, low effort, high DD value
8. **Document InMemorySessionStore limitation** (Q3) — Append to existing threat model
