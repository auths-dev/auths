# Auths Architectural Critique

## Premise

This critique is grounded in the actual codebase — not the aspirational 2030 scenario the other audit projects onto it. Auths is a **developer tool for cryptographic identity in Git repositories today**, and should be evaluated against that reality first, then against the scaling horizon you actually intend to reach.

---

## What's Genuinely Strong

### The Verification Plane Is Excellent

The `auths-verifier` crate is the crown jewel and it earns that distinction. `verify_with_keys` accepts `&Attestation` and `&[u8]` — pure data in, result out. No filesystem, no network, no clocks. The `AttestationError` enum is a clean domain error with no IO variants leaking through. The chain verification logic (`verify_chain`, `verify_chain_with_capability`) correctly implements intersection semantics for capability delegation — you can't escalate through a chain, only narrow.

The FFI layer wraps everything in `panic::catch_unwind`, which is the correct production-hardened pattern for embedding Rust into Go/Python/Swift runtimes. The fuzz targets (`attestation_parse`, `did_parse`, `verify_chain`) confirm this is built with adversarial inputs in mind.

### Sans-IO Discipline Is Real, Not Aspirational

The previous audit calls this out but undersells how thoroughly it's implemented. The policy engine's `evaluate_policy` takes `now: DateTime<Utc>` — time is always injected, never sampled. The `WitnessProvider` trait is synchronous and returns `Option<Oid>`, keeping network concerns out of the decision path. The `Decision` enum's `Indeterminate` variant is a genuine safety contribution: it prevents the system from collapsing "I don't know" into either Allow or Deny.

The KERI module's domain types (`Event`, `KeyState`, `Attestation`) are all `Serde`-only with no git2 imports. The module doc in `keri/mod.rs` even has a table declaring which types are sans-IO. This level of documentation discipline is rare.

### The Registry Backend Trait Has Good Bones

The `RegistryBackend` trait is well-designed in its *interface*. The visitor pattern (`visit_events`, `visit_identities`, `visit_devices`) avoids materialising entire collections into memory. The overwrite semantics are explicitly documented (append-only for KEL events, latest-view for attestations). The "FROZEN SURFACE" annotation on the trait is a healthy sign of API discipline.

The `AgentHandle` exists alongside the deprecated `GLOBAL_AGENT`, meaning you've already started the migration away from global state. The session handler (`AgentSession`) correctly takes `Arc<AgentHandle>`, proving the non-global path works.

---

## What's Actually Wrong

### 1. The `git2::Error` Leak Is Worse Than Stated

The other audit identifies `RegistryError::Git(#[from] git2::Error)` as a portability problem. True, but it's also a **correctness problem right now**.

The `PackedRegistryBackend` maps Git-specific failure modes (ref not found, index lock contention) through a generic `Git` variant. Callers matching on `RegistryError` cannot distinguish between "the identity doesn't exist" and "the Git index is temporarily locked." These are fundamentally different failures requiring different recovery strategies. The `RegistryError::NotFound` variant exists but the `#[from] git2::Error` catch-all swallows cases that should route there instead.

The `WitnessProvider` trait uses `git2::Oid` as its return type. This means a core trait in `auths-core` — which otherwise has no business knowing about Git — imports `git2` purely for a 20-byte hash. This is the kind of coupling that metastasises: every future witness implementation must depend on `git2` even if it never touches a repository.

### 2. The Single-Writer Model Is A Correct Design Choice (For Now)

The other audit frames the single-writer Git model as a critical flaw. I partially disagree. The `PackedRegistryBackend` doc explicitly states: *"This backend assumes a single-writer model. CAS is used as a safety net only."* This is honest engineering. For a CLI tool managing a local Git repo, single-writer is appropriate.

The actual problem is that the code **doesn't enforce what it documents**. The CAS logic in `create_commit` reads the ref, creates a commit, re-reads the ref, and compares OIDs. But between the re-read and the `set_target`, another process could update the ref. The `git2::Reference::set_target` call uses file locking internally, which helps, but the comment claims this is "atomic at the filesystem level" — it's atomic at the *file* level (the lockfile), not the *filesystem* level. On NFS or networked filesystems, this guarantee evaporates.

### 3. The Policy Engine Is Complete But Inflexible

The `evaluate_policy` function handles: revocation checks, expiry, issuer matching, and capability requirements. For the current use case, this is sufficient and well-implemented.

The other audit's recommendation to integrate Cedar is premature. Cedar adds a WASM runtime, a schema language, and significant complexity. The real issue is simpler: the `Policy` struct has a `required_capability: Option<String>` — a single optional capability. There's no way to express "requires capabilities A AND B" or "requires A OR B." This limitation will hit before the lack of a declarative engine does.

The `Policy` struct even documents its own incompleteness: *"This will be extended in fn-12 (Policy Engine epic)."* The extension point exists; the question is what shape it takes.

### 4. `GLOBAL_AGENT` Is Half-Deprecated

There are 10 references to `GLOBAL_AGENT` in the codebase. It's marked `#[deprecated]` but still actively used in the FFI/API module (`api/ffi.rs`, `api/runtime.rs`). The `AgentHandle` and `AgentSession` provide the correct non-global path, but the migration is incomplete. Every call through `GLOBAL_AGENT.lock().unwrap()` is a potential panic site if the mutex is poisoned — and the `unwrap()` is used rather than proper error propagation.

### 5. git2::Oid as a Domain Identifier Is A Leaky Abstraction

Beyond the witness provider, `git2::Oid` appears in the policy module's `evaluate_with_witness` signature. This means the *policy evaluation function* — which is otherwise beautifully sans-IO — takes a Git-specific type as input. If you ever want to run policy evaluation against a non-Git backend, this signature breaks.

This is a 4-line fix (replace `Oid` with `[u8; 20]` or a newtype), but the blast radius grows with every new function that takes `Oid`.

### 6. The Index Crate Is Underspecified

`auths-index` provides SQLite-backed indexing for fast lookups. This is architecturally sensible — separate the query model from the storage model. But the rebuild logic (`rebuild.rs`) reads directly from `PackedRegistryBackend`, creating a hard dependency between the index and the Git implementation. If the backend changes, the index rebuilder breaks.

---

## What The Other Audit Gets Wrong

### The 2030 Agentic Framing Is Premature

The audit evaluates Auths against "10,000 agents rotating keys at 100+ writes/second." This is a valid target for some future version, but it's not the right lens for architectural prioritisation today. The system works correctly for its current use case (local Git repos, CLI users, small teams). Rebuilding the storage layer for Kafka/DynamoDB before the single-writer model actually hits a wall is premature optimisation.

### Cedar Integration Is Overkill

Adding a policy DSL introduces: a new syntax for users to learn, a new testing surface, schema versioning, and a WASM dependency. The existing Rust policy code is deterministic, well-tested, and auditable. The real gap is capability expressiveness in the `Policy` struct, not the evaluation mechanism.

### CQRS Is A Solution Looking For A Problem

The suggestion to separate writes (ingestion API) from reads (materializer) makes sense at genuine scale. For a Git-backed CLI tool, this introduces: a message queue dependency, eventual consistency semantics that users must understand, and operational complexity (running a materializer process). The correct intermediate step is fixing the CAS guarantees and adding retry semantics — not introducing Kafka.

---

## Summary Assessment

| Area | Verdict | Notes |
|------|---------|-------|
| Verification core | **Production-ready** | Sans-IO, fuzzed, FFI-safe |
| KERI implementation | **Solid** | Pre-rotation, self-certifying IDs, KEL replay |
| Policy engine | **Functional, needs extension** | Missing compound capabilities |
| Storage abstraction | **Incomplete** | Trait is good, error types leak git2 |
| Global state | **Half-migrated** | AgentHandle exists, GLOBAL_AGENT still active |
| Git backend | **Correct for current scale** | Single-writer is documented and appropriate |
| WitnessProvider coupling | **Needs fix** | git2::Oid in core trait is wrong |
| Testing | **Strong** | Fuzz targets, property tests, integration tests |
