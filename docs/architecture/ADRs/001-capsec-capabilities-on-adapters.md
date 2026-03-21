# ADR-001: capsec Capabilities on Adapters, Not Port Traits

**Status:** Accepted
**Date:** 2026-03-21
**Epic:** fn-82 (capsec Type System Adoption)

## Context

We are adopting [capsec](https://github.com/bordumb/capsec) to enforce I/O boundaries at compile time. capsec provides zero-sized capability tokens (`Cap<P>`, `SendCap<P>`) and a `Has<P>` trait bound that functions use to declare what I/O they require.

The auths workspace uses a ports-and-adapters architecture. Port traits (e.g., `BlobReader`, `RegistryClient`, `KeyStorage`) are defined in domain crates (`auths-core`, `auths-id`) and stored as `Arc<dyn Trait + Send + Sync>` in `AuthsContext`. Adapter implementations live in infrastructure crates (`auths-infra-git`, `auths-infra-http`) and the CLI (`auths-cli/adapters/`).

The question: where do capsec capability bounds go?

## Decision

**Capability tokens are held by adapter structs, not declared on port traits.**

```rust
// Port trait — UNCHANGED, no capsec dependency
pub trait BlobReader: Send + Sync {
    fn read_blob(&self, key: &str) -> Result<Vec<u8>, StorageError>;
}

// Adapter — holds capability token internally
pub struct GitBlobReader {
    repo_path: PathBuf,
    fs_cap: SendCap<FsRead>,
}

impl GitBlobReader {
    pub fn new(repo_path: PathBuf, fs_cap: SendCap<FsRead>) -> Self {
        Self { repo_path, fs_cap }
    }
}

impl BlobReader for GitBlobReader {
    fn read_blob(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        capsec::fs::read(self.repo_path.join(key), &self.fs_cap)
            .map_err(|e| StorageError::ReadFailed(e.to_string()))
    }
}
```

The composition root in `auths-cli` creates `CapRoot`, grants capabilities, and passes `SendCap<P>` tokens to adapter constructors:

```rust
let root = capsec::root();
let fs_cap = root.grant::<FsRead>().make_send();
let blob_reader: Arc<dyn BlobReader + Send + Sync> =
    Arc::new(GitBlobReader::new(repo_path, fs_cap));
```

## Alternatives Considered

### Alternative A: `Has<P>` bounds on port trait definitions

```rust
pub trait BlobReader: Send + Sync + Has<FsRead> {
    fn read_blob(&self, key: &str) -> Result<Vec<u8>, StorageError>;
}
```

**Rejected** because:
- Adding generic `Has<P>` bounds to traits breaks object safety. `Arc<dyn BlobReader + Send + Sync>` would no longer compile because `Has<P>` has a generic parameter.
- The entire `AuthsContext` is built on `Arc<dyn Trait>` dispatch. This would require a fundamental redesign of the dependency injection container.
- Domain crates (`auths-core`, `auths-id`) would need a capsec dependency, leaking an infrastructure concern into domain logic.

### Alternative B: `Has<P>` bounds on individual trait methods

```rust
pub trait BlobReader: Send + Sync {
    fn read_blob(&self, key: &str, cap: &impl Has<FsRead>) -> Result<Vec<u8>, StorageError>;
}
```

**Rejected** because:
- Methods with `impl Trait` parameters are not object-safe. Same `dyn Trait` problem as Alternative A.
- Every caller — including domain logic that should be capsec-unaware — would need to pass capability tokens through.
- Fakes in tests would need dummy capability tokens even though they do no I/O.

### Alternative C: Separate capsec-aware wrapper traits

```rust
pub trait CapBlobReader: Send + Sync {
    fn read_blob(&self, key: &str, cap: &impl Has<FsRead>) -> Result<Vec<u8>, StorageError>;
}
```

**Rejected** because:
- Duplicates the entire port trait surface area.
- Two parallel hierarchies to maintain.
- Over-engineered for the actual problem.

## Consequences

**Positive:**
- Port traits remain object-safe and capsec-free. Domain crates have zero capsec dependency.
- Follows the established clock injection precedent (fn-64): capabilities are created at the CLI boundary and passed down, just like `DateTime<Utc>` is created via `Utc::now()` at the CLI boundary and injected into domain functions.
- Adapters are the natural place for I/O tokens — they are the I/O boundary by definition.
- Fakes and test doubles need no capsec awareness since port traits are unchanged. Only integration tests that construct real adapters need `capsec::test_root()`.
- Published library crates (`auths-core`, `auths-id`, `auths-verifier`) don't inherit a pre-1.0 dependency.

**Negative:**
- The compiler cannot prevent an adapter from doing I/O without its capability token — it can still call `std::fs::read()` directly. This is mitigated by `cargo capsec audit` which detects direct `std` calls.
- If an adapter is constructed without the right capability (e.g., someone forgets to pass `SendCap<FsRead>`), the error is at the adapter constructor call site, not at the I/O call site. This is acceptable — the constructor is the API contract.
- Capability tokens are not visible in port trait signatures, so a reader of the trait alone cannot see what I/O the adapter will do. The audit tool's output serves as the capability manifest.

## Precedent

This decision mirrors the clock injection pattern established in ADR fn-64:

| Concern | Clock (fn-64) | Capabilities (fn-82) |
|---------|--------------|---------------------|
| What's banned in domain crates | `Utc::now()` | `std::fs`, `std::net`, `std::process` |
| Created at | CLI boundary (`Utc::now()`) | CLI boundary (`capsec::root()`) |
| Passed via | Function parameter (`now: DateTime<Utc>`) | Adapter constructor (`SendCap<P>`) |
| Domain crates see | `DateTime<Utc>` (a value) | Nothing (capabilities are adapter-internal) |
| Enforcement | clippy.toml bans `Utc::now` | clippy.toml bans `std::fs` + capsec audit |
