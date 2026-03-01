# Security Engineering Standards

This document captures mandatory engineering rules for this codebase. These rules apply at every code review and are checked by CI. When in doubt, err on the side of stricter memory hygiene.

## Memory Hygiene

### Rule 1: No raw byte arrays for private key material at module boundaries

Any type or function that handles an Ed25519 seed, PKCS#8 private key blob, or passphrase must use zeroizing wrappers. This prevents the bytes from surviving on the heap after the operation completes.

**Function parameters containing key material:**
```rust
// Correct — zeroized on drop, no orphaned copies
pub fn extract_seed_from_pkcs8(
    pkcs8_bytes: &zeroize::Zeroizing<Vec<u8>>,
) -> Result<SecureSeed, CryptoError>;

// Wrong — raw bytes outlive the call
pub fn extract_seed_from_pkcs8(pkcs8_bytes: &[u8]) -> Result<SecureSeed, CryptoError>;
```

**Types holding private key material:**
```rust
// Correct — memory cleared automatically on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey { ... }

// Wrong — bytes remain in memory after struct is dropped
pub struct SigningKey { seed: Vec<u8>, ... }
```

**Enforcement rule**: Any type or function whose name contains `seed`, `key`, `pkcs8`, or `passphrase` must use `Zeroizing<Vec<u8>>`, `SecureSeed`, or another `ZeroizeOnDrop` wrapper. No raw `Vec<u8>` or `&[u8]` for private key material at module boundaries.

### Rule 2: Never use `Zeroizing<String>` for key material

`String` can silently reallocate its backing buffer during growth operations, leaving unzeroed copies of the secret bytes in abandoned heap allocations. `Zeroizing`'s drop impl zeroes only the *current* allocation — it cannot reach orphaned copies from past reallocations.

```rust
// Wrong — String can reallocate, leaving ghost copies
let key_pem = Zeroizing::new(String::from_utf8(raw_bytes)?);

// Correct — Vec<u8> does not reallocate silently during growth
let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(raw_bytes);
```

Only convert to `String` at the final output boundary (e.g., PEM output), which contains signatures or public keys — not private key material.

### Rule 3: `ZeroizeOnDrop` over manual `zeroize()` calls

Manual `zeroize()` calls are unreliable — they are silently skipped on early `?` returns and panics.

```rust
// Wrong — zeroize() is skipped if any earlier line returns Err
let mut seed = load_seed()?;
let sig = sign(&seed, data)?;
seed.zeroize(); // never reached on error paths

// Correct — ZeroizeOnDrop fires unconditionally, including on panic unwind
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureSeed { bytes: [u8; 32] }
```

## Async Safety

### Rule 4: No synchronous blocking I/O on async worker threads

Blocking operations on async executor threads starve the thread pool. On repositories with 50k+ commits, a synchronous `git2` revwalk takes several seconds — stalling all other tasks on that thread.

```rust
// Wrong — blocks the tokio executor thread
pub async fn generate_report(&self) -> Result<AuditReport, AuditError> {
    for commit in self.provider.walk_commits(None, None)? { ... }
}

// Correct — offloads blocking work to a dedicated thread pool
pub async fn generate_report(
    &self,
    provider: Arc<dyn GitLogProvider + Send + Sync>,
) -> Result<AuditReport, AuditError> {
    tokio::task::spawn_blocking(move || {
        provider.walk_commits(None, None)?.collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|e| AuditError::SpawnFailed(e.to_string()))??
}
```

Applies to: `git2` revwalk, `std::fs` operations, synchronous cryptographic operations over large inputs.

### Rule 5: Use `tokio::fs` for file I/O in async contexts

`std::fs::File::open` blocks the executor thread on slow or network-mounted drives. Always use `tokio::fs::File::open(...).await` in async functions.

## Code Comments

See `CLAUDE.md § Code Comments` for the full policy. The summary:

- Do NOT commit instructional comments explaining *process* (e.g., `// Do NOT use std::fs here`). The code structure should speak for itself.
- DO commit comments for opinionated decisions or mathematically non-obvious logic.
- Task descriptions and tickets may contain explanatory comments in code snippets — these are for the reader of the ticket only and must not appear verbatim in committed source.

## Mutex Poisoning

`std::sync::Mutex` becomes poisoned if any thread panics while holding the lock. Never call `.unwrap()` on a mutex lock — map the `PoisonError` to a domain error instead:

```rust
// Wrong — panics permanently after any prior thread panic
let repo = self.repo.lock().unwrap();

// Correct — returns a recoverable domain error
let repo = self.repo.lock()
    .map_err(|_| GitProviderError::LockPoisoned)?;
```

Every `Mutex`-wrapping type must include a `LockPoisoned` variant in its error enum.
