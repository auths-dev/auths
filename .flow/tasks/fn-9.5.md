# fn-9.5 Fix mutex lock unwraps in auths-core

## Description
## Fix mutex lock unwraps in auths-core

~18 mutex `.lock().unwrap()` calls across 4 files. This is the largest category.

### Policy

- **For methods returning `Result`**: Convert to `.lock().map_err(|_| AgentError::MutexError("context".into()))?`. The `AgentError::MutexError` variant already exists.
- **For methods returning `()` (cache operations)**: Use `.lock().unwrap_or_else(|e| e.into_inner())` — silently recover from poisoning. Cache clearing is best-effort. Alternatively, change return type to `Result<()>` if feasible without breaking trait signatures.
- **For trait implementations**: If the trait method signature can't be changed, use `#[allow]` with SAFETY comment as a last resort.

### Files and locations

1. **`src/config.rs:15,20`** — `ENCRYPTION_ALGO.read().unwrap()` and `.write().unwrap()` in `current_algorithm()` and `set_encryption_algorithm()`. These return plain values. Options: change return to `Result`, or use `unwrap_or_else(|e| e.into_inner())`.

2. **`src/signing.rs:386,392,409,418,487`** — `self.cache.lock().unwrap()` in `CachedPassphraseProvider` and `UnifiedPassphraseProvider`. Some methods return `()` (`clear_cache`, `on_incorrect_passphrase`). The `PassphraseProvider` trait method signatures constrain what we can do.

3. **`src/storage/memory.rs:120,125,129,133,142,149,197,202,206,210,219,224`** — `MEMORY_KEYCHAIN.lock().unwrap()` and `self.store.lock().unwrap()` in `MemoryKeychainHandle` and `IsolatedKeychainHandle`. These implement the `KeyStorage` trait which returns `Result<_, AgentError>` — so we CAN use `.map_err()`.

4. **`src/storage/encrypted_file.rs:95,103`** — `self.password.lock().unwrap()` in `EncryptedFileStorage`. Returns `Result<_, AgentError>` — can use `.map_err()`.

5. **`src/witness/server.rs:487,539,560,571`** — `state.inner.storage.lock().unwrap()` in Axum handlers. Should return HTTP 500 on poisoned mutex instead of panicking.

### Smoke test
```bash
cargo nextest run -p auths_core
```
## Acceptance
- [ ] All `.lock().unwrap()` in `crates/auths-core/src/` replaced with either `.map_err()` propagation, `.unwrap_or_else(|e| e.into_inner())`, or `#[allow]` + SAFETY comment
- [ ] No bare `.lock().unwrap()` or `.lock().expect()` remaining without annotation
- [ ] Witness server handlers return HTTP 500 on mutex poisoning instead of panicking
- [ ] `cargo nextest run -p auths_core` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
