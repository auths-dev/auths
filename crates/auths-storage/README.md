# auths-storage

Storage adapters for the identity and registry ports defined in `auths-id`.

## Role

This crate contains **adapters only** — no domain logic. It implements the port traits from `auths-id::ports` (e.g., `RegistryBackend`, `AttestationSource`) for specific storage backends. The identity domain in `auths-id` never imports from this crate.

```
auths-storage  ──depends on──▶  auths-id::ports
auths-id       (never imports from auths-storage)
binary crates  ──depend on──▶  both
```

## Feature Flags

| Feature | Dependencies enabled | Provides |
|---------|---------------------|---------|
| `backend-git` | `git2`, `tempfile` | `GitRegistryBackend` (production Git adapter) |
| `backend-postgres` | `sqlx`, `tokio` | `PostgresAdapter` (stub, not yet implemented) |

No features are enabled by default. Binary crates select the backend they need.

## Wiring a Backend (Composition Root)

```rust,ignore
use std::sync::Arc;
use auths_id::ports::RegistryBackend;
use auths_storage::git::GitRegistryBackend;

// In main.rs or app startup — the only place that knows the concrete type.
let backend: Arc<dyn RegistryBackend + Send + Sync> =
    Arc::new(GitRegistryBackend::new(config));

// Inject into application state — all downstream code sees only the trait.
let state = AppState { registry: backend };
```

## Adding a New Backend

1. Create `src/<backend>/mod.rs` and `src/<backend>/adapter.rs`
2. Implement `RegistryBackend` from `auths_id::ports::registry`
3. Add a feature flag in `Cargo.toml`
4. Export from `src/lib.rs` behind `#[cfg(feature = "backend-<name>")]`
