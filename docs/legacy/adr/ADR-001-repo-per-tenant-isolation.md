# ADR-001: Repo-per-tenant isolation for multi-tenant SaaS registry

## Status

Accepted — 2026-02-21

---

## Context

The Auths registry server (`auths-registry-server`) uses `PackedRegistryBackend` as its storage layer. In single-tenant mode the backend is backed by one Git repository (e.g. `~/.auths`) with one `refs/auths/registry` ref.

For the multi-tenant SaaS offering, multiple independent customers need isolated identity and attestation storage. Two isolation strategies were considered:

**Option A — ref-based namespacing** inside a shared repository

Each tenant's data lives under a unique ref prefix within one repo:
- `refs/auths/tenants/acme/registry`
- `refs/auths/tenants/beta/registry`
- ...

All tenants share one `.git` object store, one pack file, and one Git lock file.

**Option B — one Git repository per tenant** (selected)

Each tenant gets an independent repo:
- `~/.auths-saas/tenants/acme/.git`
- `~/.auths-saas/tenants/beta/.git`
- ...

No shared object store, no shared lock files.

---

## Decision

**Option B** (one Git repo per tenant) was selected.

### Why Option A was rejected

The concern is not a Git correctness bug — Git correctly scopes reads to the requested ref. The concern is **operational blast radius**:

- A bad ref-deletion query (e.g., `delete_refs_matching("refs/auths/tenants/*")`) affects all tenants simultaneously in a shared repo. With Option B the worst-case blast radius of such a bug is one tenant's directory.
- **Backup and restore** are harder: you must filter by ref prefix. With Option B, backup = `cp -a tenants/acme`; restore = `cp -a`.
- **Per-tenant migration and disposal** require understanding the full shared object graph rather than simply moving or deleting a directory.
- **Disaster recovery** of one tenant requires reasoning about the entire repo's ref graph rather than replacing a single directory.
- **Incident isolation** (e.g., suspending a compromised tenant) cannot be done with OS-level tools on a shared repo; it requires application-level enforcement for every read path.

### Why Option B was chosen

- Backup = `cp -a tenants/acme`. Restore = `cp -a`. Migrate = `mv`. Incident isolate = `chmod 000 tenants/acme`.
- **Zero changes to `shard.rs` and `REGISTRY_REF`** — isolation is at the repo boundary, not inside the Git tree or ref namespace. The existing storage implementation required no modification.
- OS-level permission controls (directory permissions, ACLs) are available per tenant with no application-layer enforcement.
- Each tenant's repo is independently cloneable, backupable, replicatable, and disposable.
- Existing single-tenant users see no code path changes — `SingleTenantResolver` wraps the existing backend unchanged.

---

## Architecture decision summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| `TenantResolver` return type | `Arc<PackedRegistryBackend>` | Avoids per-request Git repo open; enables bounded LRU caching in adapters without changing the trait signature |
| Tenancy configuration | `TenancyMode` enum (`Single` / `Multi`) | Compile-time exhaustiveness; impossible to accidentally mix modes; startup validation is straightforward |
| Port error type | `RegistryError` (not `ApiError`) | Domain purity: `auths-id` must not depend on `axum` or `http`. Error mapping to HTTP semantics is the extractor's job, not the port's |
| Axum extractor split | `TenantBackend` + `DefaultBackend` | Handlers are tenancy-agnostic; the extractor type in the signature makes the tenancy context explicit; single place for `RegistryError → ApiError` mapping |
| `TenantIdError` | Enum with structured variants (`InvalidLength(usize)`, `InvalidCharacter(char)`, `Reserved(String)`) | Programmatic error handling; `InvalidCharacter(char)` points at the exact offending character; no stringly-typed reasons |
| Tenant ID casing | Normalize to lowercase at `RegistryConfig::for_tenant` | Avoids FS case-sensitivity ambiguity (macOS, some NFS mounts); canonical form simplifies logs, billing, and ops tooling |
| Reserved names | `admin`, `health`, `metrics` | Reserved only if they collide with current or planned API route segments; canonical list lives in `RESERVED_TENANT_IDS` in `validate_tenant_id` |
| `tenant.json` | Written alongside `.git`; owned by `auths-id` | Part of registry storage format; decouples tenant metadata from Git internals; supports future `status`/`plan`/`billing` fields without schema migration |
| LRU cache | `moka::sync::Cache` with configurable `max_capacity` | Battle-tested concurrent cache; bounded eviction without hand-rolled locking; supports TTL if needed later |
| Symlink hardening | Canonicalize `tenants_root` (not the tenant path), then append validated `tenant_id` | `canonicalize` on a non-existent path fails; this approach is safe even before the tenant directory is created |

---

## Consequences

### Positive

- Tenant isolation is provably correct at the OS level — no shared Git objects, no shared lock files.
- Adding a new tenant = creating a directory (no schema migration, no ref renaming).
- Each tenant's repo is independently cloneable, backupable, replicatable, and disposable.
- Existing single-tenant deployments are unaffected (same code path via `SingleTenantResolver`).
- OS-level access controls (permissions, quotas, ACLs) apply per-tenant without application support.

### Negative / trade-offs

- More directories for operators to manage at scale (mitigated by tooling and monitoring).
- `moka` cache has no TTL by default — a suspended tenant continues to be served from cache until the process restarts or `FilesystemTenantResolver::invalidate()` is called explicitly. Fix deferred; use `invalidate()` for now.
- Each tenant holds open file descriptors for its Git lock file and pack index — high tenant count means proportionally higher FD usage. Monitor with `ulimit -n` and set an appropriate system limit.

---

## Alternatives not taken

- **Subdomain routing** (`acme.registry.auths.io`): cleaner UX for tenants, but requires wildcard DNS and TLS certificate provisioning — out of scope for this epic. Can be layered on top of the current path-based routing later.
- **Database-backed tenant registry**: adds a relational database dependency for what is currently a pure-filesystem concern. Deferred unless operational requirements change (e.g., need for cross-tenant queries, soft deletes, or billing integration).
- **Option A (ref-based namespacing)**: explicitly rejected — see §Context above.

---

## Security notes

- `validate_tenant_id` runs before any filesystem access, enforcing a strict `[a-z0-9_-]` allowlist that makes path traversal unexpressible. See `RESERVED_TENANT_IDS` for the reserved name list.
- `canonicalize(tenants_root)` + `starts_with` check in `FilesystemTenantResolver::open_tenant` provides defense-in-depth against post-provisioning symlink attacks (e.g., a symlink installed under `tenants/acme` after provisioning).
- Admin token is compared with `constant_time_eq` to prevent timing side-channels.
- Operators **must** set mode `0700` on the `tenants/` root directory. The server warns at startup if Unix permissions are wider than `0700`.
