# Dual Did Type Bridge for Live Network Migration

## Overview

Bridge the incompatible `Did` types between published `radicle` (v0.21.0, `struct Did(PublicKey)`, did:key only) and local `radicle_core` (`enum Did { Key, Keri }`, both formats) so that radicle-httpd compiles and supports both `did:key` and `did:keri` URL paths.

## Strategy

`auths-radicle` re-exports `radicle_core::Did` so httpd uses it for path extraction (enabling both did:key and did:keri URLs). Where httpd still interacts with published radicle APIs (e.g., `repo.doc.delegates()`), we use string-based comparison since the inner `PublicKey` types come from different radicle-crypto compilations.

This is explicitly temporary — long-term fix is publishing a new radicle version with the enum Did.

## Scope

### In Scope
- Re-export `Did` and `DidError` from `auths-radicle`
- Swap `radicle::identity::Did` import to `auths_radicle::Did` in radicle-httpd delegates.rs and identity.rs
- String-based bridge for `repo.doc.delegates()` filtering
- Roundtrip tests proving string equivalence between Did types

### Out of Scope
- Publishing a new radicle version with enum Did
- Modifying published radicle crate
- KERI delegate support in repo documents

## Key Files

| File | Role |
|------|------|
| `crates/auths-radicle/src/lib.rs` | Re-export site |
| `radicle-httpd/src/api/v1/delegates.rs` | Main fix — Did import swap + string bridge |
| `radicle-httpd/src/api/v1/identity.rs` | Did import swap |
| `heartwood/crates/radicle-core/src/identity.rs` | Source of truth for enum Did |

## Risks

- **String comparison bridge**: Temporary; works because both types serialize `did:key:z6Mk...` identically
- **repo.doc.delegates() type mismatch**: Published radicle returns `radicle::identity::Did` which cannot contain `did:keri`. Correct — existing repos only have `did:key` delegates
- **Serde compat**: `radicle_core::Did` has `#[serde(into = "String", try_from = "String")]` so JSON serialization is identical. No API breaking change.
