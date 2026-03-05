# fn-6.3 Swap Did import in radicle-httpd identity.rs

## Description

Replace `use radicle::identity::Did` with `use auths_radicle::Did` in `radicle-httpd/src/api/v1/identity.rs`. Functions `resolve_kel` and `list_devices` already expect `radicle_core::Did`, so types align after the swap.

### Key files
- `radicle-httpd/src/api/v1/identity.rs`

## Acceptance
- [x] `use auths_radicle::Did` replaces `use radicle::identity::Did`
- [x] `resolver.resolve_kel(&did)` and `storage.list_devices(&did)` type-check
