# fn-6.1 Re-export Did and DidError from auths-radicle

## Description

Add `pub use radicle_core::identity::{Did, DidError};` to the std-only re-exports section of `crates/auths-radicle/src/lib.rs`. This lets httpd use `auths_radicle::Did` without directly depending on radicle_core.

### Key files
- `crates/auths-radicle/src/lib.rs` — re-export site

## Acceptance
- [x] `auths_radicle::Did` resolves to `radicle_core::identity::Did`
- [x] `auths_radicle::DidError` resolves to `radicle_core::identity::DidError`
- [x] `cargo build -p auths-radicle` compiles
