# Auths — Enterprise / Commercial tier (`ee/`)

Crates in this directory are **source-available but not open source**. They are licensed
separately from the Apache-2.0 crates under [`../crates`](../crates) and are **not** part of the
open-source product.

- **License:** `LicenseRef-Proprietary` (see [`LICENSE`](./LICENSE)). Not redistributable under
  Apache-2.0.
- **Build:** `ee/` is its own Cargo workspace. The root workspace excludes it
  (`exclude = ["ee"]`), so `cargo build --workspace` at the repo root never compiles or ships
  these crates. Build them explicitly with `cargo build --manifest-path ee/Cargo.toml`.
- **Publishing:** every crate here sets `publish = false`.

## Crates

| Crate | Purpose |
|-------|---------|
| `auths-idp` | Enterprise IdP verification — OIDC/SAML identity binding (the "log in with your company IdP" verifier). |
