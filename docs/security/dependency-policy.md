# Dependency Policy

Rules for introducing, updating, and removing third-party Rust dependencies
in the `auths/` workspace. Especially strict for cryptographic crates.

## Exact-pinning (fn-128.T9)

Every crate whose output format is normative — i.e., whose minor-version
bump could change DER encoding, signature layout, AEAD overhead, or hash
output — is **exact-pinned** with `=x.y.z` in `[workspace.dependencies]`.

Currently exact-pinned:

| Crate                | Version  | Why exact-pin                                                          |
|----------------------|----------|------------------------------------------------------------------------|
| `ring`               | `0.17.14`| Ed25519 + ECDH + verification primitives.                              |
| `subtle`             | `2.6.1`  | Constant-time comparison; API + guarantees.                            |
| `zeroize`            | `1.8.2`  | `ZeroizeOnDrop` trait bound — derive behaviour must be stable.        |
| `sha2`               | `0.10.9` | Hash output is load-bearing for every signature.                       |
| `hkdf`               | `0.12.4` | KDF output byte-identical across bumps required for derived keys.     |
| `hmac`               | `0.12.1` | MAC tag format must stay stable.                                       |
| `chacha20poly1305`   | `0.10.1` | AEAD ciphertext format; tag length; nonce interpretation.              |
| `aes-gcm`            | `0.10.3` | Same — CNSA AEAD.                                                      |
| `json-canon`         | `0.1.3`  | Canonical JSON encoding. Pinned pre-fn-128.                            |

Not pinned (semver caret is fine): `tokio`, `serde`, `reqwest`, `axum`, and
general-purpose utility crates. Output format of these is not normative.

## Bump procedure

1. Edit the pin in `auths/Cargo.toml` `[workspace.dependencies]`.
2. Run the full KAT suite under both default and `--features fips` builds:
   ```bash
   cargo nextest run -p auths-crypto --test integration 'cases::kat::'
   cargo nextest run -p auths-crypto --test integration --features fips 'cases::kat::'
   ```
   Deterministic KATs (Ed25519 sign, ECDSA-P256 RFC 6979, HKDF, HMAC) MUST
   produce byte-identical outputs across default and FIPS. If they diverge,
   the bump has changed output format — block the bump and investigate.
3. Run `cargo deny check`.
4. Run `cargo tree -d --workspace` and confirm no duplicate versions of the
   pinned crate appear.
5. Update this document's table if the version changed.
6. Commit with a message prefixed `crypto-bump:` so release reviewers see it.

## cargo-deny (`deny.toml`)

Checked by `cargo deny check` in CI:

- **`[advisories]`** — fail on any RUSTSEC advisory that isn't in the
  ignore list (each ignore requires a comment explaining why — e.g.
  transitive-only, not exploitable, awaiting upstream fix).
- **`[bans]`** — `multiple-versions = "warn"` globally; per-crate
  architectural bans enforce SDK/adapter boundaries (e.g. `git2` stays in
  storage/adapter layer; `axum` out of core).
- **`[licenses]`** — allowlist: Apache-2.0, MIT, ISC, BSD-{2,3}-Clause,
  Unicode-3.0 / DFS-2016, MPL-2.0, Zlib, CDLA-Permissive-2.0, OpenSSL,
  CC0-1.0. GPL variants are denied by omission; GPL-licensed crates require
  a documented exception.
- **`[sources]`** — `unknown-registry = "deny"` (only crates.io);
  `unknown-git = "deny"`. Adding a git dep requires updating the allowlist
  with a rationale.

## Duplicate-version check (`cargo tree -d`)

CI also runs:

```bash
cargo tree -d --workspace --edges=normal
```

If any of the exact-pinned crates above appears twice in the resolved
graph, CI fails. This catches transitive bumps that would otherwise slip
past the `=x.y.z` pin (because the transitive resolver can still pick a
newer minor when the ecosystem cascades).

## Adding a new dependency

- Non-crypto: no formal review beyond the standard PR process.
- Crypto: requires (a) justification in the PR body, (b) addition to this
  document's table if it produces wire-format output, and (c) sign-off
  from the security lead.

## References

- `auths/Cargo.toml` `[workspace.dependencies]` — canonical pin list.
- `auths/deny.toml` — cargo-deny config.
- `docs/security/primitive-inventory.md` — fn-128.T1 inventory.
- `docs/security/fips-build.md` — FIPS build instructions + KAT parity check.
- [cargo-deny book](https://embarkstudios.github.io/cargo-deny/)
- [RustSec advisory database](https://rustsec.org/)
