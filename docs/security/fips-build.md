# FIPS 140-3 Build (`--features fips`)

Guide for building, testing, and releasing `auths` binaries that route every
cryptographic primitive through a FIPS 140-3 validated module.

**Status:** implementation landed in fn-128.T3 (CryptoProvider trait impl).
Paperwork track (CMVP submission / module boundary docs) is separate and
tracked outside this epic.

---

## What "FIPS build" means here

- Every sign/verify/KDF/AEAD/HMAC call routes through `aws-lc-rs 1.16+` with its
  `fips` feature enabled, which pulls in `aws-lc-fips-sys` — the AWS-LC build
  that carries the validated FIPS 140-3 certificate (CMVP certificate #4816 for
  AWS-LC-FIPS 2.0 / #4850 for 3.0, covering ML-KEM).
- Provider swap is compile-time only. No runtime selection.
- Default build (RustCrypto + ring) is unaffected.
- `--features fips` is mutually exclusive with `--features cnsa` and with
  `target_arch = "wasm32"`. Both are enforced by `compile_error!` guards at
  `crates/auths-crypto/src/provider.rs`.

## Toolchain requirements

`aws-lc-fips-sys` builds AWS-LC from source. You need:

| Tool    | Min version | macOS install                   | Linux install                     |
|---------|-------------|---------------------------------|-----------------------------------|
| CMake   | 3.6         | `brew install cmake`            | `apt install cmake` / `dnf`       |
| Go      | 1.18        | `brew install go`               | `apt install golang-go` / `dnf`   |
| Clang/C | any modern  | Xcode command-line tools        | `apt install clang build-essential` |
| Perl    | 5.10        | bundled                         | `apt install perl`                |
| Rust    | 1.71 (MSRV of aws-lc-rs ≤ workspace 1.93) | `rustup install 1.93` | same |

Verify with:

```bash
cmake --version
go version
clang --version
rustc --version
```

## Local build

```bash
# From the auths/ workspace root
cargo build --workspace --features fips
cargo nextest run --workspace --features fips
cargo clippy --workspace --features fips --all-targets -- -D warnings
```

Expected first-time build duration: 4–8 minutes on modern hardware — AWS-LC
compiles ~1.2M lines of C under CMake. Subsequent builds hit ccache and
take seconds.

## Verifying the swap actually happened

Two checks prove the `fips` feature is live:

1. **Dep graph:** `cargo tree --features fips | rg aws-lc-fips-sys` should
   show `aws-lc-fips-sys` as a transitive dep. If it is absent, the feature
   did not activate.
2. **KAT parity:** run the KAT suite under both builds and diff.
   ```bash
   cargo nextest run -p auths-crypto --test integration 'cases::kat::' \
     --message-format json > /tmp/kat-default.json
   cargo nextest run -p auths-crypto --test integration --features fips 'cases::kat::' \
     --message-format json > /tmp/kat-fips.json
   # Deterministic paths (Ed25519 sign, ECDSA-P256 RFC 6979, HKDF, HMAC)
   # MUST produce byte-identical outputs. AEAD round-trip must succeed
   # under both.
   ```

If a deterministic KAT produces different output under `fips`, the swap has
introduced behaviour that is not byte-compatible with the default provider
— block release and investigate before the divergence reaches a signed KEL
or attestation.

## Feature-combination guards

```rust
#[cfg(all(feature = "fips", feature = "cnsa"))]
compile_error!("features fips and cnsa are mutually exclusive.");

#[cfg(all(feature = "fips", target_arch = "wasm32"))]
compile_error!("feature fips is incompatible with target_arch = wasm32.");
```

The WASM carve-out matters: the browser verifier (`auths-verifier`) must
still build as `cargo build --target wasm32-unknown-unknown --no-default-features`
even in a workspace that has otherwise selected `fips`. `aws-lc-rs` has no
WASM target; the verifier stays on pure-Rust RustCrypto regardless of
workspace-level feature selection.

## CI integration

**Not yet landed.** When added, the workflow must:

1. Install CMake + Go before the `cargo build` step.
2. Run the full workspace build and test suite with `--features fips`.
3. Run the KAT parity check above against the default build.
4. Matrix: `ubuntu-latest` + `macos-latest`. Windows is a soft-follow —
   aws-lc-fips-sys supports it but needs MSVC + Strawberry Perl and the build
   is finicky; revisit once we have a first enterprise FIPS customer.

Suggested workflow skeleton (follow-up task):

```yaml
# .github/workflows/ci-fips.yml
name: FIPS build
on: [pull_request]
jobs:
  fips:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.93
      - name: Install CMake + Go (Ubuntu)
        if: matrix.os == 'ubuntu-latest'
        run: sudo apt-get update && sudo apt-get install -y cmake golang-go clang
      - name: Install CMake + Go (macOS)
        if: matrix.os == 'macos-latest'
        run: brew install cmake go
      - run: cargo build --workspace --features fips
      - run: cargo nextest run --workspace --features fips
      - run: cargo clippy --workspace --features fips --all-targets -- -D warnings
```

## Residual risks (accepted)

- **FIPS paperwork is separate.** This document + build produce a binary
  that *uses* a validated module. The binary itself is not CMVP-certified —
  that is an end-to-end audit + documentation effort, not a code change.
- **P-256 keygen and PKCS8 parse go through RustCrypto (`p256` crate) even
  under `fips`.** aws-lc-rs's ECDSA signer consumes PKCS8, not raw 32-byte
  scalars, so we parse via `p256` and sign via `aws-lc-rs`. The scalar
  extraction is deterministic and the subsequent signing is FIPS-validated.
  Document this to any auditor reviewing the module boundary.
- **`aws-lc-rs` MSRV** (1.71) is below the workspace `rust-toolchain.toml`
  (1.93). We pin `aws-lc-rs = "1.16"` to ensure this remains true — bumping
  is gated by re-running the KATs under both builds.

## References

- `crates/auths-crypto/src/aws_lc_provider.rs` — the provider impl.
- `crates/auths-crypto/src/provider.rs` — feature guards + `default_provider()`.
- `crates/auths-crypto/tests/cases/kat.rs` — Known-Answer Tests.
- [aws-lc-rs docs](https://docs.rs/aws-lc-rs/)
- [AWS-LC-FIPS 3.0 announcement](https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-be-validated-to-fips-140-3-level-1-with-ml-kem/)
- [NIST FIPS 140-3 transition](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/standards)
