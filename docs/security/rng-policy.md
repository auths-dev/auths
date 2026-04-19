# RNG Policy

Single source of truth for which random number generators the workspace uses,
which are banned, and why.

## Rule: use `OsRng` or an equivalent syscall-backed RNG

Security-sensitive randomness (key generation, nonces, session IDs, challenge
bytes, one-time secrets) MUST come from the operating system's CSPRNG via one
of the sanctioned wrappers below. Never use userland-only PRNGs (`thread_rng`,
`rand::random`) for anything that feeds a cryptographic operation.

## Sanctioned sources

| Wrapper                                          | Use in                                          | Why sanctioned                                   |
|--------------------------------------------------|-------------------------------------------------|--------------------------------------------------|
| `rand::rngs::OsRng`                              | General-purpose                                 | Reads `getrandom(2)` (Linux) / `/dev/urandom` / `BCryptGenRandom` (Windows) / `SecRandomCopyBytes` (macOS) via the `getrandom` crate. |
| `p256::elliptic_curve::rand_core::OsRng`         | ECDH and ECDSA keygen in `auths-pairing-protocol`, `auths-crypto` | Same backing as above but re-exported through the `p256` crate for ergonomic composability with its keygen APIs. |
| `ring::rand::SystemRandom`                       | Ring-backed daemon bearer tokens (`auths-pairing-daemon`) | ring's own wrapper around the same syscalls. Permitted because ring itself is the sanctioned crypto boundary for the daemon. |
| `aws_lc_rs::rand::SystemRandom`                  | `auths-crypto::aws_lc_provider` under `--features fips` | aws-lc-rs's wrapper; FIPS-validated source inside the FIPS build. |

Any new code that needs randomness MUST use one of these. Adding a new
sanctioned wrapper requires a review + an update to this document and to
`clippy.toml` (both workspace and per-crate copies).

## Banned methods

Enforced by `clippy::disallowed_methods` in workspace `clippy.toml` and all
6 per-crate `clippy.toml` copies (sync checked by `xtask check-clippy-sync`):

| Path                      | Why banned                                       |
|---------------------------|--------------------------------------------------|
| `rand::thread_rng`        | Can delegate to a non-syscall-backed RNG depending on feature resolution; the "thread-local" ergonomic hides the source. |
| `rand::random`            | Trampolines to `thread_rng` internally. Same hazard. |
| `rand::rngs::ThreadRng`   | The type itself — stops anyone from constructing one via an alternate path. |

## Banned for a specific reason — don't add back with a carve-out

The failure mode the ban prevents is silent correctness. A crate that uses
`thread_rng()` compiles, tests pass, and keys are generated; only an audit or
a real-world incident reveals the RNG was not syscall-backed. There is no
run-time symptom. The only reliable defence is to ban the API.

If you need a test-only RNG for determinism, use a named PRNG explicitly
seeded for the test (e.g. `rand_chacha::ChaCha8Rng::seed_from_u64(…)` with an
`#[cfg(test)]`-scoped import and a `#[allow(clippy::disallowed_methods)]`
annotated with `INVARIANT:`). Do NOT lift the ban on production code.

## Test-code carve-out

`#[cfg(test)]` blocks may use `thread_rng` if the test does not produce key
material. Rationale: test-only randomness that never crosses a crypto API
boundary is out of scope for the hazard. The xtask scanner checks for test
attribution before flagging.

## Atomic-rollout note

The `sas.rs:98` migration from `rand::random()` to `OsRng` and the clippy
`disallowed_methods` entries MUST land in the same commit. Any other
ordering leaves main red.

## Startup health probe (fn-128.T7)

The pairing daemon refuses to start if the OS CSPRNG fails a lightweight
health check:

- **Linux CRNG-init:** `rand::rngs::OsRng` reads from `getrandom(2)` in
  blocking mode via the `getrandom` crate, which blocks until the kernel
  pool is seeded. If the syscall returns bytes, the kernel has seeded.
- **Cross-platform statistical baseline:** 4 KiB sampled from `OsRng`, run
  through NIST SP 800-90B §4 Repetition Count Test (RCT) and Adaptive
  Proportion Test (APT). Cutoffs set conservatively (RCT=4, APT=51 of 512)
  so false-positives on well-behaved OS RNGs are negligible.

Probe code: `crates/auths-pairing-daemon/src/entropy_probe.rs`. Runs before
any socket bind in `PairingDaemonBuilder::build`. Failure returns
`DaemonError::EntropyCheckFailed(msg)` and propagates out of the builder.
Service managers surface the non-zero exit code.

Tests:
- `real_os_rng_passes_health_check` — production path.
- `all_zero_stream_fails_rct` — crafted RNG fails on first repeated byte.
- `biased_stream_fails_apt` — crafted RNG with ~75% zeros fails APT.
- `uniform_counter_passes_baseline` — 0x00..0xFF cycle passes.

The probe does NOT run continuously during normal operation — startup only.
NIST 90B continuous health tests over long-running sessions are out of
scope per the hardening plan.

## References

- Workspace `clippy.toml` (disallowed-methods + disallowed-types).
- `crates/xtask/src/check_clippy_sync.rs` — enforces sync with per-crate copies.
- `crates/auths-pairing-protocol/src/sas.rs:98` — the one remaining
  `rand::random()` call site, fixed in fn-128.T6.
- `crates/auths-pairing-daemon/src/entropy_probe.rs` — startup health check.
- NIST SP 800-90A Rev. 1 — DRBG recommendations.
- NIST SP 800-90B §4 — entropy source validation + RCT / APT definitions.
- Debian BoottimeEntropyStarvation — https://wiki.debian.org/BoottimeEntropyStarvation
- Cornell "Not-So-Random Numbers in Virtualized Linux" — https://rist.tech.cornell.edu/papers/vmrng.pdf
