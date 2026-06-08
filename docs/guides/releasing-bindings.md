# Releasing the language bindings (Node / Python / Go)

The keyless verifier ships to three ecosystems. Each release builds **per platform** (not per
language version) so the matrix stays small: Python collapses interpreter versions with **abi3**,
Node collapses install resolution with **optionalDependencies**, Go ships a cgo cdylib.

| Binding | Package | Workflow | Matrix axis |
| --- | --- | --- | --- |
| Node | `@auths-dev/sdk` (`packages/auths-node`) | `publish-node.yml` | platform (`os`/`cpu`) prebuilt `.node` |
| Python | `auths` (`packages/auths-python`) | `publish-python.yml` | platform, abi3 wheels (glibc + musl) |
| Go | `auths-verifier-go` | `release-go.yml` | platform prebuilt cdylib (cgo) |

## One source of truth

- **Version** comes from the workspace `Cargo.toml` (`[workspace.package].version`). The Node
  `package.json`, the Python `pyproject.toml`, and any Go release tag derive from it at release
  time — never hand-edit a binding version out of band.
- **Generated type artifacts** are produced from the Rust source, never hand-written:
  - Node `.d.ts` — emitted by `napi build` (`packages/auths-node/index.d.ts`).
  - Python `.pyi` — `packages/auths-python/python/auths/__init__.pyi` (kept in lockstep with the pyo3 surface).
  - Branded TS verdict union — `crates/auths-verifier/ts/verdict.ts` (mirrors `contract.rs`; the
    `exhaustiveness.ts` never-arm guard fails the build if a `kind` drifts).
  - C header for the cgo / FFI surface — the declarations in `packages/auths-verifier-go/verifier.go`
    track `crates/auths-verifier/src/ffi.rs`.

  CI fails if a regenerated artifact differs from the committed one (no silent drift). Same tag →
  same artifacts (reproducible: pinned toolchain `1.93`, pinned manylinux image).

## Node — optionalDependencies lockfile pitfall

`napi prepublish` publishes one tiny platform package per `(os, cpu)` and lists them all under the
main package's `optionalDependencies`. npm installs only the one matching the host. **The pitfall:**
a lockfile generated on one platform can omit the other platforms' optional deps, so `npm ci` on a
*different* platform (or in a multi-arch Docker build) fails to find its binary.

Mitigation:
- Prefer **pnpm** or **Yarn** with `supportedArchitectures` so the lockfile records every platform:
  ```jsonc
  // .npmrc (pnpm) — or package.json "installConfig"
  // pnpm: supportedArchitectures.os = ["current", "linux", "darwin", "win32"]
  //       supportedArchitectures.cpu = ["current", "x64", "arm64"]
  ```
- For npm, commit the lockfile generated with `--force` on a runner that pulls every optional dep,
  or build platform images on native runners.

## Python — abi3 + glibc/musl

Wheels are **abi3** (`cp3x-abi3-*`), so one wheel per platform serves every supported CPython. The
matrix builds glibc on a **pinned `manylinux_2_28`** image (the older baselines retired after
2025-05-06) and **musllinux_1_2** for Alpine/static-libc consumers. The dry-run publishes to
TestPyPI (`workflow_dispatch` → `testpypi`).

## Go — cgo toolchain required

The Go module links the `auths-verifier` cdylib via cgo. **`CGO_ENABLED=1` and a C toolchain are
required** — a `CGO_ENABLED=0` (static-Go / distroless) build cannot use it. `release-go.yml`
builds the cdylib `--features ffi` per platform, runs `go test ./...` against it, and bundles the
prebuilt libs. Consumers either run `packages/auths-verifier-go/build.sh` or link a bundled
prebuilt lib (see that package's README).
