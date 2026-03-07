# Auths v0.1.0 Engineering Roadmap

Zero users. No backward compatibility constraints. Break anything, delete anything.

## Priority Order

| # | Epic | What | Blocked by |
|---|------|------|------------|
| 1 | Epic 1 | Wire Rust commit verification into Python | — | DONE
| 2 | Epic 2 | Replace all string-matching error dispatch | — |
| 3 | Epic 3 | Fix known bugs and code violations | — |
| 4 | Epic 4 | Lock down public API surface | — |
| 5 | Epic 5 | Typestate PassphraseProvider | — |
| 6 | Epic 6 | Python wheels for all platforms | — |
| 7 | Epic 7 | Decouple widget from local filesystem | — |
| 8 | Epic 8 | GitHub Action cleanup | — |
| 9 | Epic 9 | Python SDK types | Epics 1, 2 |
| 10 | Epic 10 | UMD bundle for CDN | Epic 7 |
| 11 | Epic 11 | Getting started guide | All above |


## Epic 2 — Structured Error Codes Everywhere

Three places use string matching to classify errors. Replace all of them with `AuthsErrorInfo::error_code()` dispatch.

**Task 2.1** — Add `error_code: Option<String>` to `VerificationResult` in `packages/auths-python/src/types.rs` (currently only has `valid` and `error`). Propagate `e.error_code()` from all FFI error paths in `verify.rs` and `sign.rs`.

```rust
// packages/auths-python/src/types.rs

#[pyclass]
#[derive(Clone)]
pub struct VerificationResult {
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub error: Option<String>,
    #[pyo3(get)]
    pub error_code: Option<String>,
}
```

**Task 2.2** — Delete `_map_verify_error()`, `_map_sign_error()`, and `_map_network_error()` in `_client.py:30-56`. Replace with code-based dispatch. No fallback logic needed — there are no callers relying on the old behavior.

```python
# packages/auths-python/python/auths/_client.py

_ERROR_CODE_MAP = {
    "AUTHS_VERIFICATION_ERROR": ("invalid_signature", VerificationError),
    "AUTHS_MISSING_CAPABILITY": ("missing_capability", VerificationError),
    "AUTHS_CRYPTO_ERROR": ("invalid_key", CryptoError),
    "AUTHS_DID_RESOLUTION_ERROR": ("invalid_key", CryptoError),
    "AUTHS_INVALID_INPUT": ("invalid_signature", VerificationError),
    "AUTHS_SERIALIZATION_ERROR": ("invalid_signature", VerificationError),
    "AUTHS_BUNDLE_EXPIRED": ("expired_attestation", VerificationError),
    "AUTHS_KEY_NOT_FOUND": ("key_not_found", CryptoError),
    "AUTHS_INCORRECT_PASSPHRASE": ("signing_failed", CryptoError),
    "AUTHS_SIGNING_FAILED": ("signing_failed", CryptoError),
}

def _map_error(exc: Exception) -> Exception:
    code = getattr(exc, "error_code", None)
    if code and code in _ERROR_CODE_MAP:
        py_code, cls = _ERROR_CODE_MAP[code]
        return cls(str(exc), code=py_code)
    return VerificationError(str(exc), code="unknown")
```

**Task 2.3** — Fix C FFI string matching in `crates/auths-verifier/src/ffi.rs:206-224` (marked `TECH-DEBT(fn-33)`). Replace substring checks with `e.error_code()` match.

```rust
// crates/auths-verifier/src/ffi.rs

fn attestation_error_to_code(e: &AttestationError) -> i32 {
    match e.error_code() {
        "AUTHS_VERIFICATION_ERROR" => 2,
        "AUTHS_CRYPTO_ERROR" => 3,
        "AUTHS_MISSING_CAPABILITY" => 4,
        "AUTHS_INVALID_INPUT" => 5,
        "AUTHS_SERIALIZATION_ERROR" => 6,
        "AUTHS_BUNDLE_EXPIRED" => 7,
        _ => -1,
    }
}
```

---

## Epic 3 — Bug Fixes and Code Violations

Known bugs that must be fixed before v0.1.0. No epic overlap — these fell through the cracks.

**Task 3.1** — Fix `Utc::now()` violation in `crates/auths-core/src/witness/server.rs:492`. The `submit_event` handler calls `chrono::Utc::now()` directly. Change the function signature to accept `now: DateTime<Utc>` and have the caller inject it.

**Task 3.2** — Replace 7 `anyhow::anyhow!()` calls in `crates/auths-storage/src/git/identity_adapter.rs` (lines 127, 129, 132, 134, 172, 177, 184) with a `StorageError` thiserror enum. Layer 4 crate, `anyhow` is banned.

**Task 3.3** — Fix `__init__.py` import bug. `verify_chain_with_witnesses` is in `__all__` at `packages/auths-python/python/auths/__init__.py:70` but never imported from `_native` (lines 13-29). Add the import if the function exists in the native module, otherwise remove it from `__all__`.

---

## Epic 4 — Seal Public API Surface

Every `pub` symbol in a published crate is a commitment. Clean it up now while there's zero cost to breaking changes.

**Task 4.1** — Make `ports`, `presentation`, and `workflows` modules `pub(crate)` in `crates/auths-sdk/src/lib.rs` (currently `pub` at lines 36, 38, 50). No `#[doc(hidden)]` half-measure — just make them private. The `testing` module is already feature-gated, leave it.

```rust
// crates/auths-sdk/src/lib.rs

pub mod setup;
pub mod device;
pub mod signing;
pub mod keys;
pub mod pairing;
pub mod audit;
pub mod context;
pub mod error;
pub mod result;
pub mod types;

pub(crate) mod ports;
pub(crate) mod presentation;
pub(crate) mod workflows;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
```

**Task 4.2** — Delete `submit_registration()` and `bind_platform_claim()` stubs in `crates/auths-sdk/src/setup.rs:326-382`. Both always return `None`. They're dead code with no callers outside the SDK. Remove them and their call sites in `setup()`.

**Task 4.3** — Add `cargo-public-api` CI step for `auths-sdk`, `auths-verifier`, and `auths-core`. Check the baseline into `docs/public-api/` so API drift shows up in diffs.

---

## Epic 5 — Typestate PassphraseProvider

`NoopPassphraseProvider` at `crates/auths-sdk/src/context.rs:30` fails at runtime. Make it a compile-time error instead.

**Task 5.1** — Add a 7th typestate slot `PP` to `AuthsContextBuilder` (currently has 6 at `context.rs:129-133`). Split into `AuthsSigningContext` and `AuthsReadContext`. Delete `NoopPassphraseProvider` entirely.

```rust
pub type AuthsSigningContext = AuthsContext<HasPassphrase>;
pub type AuthsReadContext = AuthsContext<NoPassphrase>;

pub struct HasPassphrase(Arc<dyn PassphraseProvider + Send + Sync>);
pub struct NoPassphrase;
```

**Task 5.2** — Update CLI factories in `crates/auths-cli/src/factories/` to build the right context type per command. Signing commands get `AuthsSigningContext`, read-only commands get `AuthsReadContext`.

**Task 5.3** — Extract shared `build_ffi_context()` in Python FFI. The same builder block is copy-pasted 6 times across `identity.rs`, `rotation.rs`, `device_ext.rs`, `artifact_sign.rs`, `commit_sign.rs`. One function, 6 call sites.

```rust
// packages/auths-python/src/context_helper.rs

pub fn build_ffi_context(
    repo_path: &str,
    passphrase: Option<&str>,
) -> Result<AuthsContext, anyhow::Error> {
    let (backend, keychain, clock, id_storage, att_storage) = resolve_ffi_deps(repo_path)?;
    let provider = resolve_passphrase(passphrase);
    Ok(AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock)
        .identity_storage(id_storage)
        .attestation_sink(att_storage.clone())
        .attestation_source(att_storage)
        .passphrase_provider(provider)
        .build())
}
```

---

## Epic 6 — Cross-Platform Python Wheels

`pip install auths` must work without a Rust toolchain on macOS (x86_64/arm64), Linux (manylinux), and Windows (amd64).

**Task 6.1** — Add `publish-python.yml` workflow using `maturin-action` to build wheels for all platforms on tagged releases.

```yaml
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        target: [x86_64, aarch64]
        exclude:
          - os: windows-latest
            target: aarch64
    steps:
      - uses: PyO3/maturin-action@v1
        with:
          command: build
          args: --release -m packages/auths-python/Cargo.toml --out dist
          target: ${{ matrix.target }}
```

**Task 6.2** — Add smoke test: install the wheel in a clean venv (no Rust), run `from auths import Auths`, and test the `[jwt]` extra since `PyJWT`/`cryptography` have their own platform build issues.

---

## Epic 7 — Decouple Widget from Local Filesystem

The widget can't be built or published without the exact sibling directory layout. Fix that, plus the build bugs found during review.

**Task 7.1** — Publish `@auths/verifier-wasm` as a standalone npm package from `crates/auths-verifier` WASM build. Add `publish-wasm.yml` CI workflow on tagged releases.

**Task 7.2** — Replace `file:../auths/packages/auths-verifier-ts` devDependency and `build:wasm` script in `auths-verify-widget/package.json` with `"@auths/verifier-wasm": "^0.1.0"`. Delete the `prepublishOnly` hook that references the parent repo.

**Task 7.3** — Fix filename mismatch: `vite.config.ts:44` emits `auths-verify` (no extension), `package.json` expects `auths-verify.mjs`. Change Vite `fileName` to include `.mjs`.

**Task 7.4** — Fix WASM type mismatch: `verifier-bridge.ts:16-20` and `wasm.d.ts:9-10` declare WASM functions as returning `string` but they return `Promise<string>`. Fix the types and add `await` at call sites (lines 69, 92).

---

## Epic 8 — GitHub Action Cleanup

The action works but has several bugs and quality gaps.

**Task 8.1** — Pin `auths-version` default to `'0.1.0'` in `action.yml` (currently `''`). Resolve `github-token` in `main.ts` with `core.getInput('github-token') || process.env.GITHUB_TOKEN` since `action.yml` defaults don't evaluate expressions.

**Task 8.2** — Add PR comment deduplication. Currently `main.ts:132-144` creates a new comment on every run. Search for existing comments with a marker and update instead of creating.

```typescript
const COMMENT_MARKER = '<!-- auths-verify -->';

async function upsertPrComment(octokit, prNumber: number, body: string) {
  const { data: comments } = await octokit.rest.issues.listComments({
    ...github.context.repo,
    issue_number: prNumber,
  });
  const existing = comments.find(c => c.body?.includes(COMMENT_MARKER));
  const markedBody = `${COMMENT_MARKER}\n${body}`;
  if (existing) {
    await octokit.rest.issues.updateComment({ ...github.context.repo, comment_id: existing.id, body: markedBody });
  } else {
    await octokit.rest.issues.createComment({ ...github.context.repo, issue_number: prNumber, body: markedBody });
  }
}
```

**Task 8.3** — Fix license mismatch: `package.json` says MIT, `LICENSE` file is Apache-2.0. Pick one, update both.

**Task 8.4** — Add tests for `classifyError()` in `src/verifier.ts:28-37`. Zero test coverage on the most fragile function in the action.

**Task 8.5** — Add README workflow examples for identity-bundle mode, allowed-signers mode, and PR comment mode.

---

## Epic 9 — Python SDK Types

Polish the Python-facing types. Low risk, do after the FFI plumbing is stable.

**Task 9.1** — Change `verify()`'s `at` parameter from `str | None` to `datetime | None`. Convert to RFC 3339 internally. No deprecation needed.

**Task 9.2** — Fix `AgentIdentityBundle.attestation_json` — it's always `""` for standalone agents (set in FFI `identity.rs:207`). Change to `Optional[str]`, set to `None` instead of empty string.

---

## Epic 10 — UMD Bundle for CDN

Ship a `<script>` tag drop-in. Depends on Epic 7 (widget decoupled).

**Task 10.1** — Add `vite.config.umd.ts` that builds a UMD bundle with inlined WASM. Register `<auths-verify>` custom element on load.

**Task 10.2** — Add `unpkg` and `jsdelivr` fields to `package.json`, add `./umd` export, add `build:umd` script.

---

## Epic 11 — Getting Started Guide

Write last when APIs are stable.

**Task 11.1** — Create `docs/getting-started.md`: install CLI, create identity, sign commit, verify in Python, verify in browser (widget), verify in CI (GitHub Action). Exact commands and expected output. Under 3 minutes end-to-end.
