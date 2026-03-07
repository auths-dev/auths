# Roadmap Review

## Overall Assessment

The roadmap is **well-grounded** — every epic addresses a real problem confirmed in the code. The task decomposition is unusually concrete for a planning doc, with code snippets that reference actual file paths and line ranges. That said, there are observations on prioritization, gaps, and a few technical concerns.

---

## Per-Epic Analysis

### Epic 1 (Native Commit Verification)

Strong. This is the highest-leverage change. The Python `git.py` currently subprocess-shells to `ssh-keygen` with temp file I/O for `.sig` and `.dat` files — slow and brittle. The `auths-verifier` crate already has Ed25519 primitives, so adding SSHSIG parsing is a natural extension. One concern: Task-1.2's `CommitVerificationResult` has `valid: bool` + `error: Option<String>` — this repeats the anti-pattern Epic 2 is trying to fix. Use a `Result<VerifiedCommit, CommitVerificationError>` instead, with a typed error enum.

### Epic 2 (Structured FFI Error Codes)

Correct diagnosis. The string-matching pattern in `_client.py` is confirmed fragile, and the same issue exists in the verifier's FFI layer (`auths-verifier/src/ffi.rs:202-224`, marked `TECH-DEBT(fn-33)`). One gap: the roadmap only addresses the Python side but doesn't mention fixing the C FFI in `auths-verifier/src/ffi.rs`, which has the same string-matching problem. Consider adding a Task-2.4 for that.

### Epic 3 (Pythonic Types)

Low risk, high polish. The `at` parameter change from `str` to `datetime` is clean. Task-3.2 (dataclass audit) is mostly already done — `Identity` and `Device` are dataclasses, but `AgentIdentityBundle` has an issue: its `attestation_json` field is always empty string for standalone agents (confirmed in `identity.rs:207`). Should be `Option<str>` / `None`.

### Epic 4 (Typestate PassphraseProvider)

Architecturally elegant and consistent with the existing 6-slot typestate builder. This is the kind of compile-time safety that justifies Rust. The code snippets are accurate — `AuthsContextBuilder` already has the pattern. Worth noting: the Python FFI layer (`identity.rs`, `rotation.rs`, etc.) duplicates `AuthsContext` construction in 5 modules. A shared builder helper should be part of this epic.

### Epic 5 (Seal Public API)

Essential for v0.1.0. The `ports`, `presentation`, and `workflows` modules being public is confirmed. The `testing` module is already behind `#[cfg(any(test, feature = "test-utils"))]` in practice, but `ports` and `workflows` are not `#[doc(hidden)]` yet. Good task.

### Epic 6 (Decouple Widget)

Critical. The `file:../auths/packages/auths-verifier-ts` dependency is confirmed, as is the `cd ../auths/crates/auths-verifier && wasm-pack build` script. Both break in any CI or contributor setup without the exact sibling directory structure. One addition: the widget commits both `wasm/` and `dist/` to git — the roadmap should address whether those committed artifacts remain after the npm package is published.

### Epic 7 (Action Binary Pinning)

Good. The empty default for `auths-version` is confirmed. However, the roadmap's `default: ${{ github.token }}` for `github-token` won't work — `action.yml` defaults don't evaluate expressions. You'd need to resolve this in `main.ts` with `core.getInput('github-token') || process.env.GITHUB_TOKEN`. Also, several additional issues surfaced in the action that aren't covered:

- `classifyError()` uses string matching (same anti-pattern as Epic 2) — no structured error types from the CLI's `--json` output
- PR comments pile up with no deduplication/update logic
- License mismatch: `package.json` says MIT, `LICENSE` file is Apache-2.0
- `classifyError` has zero test coverage

### Epic 8 (Cross-Platform Wheels)

Correct and necessary. The `maturin-action` matrix is well-specified. One note: the `auths-python` crate is a standalone workspace (not part of the main workspace), so the `-m packages/auths-python/Cargo.toml` path in the snippet is correct. The smoke test in Task-8.2 should also test the `[jwt]` optional extra since it pulls in `PyJWT` and `cryptography` (which has its own platform build complexities).

### Epic 9 (UMD Bundle)

Nice to have for CDN adoption. The inline WASM pattern already works for the ESM full bundle (~615KB). A UMD variant is straightforward with Vite's library mode. One concern: the widget has a filename mismatch (package.json says `.mjs`, Vite emits without extension, CI checks for `.js`) — fix this before adding another build target.

### Epic 10 (Getting Started Guide)

Good for launch. The snippets are clean and realistic. Consider adding a "Verify in a browser" section using the `<auths-verify>` widget since that's an impressive zero-install demo.

---

## What's Missing

1. **The `Utc::now()` violation in `auths-core/src/witness/server.rs:492`** — Production code calling `Utc::now()` directly, violating the clock injection rule. Not covered by any epic.

2. **`anyhow` in `auths-storage/src/git/identity_adapter.rs`** — This Layer 4 crate uses `anyhow::anyhow!()` where it should use `thiserror`. The `CLAUDE.md` rule is explicit. Not covered.

3. **Python `__init__.py` import bug** — `verify_chain_with_witnesses` is in `__all__` but not imported at the top level. `from auths import verify_chain_with_witnesses` raises `NameError`. This is a real bug that should be fixed before v0.1.0.

4. **`AuthsContext` duplication in Python FFI** — The same 15-20 line context construction block is copy-pasted across 5 Rust modules (`identity.rs`, `rotation.rs`, `device_ext.rs`, `artifact_sign.rs`, `commit_sign.rs`). Epic 4 is a natural place to address this.

5. **Widget WASM type mismatch** — `verifier-bridge.ts` declares WASM functions as synchronous (`string` return), but the actual wasm-pack output returns `Promise<string>`. Latent type-safety gap.

6. **Action `classifyError` has no tests** — The most fragile function in the action codebase has zero test coverage.

7. **`submit_registration` and `bind_platform_claim` in `auths-sdk/src/setup.rs` are stubs** — Both always return `None`. If v0.1.0 is supposed to support registry registration or platform OIDC claims, these need implementation. If not, they should be removed or clearly documented as future work.

---

## Suggested Priority Order

The roadmap doesn't specify ordering. Suggested sequence:

| Priority | Epic | Rationale |
|----------|------|-----------|
| 1 | Epic 1 | Highest user-facing impact — eliminates `ssh-keygen` subprocess dependency |
| 2 | Epic 2 | Fixes fragility that Epic 1 would otherwise inherit |
| 3 | Epic 5 | Must happen before any published crate — API stability commitment |
| 4 | Epic 8 | Blocks Python SDK distribution — no users without wheels |
| 5 | Epic 6 | Blocks widget distribution — can't publish without decoupled WASM |
| 6 | Epic 4 | Correctness improvement, can be done in parallel |
| 7 | Epic 7 | Action polish, lower urgency |
| 8 | Epic 3 | Python DX polish, low risk |
| 9 | Epic 9 | Nice to have, extends Epic 6 |
| 10 | Epic 10 | Write last when the APIs are stable |

---

## Summary

The roadmap is solid engineering work — concrete, well-scoped, and grounded in real code. The main gaps are: a few known bugs not covered by any epic (the `__init__.py` import, the `Utc::now()` violation, the `anyhow` in storage), the action's string-matching fragility mirroring Epic 2's problem, and some stub functions in the SDK that need a decision (ship or remove). The priority ordering matters — Epics 1, 2, 5, and 8 are gate-keeping v0.1.0 and should be sequenced first.
