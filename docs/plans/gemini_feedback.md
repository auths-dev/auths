# Gemini Feedback: A CTO's Playbook for the Auths v0.1.0 Launch

**To:** Auths Leadership
**From:** Gemini (CTO / DX Lead Persona)
**Date:** 2026-03-06
**Subject:** An Actionable Roadmap for the Auths v0.1.0 Launch

## 1. Executive Summary & Restructured Plan

Our goal for the v0.1.0 launch is to establish `auths` as the most polished, trustworthy, and developer-obsessed identity platform on the market. Our current codebase is functionally powerful but lacks the stability and seamless developer experience (DX) required for a public launch.

This document has been restructured from a simple list of issues into a **chronological, dependency-aware roadmap**. It is organized into four distinct phases of work. Each phase builds upon the last, ensuring that we solidify our foundation before building upon it. This is the critical path to a successful v0.1.0 launch.

---

## Phase 1: Solidify the Core (Rust SDK & Verifier)

**Objective:** Create a stable, predictable, and secure foundation. All work in this phase is a prerequisite for subsequent phases.

### 1.1. Implement Native Commit Verification
*   **Why:** The current Python-based commit verification shells out to `ssh-keygen`, which is slow, brittle, and not portable. This is our biggest reliability risk.
*   **The Problem:**
    ```python
    # in packages/auths-python/python/auths/git.py
    proc = subprocess.run(
        ["ssh-keygen", "-Y", "verify", ...], ...
    )
    ```
*   **Action:** Implement the entire commit signature verification logic in pure Rust within the `crates/auths-verifier` crate. This single change will dramatically improve performance and reliability for a key feature.

### 1.2. Refactor SDK Configuration for Compile-Time Safety
*   **Why:** The SDK must be impossible to misconfigure. We can prevent entire classes of runtime errors at compile time.
*   **The Problem:** The `AuthsContextBuilder` in `crates/auths-sdk/src/context.rs` uses a `NoopPassphraseProvider` that causes a runtime error if signing is attempted without a real provider.
    ```rust
    // This defers a configuration error to a runtime crash.
    passphrase_provider: self
        .passphrase_provider
        .unwrap_or_else(|| Arc::new(NoopPassphraseProvider)),
    ```
*   **Action:** Eliminate the `Noop` providers. Use the typestate pattern to create distinct `AuthsContext` types, such as `AuthsContext<Unsigned>` and `AuthsContext<SigningReady>`. Workflows that require signing must take the `SigningReady` context as an argument, making it a compile-time error to call them without the correct configuration.

### 1.3. Eradicate Panics from the Public API
*   **Why:** A library that can `panic` is a library that cannot be trusted in production. It is the most hostile behavior an SDK can exhibit.
*   **The Problem:** The codebase is littered with `.unwrap()` and `.expect()` calls that can crash the host application.
    ```rust
    // in crates/auths-sdk/src/workflows/mcp.rs:80
    .expect("failed to build HTTP client") // Will crash if host TLS is misconfigured.
    ```
*   **Action:** Audit and refactor every `.unwrap()` and `.expect()` in the `auths-sdk` crate's public-facing workflows. Replace them with proper, descriptive error variants (e.g., `McpAuthError::HttpClientBuildFailed`).

### 1.4. Unify and Seal the Public API Surface
*   **Why:** We are making a promise of stability with `v0.1.0`. The API we launch with is the API we must support.
*   **Action:**
    1.  **Unify:** Refactor the `initialize_developer`, `initialize_ci`, and `initialize_agent` functions in `crates/auths-sdk/src/setup.rs` into private helpers. The single public entry point must be `pub fn initialize(config: IdentityConfig, ...)`.
    2.  **Seal:** Run `cargo public-api` to generate a definitive list of our public API. Anything we are not ready to commit to for the long term must be hidden (`pub(crate)` or `#[doc(hidden)]`).

---

## Phase 2: Refine the Developer Experience (Python FFI & SDK)

**Objective:** Create an idiomatic, robust, and effortless experience for Python developers. This phase depends heavily on the stability provided by Phase 1.

### 2.1. Implement Robust FFI Error Handling
*   **Dependency:** Phase 1.3 (Eradicate Panics). The Rust layer must return errors, not panic.
*   **Why:** The current error handling is based on string-matching messages from Rust, which is extremely fragile.
*   **The Problem:**
    ```python
    # in packages/auths-python/python/auths/_client.py
    def _map_verify_error(exc: Exception) -> Exception:
        msg = str(exc)
        if "public key" in msg.lower(): # This will break silently.
            return CryptoError(msg, code="invalid_key")
    ```
*   **Action:** Modify the Rust FFI layer to return a stable, machine-readable error code (a C-style enum or integer). The Python `_map_verify_error` function must be rewritten to dispatch on this reliable code.
This MUST be consistent across all such files

### 2.2. Consume Native Commit Verification
*   **Dependency:** Phase 1.1 (Native Commit Verification).
*   **Why:** To eliminate the slow and brittle `subprocess` calls.
*   **Action:** Remove the `verify_commit_range` implementation from `packages/auths-python/python/auths/git.py` and replace its body with a single call to the new native Rust function (exposed via the `auths._native` module).

### 2.3. Adopt Pythonic Types and Conventions
*   **Why:** The Python SDK must respect the conventions of its ecosystem to feel natural to developers.
*   **The Problem:** The API uses strings for timestamps and may not return idiomatic `dataclass` instances.
    ```python
    # in packages/auths-python/python/auths/_client.py
    def verify(self, ..., at: str | None = None) -> VerificationResult:
        # ...
    ```
*   **Action:**
    1.  Modify methods like `verify` to accept `datetime.datetime` objects. The implementation can then convert them to Unix timestamps (integers) to pass to the Rust layer.
    2.  Audit all functions that return data from Rust. Ensure they return proper `@dataclass` instances, not raw dictionaries or tuples.
    3.  Ensure all public methods and parameters follow `snake_case` conventions.

---

## Phase 3: Polish the Public Integrations (JS Ecosystem)

**Objective:** Ensure our integrations are seamless, easy to use, and inspire confidence. This can run in parallel with Phase 2.

### 3.1. Manage External Dependencies for Independent Repos
*   **Correction & Context:** My previous analysis incorrectly assumed a monorepo structure. Understanding these are independent repositories makes the dependency management even more critical. The current build scripts have hardcoded relative paths that will fail in any standard CI/CD environment or for any external contributor.
*   **Action (`auths-verify-widget`):** The `build:wasm` script in `package.json` (`"cd ../auths/crates/auths-verifier && wasm-pack build ..."`) is a critical flaw. It relies on a local file structure that will not exist in a clean checkout. The WASM verifier *must* be treated as a versioned, third-party dependency.
    1.  The `auths/crates/auths-verifier` project must be configured to compile to WASM and be published to `npm` as a standalone package (e.g., `@auths/verifier-wasm`).
    2.  The `auths-verify-widget` must remove the `build:wasm` script and add `@auths/verifier-wasm` as a standard `devDependency` in its `package.json`.
    This ensures the widget can be built, tested, and released independently.
*   **Action (`auths-verify-github-action`):** The action correctly treats the `auths` CLI as an external dependency by downloading it at runtime. However, for a v0.1.0 launch, this introduces too much variability.
    1.  For the v0.1.0 release, the action *must bundle a specific, known-good version* of the `auths` native binary for Linux x64 (the standard GitHub runner environment). This guarantees performance and reliability.
    2.  This can be accomplished by adding a script to the `auths-verify-github-action` repo that downloads a specific versioned release of the `auths` CLI from its GitHub Releases page and places it in the `dist` directory as part of the build process.

### 3.2. Improve DX for Integrations
*   **Why:** These integrations are the "front door" to our product for many developers. The experience must be flawless.
*   **Action (`auths-verify-widget`):**
    1.  **Clarify Variants:** The `README.md` must clearly explain the "full" vs. "slim" builds.
    2.  **No-Build Option:** Create a UMD bundle and publish it to a CDN (`unpkg`, `jsdelivr`) so the widget can be used with a simple `<script>` tag.
*   **Action (`auths-verify-github-action`):**
    1.  **Better Failure UX:** On verification failure, post a detailed PR comment explaining *which* commits failed and *how* to fix it. This turns failure into an educational moment.
    2.  **Streamline `action.yml`:** Default the `github-token` to `${{ github.token }}` and add at least three copy-pasteable examples for common use cases to the `README.md`.

---

## Phase 4: Release Engineering & Documentation

**Objective:** Ensure the product is easy to install and use. This is the final step before launch.

### 4.1. Guarantee Effortless Installation
*   **Dependency:** Phase 1, 2, and 3 must be complete.
*   **Why:** `pip install auths` and `npm install @auths-dev/verify` must *just work*. A difficult installation is our single biggest adoption blocker.
*   **Action (`auths-python`):** Ensure the CI/CD pipeline uses `maturin build --release` to build and publish binary wheels for all major platforms (manylinux, macOS x86_64/arm64, Windows amd64) to PyPI.
*   **Action (JS packages):** Ensure the CI/CD pipeline correctly publishes all public `npm` packages (`@auths/verifier-wasm`, `@auths-dev/verify`).

### 4.2. Write the "First Five Minutes" Guide
*   **Why:** A developer's first impression is formed in the first five minutes. We need a guide that makes them feel successful immediately.
*   **Action:** Create a "Getting Started" guide that takes a developer from zero to a successful signature verification in under 3 minutes. This guide should use the Python SDK as its primary example.

## Final Go/No-Go Checklist

We are ready to launch v0.1.0 **if and only if** we can answer "Yes" to all of the following:
- [ ] Is all work in **Phase 1** complete and verified?
- [ ] Is all work in **Phase 2** complete and verified?
- [ ] Is all work in **Phase 3** complete and verified?
- [ ] Does `pip install auths` work on clean installs of macOS, Linux, and Windows without requiring a Rust toolchain?
- [ ] Do we have a "Getting Started" guide that takes a developer from zero to a successful signature verification in under 3 minutes?
