---
hide:
  - navigation
  - toc
---

<div align="center" style="margin-top: 4rem; margin-bottom: 4rem;" markdown="1">

<h1 class="hero-text">Portable Identity for Developers, Agents, and Workflows</h1>

<p class="hero-subtitle">
Cryptographic commit signing with Git-native storage. One identity, multiple devices, no central authority.
</p>

[Get Started](getting-started/install.md){ .md-button .md-button--primary }
&nbsp;&nbsp;
[Architecture](architecture/overview.md){ .md-button }

</div>

## Install

=== "macOS"

    ```bash
    brew tap auths-dev/auths-cli
    brew install auths
    ```

=== "Linux"

    ```bash
    curl -sSfL https://get.auths.dev | sh
    ```

=== "Cargo"

    ```bash
    cargo install auths-cli
    ```

=== "Source"

    ```bash
    git clone git@github.com:auths-dev/auths.git
    cargo install --path crates/auths-cli
    ```

!!! tip
    See the full [Installation guide](getting-started/install.md) for platform-specific keychain setup and pre-built binaries.

---

<div class="grid cards" markdown>

-   :material-git: **Git-Native, No Blockchain**

    ---

    Identity data and attestations are stored as Git refs under `refs/auths/`. Your `~/.auths` repo is the single source of truth. No database, no central server, no chain -- just Git.

-   :material-devices: **Multi-Device Identity**

    ---

    Create a stable `did:keri` identity and delegate your laptop, phone, and CI server under it — each device gets its own key, anchored in your identity's event log. Every device signs as **you**. Revoke a lost device in one command.

-   :material-check-decagram: **Verifiable Everywhere**

    ---

    Embed `auths-verifier` via WASM, FFI, or native Rust. Verify attestation chains in browsers, CI pipelines, and backend services -- no network call required.

</div>

---

## Quick Tour

```bash
# Try sign + verify in-process — zero setup, no prompts, under a second
auths demo

# One-time: create your identity, configure Git signing, install the commit hook
auths init

# Commit as normal — signed and verifiable automatically
git commit -m "my first signed commit"
auths verify HEAD
```

---

## Quick Links

<div class="grid cards" markdown>

-   :material-rocket-launch: **Getting Started**

    ---

    Install Auths, create your first identity, and sign your first commit.

    [Installation](getting-started/install.md)

-   :material-sitemap: **Architecture**

    ---

    Understand the identity model, Git storage layout, attestation format, and crate structure.

    [Architecture Overview](architecture/overview.md)

</div>

## All Sections

- [CLI Command Reference](cli/commands/primary.md) -- every `auths` command, flags, and examples ([advanced commands](cli/commands/advanced.md))
- [Design Notes](design/sigstore-comparison.md) -- threat models, comparisons, and design specs under `docs/design/`
- [Essays](essays/the-repository-is-the-root-of-trust.md) -- longer-form writing on the trust model under `docs/essays/`
- [Proposed Issues](proposed-issues/keri-ixn-anchored-attestations.md) -- drafted improvement proposals under `docs/proposed-issues/`
- [Archive (pre-KEL-native)](archive/README.md) -- historical documents that predate the June-2026 KEL-native migration

---

## Open Source

Auths is open source under the MIT / Apache 2.0 license.

[View on GitHub :material-github:](https://github.com/auths-dev/auths){ .md-button }
