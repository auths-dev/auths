# Codebase Evaluation Prompt: Auths — Decentralized Developer Identity

You are a senior technology analyst with expertise in developer infrastructure, cybersecurity, and venture capital valuation. You have deep knowledge of software supply chain security, decentralized identity (SSI/DID/KERI), and open-source business models.

## Your Task

Evaluate the `auths` project — a decentralized identity system for developers — across three dimensions:

1. **SWOT Analysis** against the competitive landscape
2. **VC-style valuation** of the current codebase as a technical asset
3. **Milestone roadmap** with concrete requirements to reach $10M, $50M, $100M, $500M valuations

Be rigorous and skeptical. Identify real risks, not just opportunities. Compare against actual competitors with real market data.

---

## Project Summary

**Auths** is a decentralized cryptographic identity system for developers. It enables commit signing, artifact signing, and identity delegation using KERI-inspired key event logs stored natively in Git refs. No blockchain, no central server — just Git and cryptography.

### Technical Footprint

| Metric | Value |
|--------|-------|
| Language | Rust |
| Workspace crates | 22 |
| Source files (`.rs`) | 555 |
| Lines of code (total) | ~171,000 |
| Passing tests | 1,593 |
| Version | 0.0.1-rc.7 |
| License | Apache-2.0 |
| Rust edition | 1.93 |
| CI platforms | Ubuntu x86_64, macOS aarch64, Windows x86_64 |

### Architecture (6-layer dependency hierarchy)

```
Layer 0: auths-crypto       — Ed25519 primitives, DID:key encoding
Layer 1: auths-verifier     — Standalone verification (FFI/WASM/native), 11 deps
Layer 2: auths-core         — Platform keychains (macOS/Linux/Windows), signing, policy, ports
Layer 3: auths-id           — Identity lifecycle, attestation, KERI event logs
         auths-policy       — Policy-as-code engine (compile, evaluate, enforce)
Layer 4: auths-storage      — Git and SQL storage adapters
         auths-sdk          — Application services layer
Layer 5: auths-infra-git    — Git client adapter
         auths-infra-http   — HTTP client adapter
Layer 6: auths-cli          — CLI with 23+ commands (auths, auths-sign, auths-verify)
```

### Key Technical Capabilities

- **Zero-network verification**: The `auths-verifier` crate compiles to native, C FFI, and WASM. Identity bundles contain the full attestation chain + root public key, enabling completely offline verification. No Fulcio CA, no Rekor transparency log, no network calls.
- **Git-native storage**: All identity state lives in Git refs (`refs/auths/`, `refs/keri/`). The `~/.auths` directory is itself a Git repo. Full audit trail via `git log`, distributed replication via `git push/pull`.
- **KERI key lifecycle**: Pre-rotation support via Key Event Logs. Key rotation doesn't break identity — old signatures remain verifiable because the KEL establishes key authority at signing time.
- **Delegation chains with capability scoping**: Attestation chains from root identity to leaf device. Each attestation carries scoped capabilities (`SignCommit`, `SignRelease`, `ManageMembers`, `RotateKeys`). A CI bot can sign commits but not rotate keys.
- **Cross-platform keychains**: macOS Security Framework, Linux Secret Service, Windows Credential Manager via conditional compilation.
- **SCIM 2.0 provisioning**: RFC 7643/7644 compliant for enterprise IdP integration.
- **OIDC bridge**: Exchanges attestation chains for cloud-provider JWTs (AWS STS, GCP Workload Identity, Azure AD).
- **Policy engine**: `compile()`, `evaluate_strict()`, `enforce()` with shadow policies for canary testing.
- **MCP authorization server**: JWT validation with capability-scoped tool authorization for AI agents.
- **Mobile FFI**: UniFFI bindings generating Swift/Kotlin code. Transport-agnostic pairing protocol with QR code support.
- **Witness network**: Byzantine-tolerant verification with N-of-M witness quorum checking.

### Distribution Channels (already built)

**1. GitHub Action (`auths-verify-github-action`)**
- Published on GitHub Marketplace as `auths-dev/auths-verify-github-action@v1`
- Auto-detects commit range from PR/push events
- Downloads and caches the `auths` CLI with SHA256 checksum verification
- Generates GitHub Step Summary with per-commit results table
- Posts fix instructions as PR comments (copy-pasteable `git commit --amend -S` commands)
- Supports two verification modes: allowed-signers file or identity bundle (stateless CI)
- Pre-flight checks for shallow clones and missing dependencies

**2. Embeddable Verification Widget (`auths-verify-widget`)**
- Published as `@auths-dev/verify` on npm
- Drop-in web component: `<auths-verify repo="https://github.com/user/repo"></auths-verify>`
- Runs WASM verification engine entirely in the browser — no server calls
- Three display modes: badge, detail (expandable attestation chain), tooltip
- Supports GitHub and Gitea forges (including self-hosted)
- Manual mode for offline/GitLab scenarios (supply attestation + public key directly)
- CDN-loadable with zero build step required

### Current State / Gaps

- Pre-revenue, no production deployments
- No published binary releases (users must `cargo install --path`)
- No formal security audit
- SDK error types still partially wrap `anyhow::Error` (transitional)
- Version 0.0.1-rc.7 — not yet v0.1.0
- No Homebrew formula, no apt/dnf packages
- GitLab forge support is limited (API doesn't expose custom refs)

---

## Competitive Landscape

Evaluate `auths` against these competitors. For each, identify where `auths` wins, where the competitor wins, and whether they are direct competitors, complementary, or potential acquirers.

| Competitor | Model | Market Position |
|------------|-------|-----------------|
| **Legacy GPG** | Manual key management, Web of Trust | Default for Git signing. <5% of GitHub commits are signed. Terrible DX. |
| **SSH Signing (GitHub native)** | `git config gpg.format ssh` + `allowed_signers` | Built into GitHub. No identity lifecycle, no attestation chain, no rotation. |
| **Sigstore / Gitsign** | Keyless OIDC-based signing via Fulcio CA + Rekor transparency log | Google-backed. Requires network for every sign and verify. Central CA. Identity borrowed from OIDC providers. No delegation. |
| **Chainguard** | Hardened container images + Sigstore-based signing | $3.5B valuation. Focuses on container/artifact signing, not developer identity. Complementary or potential acquirer. |
| **Centralized IAM (Okta, Azure AD, AWS IAM)** | Federated identity with SAML/OIDC tokens | Not developer-native. Cannot sign Git commits. No cryptographic proof of authorship. |
| **OriginVault DID SDK** | TypeScript SDK for DID management and VC signing | JavaScript-only. No Git integration. No CLI. No CI/CD story. |
| **Snyk** | Developer security tooling | $407.8M revenue. Different focus (vulnerability scanning) but overlapping buyer persona. |

### Market Data

- Software Supply Chain Security TAM: $2.16B (2025), growing to $3.27B by 2034 (10.9% CAGR)
- Chainguard: $3.5B valuation on ~$37M ARR (95x revenue multiple)
- By 2028: 85% of large enterprise software teams will deploy supply chain security tools (up from 60% in 2025)

---

## What I Want From You

### 1. SWOT Analysis

Provide a detailed SWOT analysis. Be specific — reference the technical capabilities and gaps listed above. Don't be generic.

- **Strengths**: What structural/technical advantages does this codebase have?
- **Weaknesses**: What are the real risks? (team size, go-to-market, missing pieces)
- **Opportunities**: What market trends favor this project?
- **Threats**: What could kill it? (competitor moves, standard changes, adoption barriers)

### 2. Current Valuation Assessment

As a VC analyst, what would you value this at today? Consider:
- The codebase as a technical asset (171K lines of Rust, 1,593 tests, 22-crate architecture)
- The distribution channels (GitHub Action, npm widget)
- The competitive positioning (zero-network verification is architecturally unique)
- The gaps (pre-revenue, no production deployments, no security audit)
- Comparable transactions in the space

### 3. Milestone Roadmap to Each Valuation Tier

For each tier, specify:
- What must be true (product, traction, team, revenue)
- What are the biggest risks at that stage
- What comparable companies achieved similar valuations and how

| Valuation | What Must Be True |
|-----------|-------------------|
| **$10M** | ? |
| **$50M** | ? |
| **$100M** | ? |
| **$500M** | ? |

### 4. Strategic Questions

Answer these:
- Is the "Git-native storage" approach a genuine moat or a limitation?
- Can Sigstore add offline verification and neutralize the key differentiator?
- Is the right GTM motion bottom-up developer adoption or top-down enterprise sales?
- Which distribution channel (GitHub Action, widget, CLI, mobile) should be prioritized?
- What's the most likely exit path — acquisition by GitHub/Microsoft, Google, HashiCorp, or IPO?
- Is the KERI approach a strength (standards-based) or a risk (niche, unproven at scale)?

### 5. What Would You Want to See Next?

If you were a lead investor in a seed round, what 3-5 things would you want to see demonstrated in the next 6 months to gain conviction?

---

## Output Format

Structure your response with clear headers for each section. Use tables where appropriate. Be direct — no filler. Back claims with reasoning or comparables. Flag assumptions explicitly.
