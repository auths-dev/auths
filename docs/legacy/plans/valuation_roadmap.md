# Auths: M&A Valuation-Focused Codebase Diligence

**Date:** 2026-03-01
**Prepared by:** Technical Diligence Team (dual-hatted: M&A Banking + CTO/Principal Engineer)
**Classification:** Confidential — Investment Committee Use Only

---

## 1) Concise Project Summary

- **What it is:** Auths is a decentralized identity system for developers enabling cryptographic commit signing with Git-native storage, inspired by KERI (Key Event Receipt Infrastructure) principles.
- **Who it's for:** Software developers, DevSecOps teams, CI/CD pipelines, and enterprises requiring code provenance and supply chain integrity.
- **Problem solved:** Eliminates dependence on centralized identity providers (GitHub, GPG keyservers, Keybase) for code signing by providing self-certifying, portable cryptographic identities stored entirely in Git.
- **Core IP:** The KERI-inspired identity state machine (`auths-id`), dual-signed attestation model, and the minimal-dependency embeddable verifier (`auths-verifier` with FFI/WASM support). These components would survive any acquisition.
- **Product form today:** CLI tool (`auths`, `auths-sign`, `auths-verify`), Rust SDK, embeddable verification library (FFI + WASM), registry server (HTTP API), auth server ("Login with Auths"), and OIDC bridge for cloud provider integration.
- **Codebase scale:** ~223K lines of Rust across 22 crates, 627 commits over 10 months, single contributor.
- **Architecture:** Clean hexagonal/ports-and-adapters design with strict dependency direction (inward only), enforced by `cargo deny` and CI.
- **Test maturity:** ~350+ test functions (10K+ with contract macro expansion), property-based testing (proptest), 3 fuzz targets (libfuzzer), multi-platform CI (Ubuntu/macOS/Windows), network-isolated unit tests, SemVer enforcement via `cargo-semver-checks`.
- **Security posture:** Comprehensive — Ed25519 via `ring`, XChaCha20-Poly1305 encryption, Argon2id KDF, `Zeroize`/`ZeroizeOnDrop` on all key material, platform keychain integration (macOS/Linux/Windows/iOS/Android), constant-time token comparison, rate limiting, FFI panic safety.
- **Packaging/distribution:** Homebrew (`brew install auths-dev/auths-cli/auths`), `cargo install`, Docker images, GitHub Actions release workflow, cross-platform binaries.
- **License:** Apache-2.0 / MIT dual license (acquisition-friendly, no copyleft encumbrance).
- **Current status:** Pre-revenue, pre-public-launch, v0.0.1-rc.13. No detectable community, stars, forks, or external adoption signals.

---

## 2) Technical Diligence: What Drives Valuation

### Diligence Scoring Table

| Dimension | Score (0–5) | Evidence | Why It Matters to Valuation | Fix Cost | Risk to Acquirer |
|-----------|:-----------:|----------|----------------------------|:--------:|:----------------:|
| **Architecture boundaries & integrability** | 4.5 | 22 crates in strict layered architecture (`ARCHITECTURE.md`). Dependency direction enforced by `cargo deny check bans` and `scripts/check-arch.sh` in CI. Port traits in `auths-core/src/ports/`, `auths-sdk/src/ports/`. `auths-verifier` has zero heavy deps (no git2, no tokio in WASM mode). | An acquirer can extract `auths-verifier` as a standalone library, embed `auths-sdk` as a headless SDK, or integrate the full stack. Clean boundaries mean integration without rewrite. | S | Low |
| **Maintainability** | 4.0 | Consistent patterns: clock injection, port traits, contract test macros. Clippy strict mode (`-D warnings -D clippy::disallowed_methods`). `println!`/`eprintln!` banned in library crates. Domain errors via `thiserror`, `anyhow` confined to presentation layer. Single-contributor codebase is a risk but code quality is high. | Low maintenance burden post-acquisition. New engineers can onboard via `ARCHITECTURE.md`, `CONTRIBUTING.md`, and structured test suite. | S | Low |
| **Testability & determinism** | 4.5 | Clock injection eliminates time-based flakiness. `MockClock`, `FakeClock`, `FakeRegistryBackend`, `FakeIdentityResolver` in `auths-test-utils`. Contract test macros ensure fake-to-real parity. Argon2 fast params under `#[cfg(test)]`. OnceLock shared keypairs. Network-isolated unit tests in CI (iptables). Only 3 flaky tests out of 350+. | Deterministic tests = reliable CI = lower operational cost. Contract tests prevent regression when swapping backends. | S | Low |
| **Security posture & supply chain** | 4.0 | `SECURITY.md` with 5 enforced rules. `Zeroize`/`ZeroizeOnDrop` on `SecureSeed`. Platform keychains. `deny.toml` with license whitelist and dependency confinement. `cargo audit` config tracking 11 transitive CVEs (all from `keri` dependency chain). Fuzzing on verification boundaries. Constant-time token comparison. Rate limiting. FFI panic catching. | Security is table stakes for identity/signing products. Strong posture reduces acquirer risk and accelerates SOC2/FedRAMP compliance. Transitive CVEs from `keri` are a minor concern. | S (CVE monitoring) | Low |
| **Reliability & failure modes** | 3.5 | Typed error enums throughout domain/SDK. `thiserror`/`anyhow` translation boundary. Mutex poison handling (`map_err` not `unwrap`). FFI size limits (`MAX_ATTESTATION_JSON_SIZE = 64KiB`). Rate limiting on server. Replay attack prevention in `store_attestation()`. Bundle TTL for stale attestation expiry. No circuit breakers on the main data path (inference: Git operations could block). | Production readiness signal. Typed errors enable structured alerting. Git-as-storage could introduce latency under contention — a known tradeoff documented in the tiered caching design. | M | Low |
| **Observability & supportability** | 2.5 | `auths-telemetry` crate exists with `metrics`, `tracing`, `prometheus`. `EventSink` port for structured telemetry. `StdoutSink` and `MemorySink` implementations. `DROPPED_AUDIT_EVENTS` counter. `auths doctor` CLI command. However: no distributed tracing integration (Jaeger/OTLP), no structured log correlation, no dashboard templates. | Enterprise acquirers need day-2 ops story. The port trait exists but production observability is incomplete. This is typical for pre-launch and fixable. | M | Low |
| **Release engineering** | 4.0 | GitHub Actions CI: multi-platform (Ubuntu/macOS/Windows), `cargo-semver-checks`, WASM portability check, `cargo deny`. Release workflow produces cross-platform binaries with artifact signing. Homebrew tap. Docker images. `justfile` with 46KB of build recipes. `xtask` crate for CI setup. Pre-commit hooks. Version 0.0.1-rc.13 shows active iteration. | Mature CI/CD reduces acquirer integration cost. SemVer enforcement on stable crates protects downstream consumers. | S | Low |
| **Documentation & onboarding** | 4.0 | `ARCHITECTURE.md` (port inventory, bounded contexts, dependency rules). `CONTRIBUTING.md` (code style, PR checklist). `TESTING.md`. `SECURITY.md`. `RELEASES.md`. Per-crate READMEs. MkDocs site (`mkdocs.yml`) with 70+ pages of planned content. Rustdoc mandatory for public APIs. `E2E_TEST_PLAN.md`. ADRs in `docs/adr/`. Enterprise OIDC guide. | Documentation quality signals engineering maturity. Reduces onboarding time for acquirer's team. MkDocs site structure is comprehensive even if not all pages are published. | S | Low |
| **Licensing/IP provenance** | 4.5 | Apache-2.0 / MIT dual license. DCO (Developer Certificate of Origin) required. `deny.toml` blocks all GPL variants. 627 commits from a single contributor (clean IP provenance). No CLA required (DCO is sufficient for most acquirers). Copyright notice in LICENSE is templated (`[2025] [name of copyright owner]`) — should be filled in. | Dual Apache/MIT is the gold standard for acquisition. No GPL contamination risk. Single-contributor simplifies IP assignment. | S (fix copyright notice) | Low |

### Integration Assessment

**"Could a serious acquirer integrate this in <90 days without rewrite?"**

**Yes.** The hexagonal architecture with port traits means an acquirer can:
1. **Day 1–30:** Extract `auths-verifier` (zero heavy deps) and embed it in their existing CI/CD pipeline or developer tool via FFI, WASM, or Rust crate dependency.
2. **Day 30–60:** Wire `auths-sdk` workflows into their identity management system by implementing the port traits (`IdentityResolver`, `RegistryClient`, `EventLogWriter`, etc.) against their existing infrastructure.
3. **Day 60–90:** Deploy `auths-registry-server` alongside their existing services, or integrate the `auths-id` domain layer directly.

The strict dependency layering means any layer can be adopted independently. The verifier is explicitly designed for embedding (cdylib + WASM targets, no git2 dependency, FFI exports with null checks and panic catching).

**"What's the probability this becomes a rewrite post-close, and why?"**

**Low (15–20%).** Rewrite risk factors:
- **In favor of keeping:** Clean architecture, comprehensive tests, Rust (performance + safety), standard patterns (ports/adapters, `thiserror`, `serde`), no framework lock-in beyond `axum` (easily swappable at server layer).
- **Against keeping:** Single-contributor means limited code review history. Some transitive dependency debt from `keri` ecosystem (tracked but not fixable upstream). An acquirer using Go/Java/Python would need to maintain Rust expertise.
- **Most likely outcome:** Partial extraction (verifier + SDK + core) with server layer rebuilt to match acquirer's infrastructure choices. This is not a "rewrite" but a normal integration pattern.

---

## 3) Banker-Grade Valuation Analysis (Pre-Revenue)

### 3A) Valuation Framing

#### Replacement Cost

| Component | Eng-Months | Blended Rate ($25K/mo) | Notes |
|-----------|:----------:|:----------------------:|-------|
| `auths-crypto` + `auths-core` (crypto, keychains, port traits) | 8 | $200K | Ed25519, XChaCha20-Poly1305, Argon2id, 5-platform keychain, encryption at rest |
| `auths-id` (identity lifecycle, KEL state machine, attestations) | 10 | $250K | KERI-inspired event log, dual-signed attestations, rotation, revocation, freeze |
| `auths-verifier` (FFI + WASM + fuzzing) | 5 | $125K | Minimal-dep verifier with 3 fuzz targets, C FFI, WASM bindings |
| `auths-sdk` (workflows, port orchestration) | 6 | $150K | Setup, signing, verification, device pairing, audit workflows |
| `auths-cli` (3 binaries, doctor, git integration) | 6 | $150K | Clap-based CLI, git signing integration, agent, emergency commands |
| `auths-registry-server` (multi-tenant, Postgres, Stripe) | 8 | $200K | Axum HTTP API, multi-tenant with moka cache, rate limiting, admin auth |
| `auths-auth-server` + `auths-oidc-bridge` | 5 | $125K | Challenge-response auth, GitHub OIDC, AWS STS integration |
| Infrastructure crates (cache, index, infra-git, infra-http, telemetry) | 6 | $150K | Redis tiered caching, SQLite index, Git adapters, HTTP adapters |
| Mobile FFI (iOS/Android via UniFFI) | 3 | $75K | UniFFI bindings for mobile identity |
| Test infrastructure (`auths-test-utils`, contract macros, fuzz targets) | 4 | $100K | Fakes, mocks, contract test macros, proptest generators |
| CI/CD, docs, build system, release engineering | 3 | $75K | Multi-platform CI, SemVer checks, Homebrew, Docker, MkDocs |
| Architecture & design (KERI adaptation, DID model, security model) | 6 | $150K | Non-trivial domain expertise; KERI/DID/IETF standards knowledge |
| **Total** | **70** | **$1.75M** | |

**Risk premium (1.5–2.5x):** Building this from scratch carries execution risk — cryptographic code, cross-platform keychains, KERI protocol adaptation, and FFI/WASM safety are error-prone domains. A reasonable risk premium is 2x.

**Replacement cost estimate: $3.0–4.5M**

#### Strategic Value

The strategic value depends on the acquirer. For a developer platform (GitHub, GitLab, JFrog, Snyk):
- **Accelerates roadmap by 12–18 months** on decentralized developer identity
- **Reduces regulatory risk** — EO 14028/14144 and EU CRA mandate code provenance; auths provides the identity layer
- **Creates competitive moat** — first-mover on Git-native decentralized identity
- **Enables new product lines** — "Login with Auths", artifact signing, OIDC bridge for CI/CD, org-level identity governance

#### Moat/Defensibility

| Factor | Defensibility | Evidence |
|--------|:------------:|---------|
| KERI adaptation for Git | **High** | No other implementation exists. KERI ecosystem is nascent (cesride: 17 stars). Custom KEL state machine in `auths-id`. |
| Dual-signed attestation model | **Medium-High** | Novel design combining issuer + device signatures with capabilities, expiry, revocation. JSON-canonical serialization. |
| Cross-platform keychain integration | **Medium** | macOS Security Framework, Linux Secret Service, Windows Credential Manager, iOS/Android KeyStore. Laborious but not conceptually novel. |
| Embeddable verifier (FFI/WASM) | **Medium** | Design choice (minimal deps, cdylib, wasm-bindgen) is replicable but the fuzzing and safety engineering adds value. |
| Git-native storage model | **High** | Storing identity data as Git refs (`refs/auths/`, `refs/keri/`) is a unique design decision. Eliminates infrastructure dependency. |

#### Adoption & Distribution

- **Current:** Zero public adoption. No stars, forks, community mentions, or pilots detected.
- **Distribution channels available but unused:** Homebrew tap, crates.io publishing capability, Docker images, MkDocs site, GitHub Actions integration.
- **Credible path:** Developer identity is a "pull" product driven by compliance mandates (EO 14028, EU CRA, SLSA). The Homebrew install + `auths init` onboarding is frictionless. The OIDC bridge enables enterprise CI/CD integration.

#### Integration Fit

- **Enterprise stacks:** OIDC bridge already supports AWS STS integration. GitHub Actions OIDC cross-reference implemented. PostgreSQL-backed servers. Docker deployment. Rate limiting.
- **Developer workflows:** Git-native signing (`git commit -S`), `allowed-signers` export, `auths doctor` diagnostics.
- **CI/CD pipelines:** `auths-verify` CLI, embeddable verifier (WASM for browser, FFI for C/Go/Python/Swift), GitHub Action.
- **Platform integration:** SDK with port traits means any backend can be swapped.

### 3B) Valuation Range with Rationale

| Case | Valuation | Rationale | What Must Be True | Deal Structure |
|------|----------:|-----------|-------------------|----------------|
| **Low** | **$3–5M** | Replacement cost floor. IP acquisition or acqui-hire. Codebase value + founder domain expertise. | No adoption, no revenue, no community. Acquirer wants the technology IP to accelerate their own roadmap. Market timing is neutral. | **Asset deal / acqui-hire.** IP assignment + 2-year employment contract for founder. Minimal earnout. |
| **Base** | **$8–15M** | Strategic technology acquisition. 2–3x replacement cost with strategic premium. Acquirer is a developer platform with immediate integration path. | Codebase passes security audit. Founder demonstrates deep domain expertise and can lead integration. At least 1–2 design partner LOIs or credible pilot discussions. Clean IP (confirmed). | **IP purchase + earnout.** 60% upfront, 40% earnout over 18 months tied to integration milestones (SDK shipped, N customers using verification). Founder joins as tech lead. |
| **High** | **$20–35M** | Post-launch traction. Public OSS project with 500+ stars, 3–5 enterprise design partners, clear path to revenue (SaaS registry, per-seat verification, enterprise support). Competitive dynamics (multiple acquirers bidding). | Successful public launch with developer community traction. At least 3 enterprise design partners with signed LOIs. Demonstrated regulatory demand (customer buying because of EO 14028 / EU CRA compliance). Competitive pressure from at least 2 acquirers. | **Full acquisition.** 70% cash, 30% stock/earnout. Founder leads identity product line. 3-year retention package. |

#### Key Diligence Unknowns That Could Move the Number

| Unknown | Impact if Positive | Impact if Negative |
|---------|-------------------|-------------------|
| Founder domain expertise depth (KERI, cryptography, standards bodies) | +$2–5M (irreplaceable knowledge) | -$1–2M (replaceable engineer) |
| Patent portfolio or pending patents | +$3–10M (defensive IP) | Neutral (OSS projects rarely have patents) |
| Undisclosed pilots or enterprise conversations | +$5–15M (de-risks adoption) | Neutral (expected for pre-launch) |
| Security audit results (if conducted) | +$1–3M (de-risks integration) | -$2–5M (if critical vulnerabilities found) |
| Regulatory mandate acceleration (EU CRA enforcement Sept 2026) | +$5–10M (urgency premium) | Neutral (mandates exist regardless) |

### 3C) Acquirer Map

| Acquirer Type | Examples | Why They'd Buy | Integration They'd Want | Deal-Killers |
|---------------|---------|----------------|------------------------|-------------|
| **Code hosting / developer platform** | GitHub (Microsoft), GitLab, Bitbucket (Atlassian) | Native decentralized identity for their platform. Differentiation vs. GPG/SSH signing. Compliance story for enterprise customers. | Embed verifier in platform. Replace GPG signing with auths identity. Add "Verified by Auths" badges. Ship as platform feature. | Licensing issues. Incompatible architecture. Founder unwilling to join. GitHub already building competing solution internally. |
| **Supply chain security** | Chainguard, Snyk, JFrog, Sonatype | Extend from container/package security into developer identity. Complete the provenance chain from developer to artifact. | Embed SDK in their scanning pipeline. Use attestation model for developer-to-artifact provenance. | Overlap with Sigstore investment (Chainguard). Too narrow for their platform breadth. |
| **Identity / IAM vendor** | Okta, Auth0 (Okta), Beyond Identity, 1Password | Add developer identity to their portfolio. "Login with Auths" for developer platforms. Machine identity for CI/CD. | Integrate auth server with their IdP. Use DID model for machine identity. OIDC bridge integration. | Too developer-niche for broad IAM vendors. Requires Rust expertise they may lack. |
| **Cloud provider** | AWS, GCP, Azure | Developer identity for their cloud-native CI/CD. Code signing for their artifact registries (ECR, Artifact Registry, ACR). | OIDC bridge for native cloud identity federation. Embeddable verifier in their CI/CD services. | Build-vs-buy favors build for hyperscalers. Auths too early-stage for their scale. |
| **DevSecOps platform** | Harness, CircleCI, Buildkite | Differentiate CI/CD with built-in code provenance. Compliance automation for regulated customers. | Embed verifier in pipeline. Ship signing as a pipeline step. Dashboard for attestation status. | Narrow feature — may prefer Sigstore integration. |
| **Security-focused acquirers** | CrowdStrike, Palo Alto Networks, Fortinet | Developer identity as extension of endpoint/identity security. Supply chain attack prevention. | SDK integration with their SIEM/SOAR. Attestation verification in their threat detection pipeline. | Too developer-niche. Prefer to build on Sigstore. |
| **Sovereign code / decentralization** | Radicle, Protocol Labs, Gitea | Identity layer for decentralized code collaboration. `auths-radicle` integration already exists. | Full stack integration. Identity for decentralized forge. | Small acquisition budgets. Radicle's own funding constraints. |
| **Crypto / Web3 identity** | Spruce, Ceramic, Disco | DID-native identity with proven engineering. Bridge Web3 identity to developer tooling. | DID model integration. Verifiable credentials pipeline. | Web3 market downturn. Valuation expectations mismatch. |

---

## 4) Open Core Strategy

### The Core Tension

Auths is a security and identity product. Users must be able to audit what they're trusting. But the entire codebase — including the SaaS infrastructure, billing integrations, and operational tooling — does not need to be public. The right answer is **open core**: open-source the protocol and client-side tooling, keep the commercial server infrastructure proprietary.

### Crate Classification

Every crate falls into one of three categories:

#### Open Source (Apache-2.0 / MIT) — Publish Publicly

These crates are the **adoption flywheel**. Every install, every `cargo add`, every npm import extends the auths attestation format into another system. The more systems that verify auths attestations, the stronger the network effect. Hiding these would be self-defeating.

| Crate | Publish To | Strategic Rationale |
|-------|-----------|-------------------|
| `auths-verifier` | crates.io, npm (WASM), PyPI, Go module | **The most important crate to open-source.** Every verifier installation is a lock-in point. Verifiers must be everywhere — CI pipelines, code review tools, artifact registries, browsers. If verification requires proprietary software, adoption dies. Sigstore's verifier is open-source; this is table stakes. |
| `auths-core` | crates.io | Foundation for all integrations. Third-party developers building on auths need access to the port traits, crypto primitives, and keychain abstraction. Opening this invites ecosystem contributions (new keychain backends, new storage adapters). |
| `auths-sdk` | crates.io | Application developers need this to build auths-powered workflows into their own tools. SDK adoption creates downstream dependency, which is the strongest form of lock-in. |
| `auths-crypto` | crates.io | Commodity crypto layer (Ed25519, KERI key parsing). No competitive advantage in hiding it. Opening it allows security researchers to audit the cryptographic foundations — critical for trust. |
| `auths-cli` | Homebrew, cargo install, GitHub releases | The primary distribution vehicle and first-touch experience. A security tool that can't be inspected won't be adopted. The CLI also demonstrates the product capabilities and drives users toward the hosted registry. |
| `auths-id` | crates.io | The KERI-inspired identity state machine is the protocol definition. Open-sourcing the protocol is how standards emerge. Keeping it proprietary would fork the ecosystem and invite competitors to build an incompatible alternative. |
| `auths-policy` | crates.io | Policy engine is part of the attestation model. Third parties need to evaluate policies in their own systems. |
| `auths-test-utils` | crates.io (or source-available) | Enables third-party contributors and integration testers. Low commercial value, high community value. |
| `auths-infra-git` | crates.io | Git storage adapters are reference implementations. Enables self-hosted deployments that feed users into the hosted registry when they want managed infrastructure. |
| `auths-radicle` | crates.io | Radicle integration is a partnership and ecosystem play. Must be open for Radicle community adoption. |

#### Proprietary — Keep in Private Repository

These crates are the **revenue moat**. They contain the operational infrastructure, billing integrations, and enterprise features that customers pay for. A competitor cannot replicate your business by reading your open-source code because the value is in the *managed service*, not the protocol.

| Crate | Why Proprietary | Revenue Model |
|-------|----------------|--------------|
| `auths-registry-server` | **This is the SaaS product.** Multi-tenant isolation (`TenantResolver`, `FilesystemTenantResolver`), moka LRU cache, path-traversal hardening, admin authentication, API key management, Stripe billing integration, tenant provisioning. This is where all commercial revenue originates. | Per-tenant SaaS subscription. Enterprise on-prem licensing. |
| `auths-auth-server` | **"Login with Auths" is a premium feature.** Challenge-response authentication, session management, PostgreSQL-backed session store, air-gapped `LocalGitResolver`. This enables "Login with Auths" as a product for web applications. | Per-authentication-request pricing or flat monthly fee. Bundled with registry subscription. |
| `auths-oidc-bridge` | **Enterprise cloud integration commands premium pricing.** GitHub OIDC cross-reference, AWS STS `AssumeRoleWithWebIdentity`, JWKS caching with circuit breaker, thundering-herd protection. Enterprise CI/CD teams pay for managed cloud identity federation. | Enterprise tier add-on. Per-cloud-provider pricing. |
| `auths-cache` | **Operational infrastructure.** Redis-backed tiered caching, write-through archival, dead-letter queue. This is the scaling layer that makes the hosted registry performant. No reason to give away scaling work. | Embedded in SaaS pricing. |
| `auths-index` | **Performance infrastructure.** SQLite-backed O(1) attestation lookups, WAL mode, index rebuild from Git. Part of the operational advantage of the hosted service. | Embedded in SaaS pricing. |
| `auths-telemetry` | **Operational advantage.** Metrics, tracing, Prometheus integration. Part of what makes the managed service reliable and monitorable. | Embedded in SaaS pricing. |

#### Source-Available (Delayed Open-Source or BSL) — Consider Case by Case

These crates sit in a gray zone. They have community value but also commercial value. Consider publishing them under a source-available license (BSL 1.1 or similar) that converts to open-source after a time delay (e.g., 36 months).

| Crate | Consideration |
|-------|--------------|
| `auths-infra-http` | Contains `HttpIdentityResolver`, `HttpWitnessClient`, `HttpRegistryClient`. Third parties need HTTP adapters to integrate with hosted registry, but giving away the full client implementation makes it trivial to build a competing hosted service. **Recommendation:** Open-source. The HTTP API is documented anyway; clients are commodities. |
| `auths-storage` | Pluggable storage backend interface with Git and Postgres backends. Open-sourcing enables self-hosted deployments; keeping proprietary forces dependency on hosted service. **Recommendation:** Open-source the interface and Git backend. Keep Postgres backend proprietary (part of the SaaS stack). |
| `auths-mobile-ffi` | UniFFI bindings for iOS/Android. Mobile SDK could be a paid product or an adoption driver. **Recommendation:** Open-source. Mobile adoption drives ecosystem lock-in. |
| `auths-chat-ffi` | UniFFI bindings for chat. **Recommendation:** Open-source if chat is a distribution channel; proprietary if it becomes a product. |
| `auths-chat-server` | Chat server. **Recommendation:** Proprietary unless pivoting to a chat-first distribution model. |

### "But Can't Competitors Just Copy It?"

This is the most common objection to open-source. The evidence says no, for five reasons:

**1. The code is not the moat — the system is.**

The `ARCHITECTURE.md` alone documents 70 engineer-months of design decisions: KERI adaptation, dual-signed attestation model, clock injection, port-based architecture, cross-platform keychain integration, FFI/WASM safety patterns. A competitor can read the code. Replicating the *system* — the accumulated design decisions, security hardening, test infrastructure, and domain expertise — takes years.

Evidence: Sigstore's code is fully open-source. Nobody has forked it into a competing product. The operational complexity and community trust are the barriers, not secrecy.

**2. Network effects protect you.**

Once developers sign commits with auths attestations and verifiers consume them, the *attestation format* becomes the moat. Every `auths-verifier` installation in a CI pipeline is a customer whose workflow depends on the auths attestation schema. Switching costs are measured in the number of downstream systems that parse your format.

This is the Stripe pattern: the API documentation is public, the SDKs are open-source, but the network of merchants and payment processors is the lock-in.

**3. Trust is non-negotiable for security tools.**

No enterprise security team will adopt an identity system they cannot audit. This is not a preference — it's a procurement requirement. Closed-source cryptographic identity tools do not get past security review at serious companies.

Evidence: Every successful code signing tool is open-source at the verification layer. GPG, SSH, Sigstore cosign/gitsign, SLSA verifiers — all open. The ones that tried closed-source (proprietary HSM vendors, closed signing services) serve only captive markets.

**4. Your real competitors won't copy you.**

| Competitor | Why They Won't Fork Auths |
|-----------|--------------------------|
| Sigstore / Chainguard | Has $892M in funding, Google/Red Hat backing, and their own architecture. They will build, not copy. |
| GitHub / Microsoft | Would build natively into their platform. They acquire companies; they don't fork repos. |
| GitLab | Same as GitHub — build or acquire. |
| Small startups | Lack the domain expertise in KERI, cryptographic identity, and cross-platform keychains to maintain a fork. The code is the easy part; the ongoing security maintenance is the hard part. |

**5. Open-source is your sales channel.**

The funnel: Developer discovers auths on GitHub/crates.io -> installs CLI -> signs commits -> team adopts -> needs hosted registry for multi-tenant/org management -> pays for SaaS.

Closing the top of this funnel (by making the CLI proprietary) kills adoption. The open-source crates are marketing, not product giveaway.

### Licensing Architecture

```
Open Source (Apache-2.0 / MIT)         Proprietary (All Rights Reserved)
-------------------------------------  ------------------------------------
auths-crypto                           auths-registry-server
auths-core                             auths-auth-server
auths-id                               auths-oidc-bridge
auths-verifier                         auths-cache
auths-sdk                              auths-index
auths-cli                              auths-telemetry
auths-policy                           auths-chat-server
auths-infra-git
auths-infra-http
auths-storage (interface + Git backend)
auths-radicle
auths-mobile-ffi
auths-test-utils
```

### Repository Structure

Two repositories:

| Repository | Visibility | Contents |
|-----------|-----------|---------|
| `auths-dev/auths` | **Public** | All open-source crates. CI/CD. Documentation. Community contributions welcome. |
| `auths-dev/auths-cloud` | **Private** | Registry server, auth server, OIDC bridge, cache, index, telemetry. SaaS infrastructure. Deployment configs. Stripe integration. |

The private repo depends on the public repo via `git` or `path` dependency in `Cargo.toml`. The public repo never references the private repo. This mirrors the existing architecture — dependencies already flow inward, so the split is natural.

### Implementation: How to Split

The existing hexagonal architecture makes this split clean. The dependency graph already enforces that server crates depend on core/SDK, never the reverse.

**Step 1:** Create `auths-cloud` private repo.

**Step 2:** Move these crates:
- `crates/auths-registry-server/`
- `crates/auths-auth-server/`
- `crates/auths-oidc-bridge/`
- `crates/auths-cache/`
- `crates/auths-index/`
- `crates/auths-telemetry/`
- `crates/auths-chat-server/`
- `deploy/`, `docker-compose.yml`, `Dockerfile.*`, `fly.toml`
- `.sqlx/` (offline query cache)

**Step 3:** In `auths-cloud/Cargo.toml`, reference the public crates:
```toml
[dependencies]
auths-core = { git = "https://github.com/auths-dev/auths.git", branch = "main" }
auths-sdk = { git = "https://github.com/auths-dev/auths.git", branch = "main" }
auths-verifier = { git = "https://github.com/auths-dev/auths.git", branch = "main" }
auths-id = { git = "https://github.com/auths-dev/auths.git", branch = "main" }
```

After publishing to crates.io, switch to versioned dependencies:
```toml
auths-core = "0.1"
auths-sdk = "0.1"
auths-verifier = "0.1"
```

**Step 4:** Update CI. The public repo CI tests only public crates. The private repo CI tests the full stack (pulls public crates as dependencies).

### Competitive Precedent

This exact model is used by the most successful open-core companies in developer tooling:

| Company | Open Source | Proprietary |
|---------|-----------|------------|
| **GitLab** | GitLab CE (core platform) | GitLab EE (enterprise features, RBAC, compliance) |
| **HashiCorp** | Terraform CLI, Vault CLI, Consul | Terraform Cloud/Enterprise, HCP Vault |
| **Elastic** | Elasticsearch, Kibana (core) | X-Pack security, ML, enterprise features |
| **Grafana Labs** | Grafana, Loki, Tempo, Mimir | Grafana Cloud (managed service) |
| **PostHog** | PostHog (analytics platform) | PostHog Cloud (managed hosting + enterprise) |
| **Airbyte** | Airbyte connectors + engine | Airbyte Cloud (managed service) |

In every case: the protocol/client/engine is open, the managed service/enterprise features are proprietary. Revenue comes from the operational convenience of not self-hosting, plus enterprise-only features (SSO, RBAC, audit logs, SLAs).

### Impact on Valuation

The open-core model **increases** valuation compared to fully proprietary or fully open-source:

| Model | Valuation Impact | Why |
|-------|:---------------:|-----|
| Fully proprietary | Lowest | No adoption flywheel. No community. No trust signal for security product. Limited distribution. |
| Fully open-source | Medium | Strong adoption but weak revenue moat. Acquirer worries: "what stops AWS from hosting this?" |
| **Open core** | **Highest** | Adoption flywheel (open) + revenue defensibility (proprietary). Acquirer gets both community and business model. Best of both worlds. |

Open-core companies command 15–25% higher acquisition multiples than fully open-source companies because the acquirer gets both the community/ecosystem (hard to build) and a defensible revenue stream (hard to compete with).

### Impact on the 90-Day Plan

The open-core strategy changes the execution sequence:

1. **Sprint 1 (Go Public):** Split repos *before* going public. Do not publish server crates.
2. **Sprint 2 (Publish):** Publish only open-source crates to crates.io and npm.
3. **Sprint 3 (Enterprise):** The proprietary registry becomes the "upgrade path" in design partner conversations: "Try the CLI for free, hosted registry for teams."
4. **Sprint 6 (Position):** The acquisition narrative becomes: "You're buying the protocol standard (open) and the commercial platform (proprietary). The open-source community is your distribution moat."

---

## 5) Valuation Milestones Ladder

### Tier 0: Lowest Plausible Valuation — $3–5M

#### 5A) What Must Be True
- **Technical:** Codebase compiles, tests pass, CI is green. Architecture is documented.
- **Product:** CLI works end-to-end for a single developer (init, sign, verify). Homebrew install exists.
- **Adoption:** Zero external users. No public launch.
- **Commercial:** No revenue, no pricing, no sales motion.
- **Status: THIS IS WHERE AUTHS IS TODAY.**

#### 5B) Current State Assessment
The codebase already exceeds the minimum for Tier 0:
- 22-crate hexagonal architecture with enforced boundaries
- Multi-platform CI with SemVer checks, fuzzing, property-based testing
- Comprehensive documentation (ARCHITECTURE.md, CONTRIBUTING.md, SECURITY.md)
- Homebrew distribution, Docker images, GitHub Actions release workflow
- OIDC bridge with AWS STS integration
- Multi-tenant registry server with PostgreSQL, rate limiting, admin auth

#### 5C) Fastest Path to Tier 1 ($10M)
1. **Public launch on GitHub** — make repo public, write launch blog post, submit to Hacker News/Reddit. (Effort: S, Artifact: public repo + blog post)
2. **Publish crates to crates.io** — `auths-verifier`, `auths-core`, `auths-sdk`. (Effort: S, Artifact: crates.io listings)
3. **Record a 3-minute demo video** — show init → sign → verify flow. (Effort: S, Artifact: YouTube/Loom video)
4. **Secure 2 design partner LOIs** — target DevSecOps teams at Series B+ startups who need SLSA compliance. (Effort: M, Artifact: signed LOI templates)
5. **Commission independent security audit** — focus on `auths-verifier` and `auths-core`. (Effort: M, Artifact: audit report from Trail of Bits, NCC Group, or similar)

---

### Tier 1: $10M

#### 5A) What Must Be True
- **Technical:** Independent security audit completed with no critical findings. Open-source crates published to crates.io (open-core model; server crates remain proprietary). WASM verifier available on npm.
- **Product:** Documentation site live (docs.auths.dev). SDK quickstart guides for Python, Go, JavaScript. End-to-end demo for CI/CD integration.
- **Adoption:** 200+ GitHub stars. 5+ external contributors. 2–3 design partner LOIs signed.
- **Commercial:** Pricing model defined (even if not launched). Enterprise support tier conceptualized.

#### 5B) Actionable Tasks

**Engineering / Architecture**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Fix copyright notice in LICENSE | Legal hygiene for acquisition | S | Updated `LICENSE` file |
| Publish `auths-verifier` v0.1.0 to crates.io | Distribution + credibility signal | S | crates.io listing |
| Publish `auths-core` and `auths-sdk` to crates.io | Ecosystem availability | S | crates.io listings |
| Build and publish WASM verifier to npm | JavaScript ecosystem reach | M | npm package `@auths/verifier` |
| Resolve `keri` transitive CVE chain | Clean `cargo audit` output | M | Updated Cargo.lock or documented mitigations |

**Security / Compliance**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Commission security audit (auths-verifier + auths-core) | De-risks acquirer diligence | M | Audit report (Trail of Bits, NCC Group, or equivalent) |
| Generate SBOM in CI | Regulatory compliance signal (EO 14028) | S | `cargo cyclonedx` or `syft` output in release artifacts |
| Add `SECURITY.md` vulnerability disclosure policy | OSS security hygiene | S | Updated `SECURITY.md` with reporting process |

**Tooling / Ecosystem / Integrations**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Publish Python bindings to PyPI | Cross-language reach | M | `pip install auths-verifier` |
| Publish Go bindings | Cross-language reach | M | `go get github.com/auths-dev/auths-go` |
| GitHub Action for commit verification | CI/CD integration | M | `auths-dev/auths-verify-action@v1` |
| VS Code extension (signing status) | Developer experience | M | VS Code Marketplace listing |

**Go-to-Market (Sales)**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Define pricing model (free tier + enterprise) | Commercial readiness signal | S | Pricing page draft |
| Create design partner LOI template | Formalize enterprise interest | S | LOI template document |
| Target 2–3 Series B+ DevSecOps teams | Validate enterprise demand | M | Signed LOIs |

**Marketing / Positioning**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Public launch blog post | Awareness + GitHub stars | S | Blog post on personal site / Medium |
| Hacker News / Reddit launch | OSS traction | S | HN submission |
| 3-minute demo video | Low-friction evaluation | S | YouTube/Loom video |
| "Why not Sigstore?" positioning doc | Differentiation clarity | S | Blog post or docs page |

**Founder Scaling**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Create contributor onboarding guide | Enable external contributions | S | `CONTRIBUTING.md` (already exists, enhance with "good first issues") |
| Label 10 "good first issues" on GitHub | Community building | S | GitHub issues |
| Identify first hire profile (DevRel or senior Rust engineer) | Scaling plan | S | Job description draft |

#### 5C) Fastest Path to Tier 2 ($20M)
1. **Public launch + Hacker News** — immediate visibility and star count. (S)
2. **Security audit** — de-risks enterprise conversations. (M)
3. **GitHub Action for verification** — adoption flywheel in CI/CD. (M)
4. **2–3 design partner LOIs** — social proof for acquirers. (M)
5. **npm + PyPI packages** — cross-language distribution. (M)

---

### Tier 2: $20M

#### 5A) What Must Be True
- **Technical:** Security audit clean. WASM verifier on npm. Python/Go bindings published. Stable API (v0.1+ on crates.io with no breaking changes for 3+ months).
- **Product:** Hosted registry (auths.dev) in beta. "Login with Auths" demo for web apps. Documentation site live with full quickstart guides.
- **Adoption:** 1,000+ GitHub stars. 10+ external contributors. 5+ enterprise design partners actively testing. Mentioned in 2+ conference talks or blog posts by third parties.
- **Commercial:** Free hosted tier live. Enterprise pricing defined. 1–2 paid pilot agreements ($5K–$20K each).

#### 5B) Actionable Tasks

**Engineering / Architecture**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Launch hosted registry at auths.dev | SaaS revenue path | L | Production deployment on Fly.io/AWS |
| Implement SLSA provenance metadata in attestations | Regulatory alignment | M | SLSA Build Level 2 compliance documentation |
| Add OpenTelemetry tracing to server crates | Enterprise observability requirement | M | OTLP export configuration |
| Stabilize SDK API (v0.1.0 → v1.0.0 roadmap) | Ecosystem trust | M | Migration guide + semver commitment |

**Security / Compliance**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| SOC 2 Type I readiness assessment | Enterprise procurement gate | L | Gap analysis document |
| SLSA Build Level 2 attestation for releases | Regulatory compliance | M | SLSA provenance attestation in CI |
| Vulnerability disclosure program (VDP) | Enterprise trust signal | S | HackerOne or similar program |

**Tooling / Ecosystem / Integrations**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| GitLab CI integration | Expand beyond GitHub | M | GitLab CI template + docs |
| Terraform provider for registry | Infrastructure-as-code adoption | M | `terraform-provider-auths` |
| Pre-receive hook for GitHub Enterprise | Enterprise deployment | M | GitHub App or webhook receiver |

**Go-to-Market (Sales)**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Convert 2+ design partners to paid pilots | Revenue signal | M | Signed pilot agreements |
| Enterprise demo environment | Sales enablement | M | Hosted demo at demo.auths.dev |
| Case study from design partner | Social proof | M | Published case study |

**Marketing / Positioning**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Conference talk (KubeCon, DevSecCon, or RSA) | Credibility + awareness | M | Accepted talk + recording |
| "Auths vs. Sigstore" technical comparison | Competitive positioning | S | Blog post with architecture diagrams |
| Developer advocate hires or partnerships | Sustained awareness | M | DevRel presence at meetups/conferences |

**Founder Scaling**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Hire first full-time engineer (senior Rust) | Development velocity | L | Filled position |
| Establish advisory board (2–3 industry experts) | Credibility + network | M | Advisory agreements |
| Set up open governance model for OSS project | Community trust | M | Governance document + maintainer guidelines |

#### 5C) Fastest Path to Tier 3 ($50M)
1. **Hosted registry beta at auths.dev** — SaaS revenue path. (L)
2. **2+ paid pilot agreements** — revenue signal. (M)
3. **Conference talk at KubeCon/DevSecCon** — industry credibility. (M)
4. **SLSA Build Level 2 attestation** — regulatory differentiation. (M)
5. **Hire first engineer** — remove single-contributor risk. (L)

---

### Tier 3: $50M

#### 5A) What Must Be True
- **Technical:** v1.0 stable API. SLSA Build Level 3 attestation. SOC 2 Type I in progress. SBOM generation in CI.
- **Product:** Hosted registry GA. Web dashboard for identity management. "Login with Auths" in production with 2+ customers.
- **Adoption:** 5,000+ GitHub stars. 50+ external contributors. Featured in CNCF/OpenSSF landscape. 10+ enterprises in production.
- **Commercial:** $100K–$500K ARR. 3–5 paying enterprise customers. Clear pricing tiers (free/team/enterprise).
- **Team:** 3–5 full-time employees (including founder).

#### 5B) Actionable Tasks

**Engineering / Architecture**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Ship SDK v1.0 stable release | Ecosystem commitment | L | v1.0 release on crates.io |
| Multi-cloud OIDC support (GCP, Azure) | Enterprise reach beyond AWS | M | OIDC bridge documentation for all 3 clouds |
| Key rotation automation | Enterprise key management | M | `auths key rotate` with automated rollover |
| High-availability registry deployment | Enterprise SLA | L | Multi-region deployment guide + Terraform modules |

**Security / Compliance**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Complete SOC 2 Type I audit | Enterprise procurement gate | L | SOC 2 Type I report |
| FedRAMP readiness assessment (if targeting US Gov) | Government market access | L | FedRAMP gap analysis |
| SLSA Build Level 3 with hermetic builds | Highest provenance assurance | L | SLSA v1.0 Build Level 3 attestation |

**Tooling / Ecosystem / Integrations**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| JFrog Artifactory plugin | Enterprise artifact management | M | JFrog Marketplace listing |
| Kubernetes admission controller | Cloud-native enforcement | M | Helm chart + operator |
| Sigstore interoperability layer | Coexistence with dominant standard | M | Sigstore-to-auths bridge documentation |

**Go-to-Market (Sales)**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Hire first sales/BD hire | Revenue acceleration | L | Filled position |
| Enterprise contract templates | Sales efficiency | M | Standard MSA + DPA templates |
| Partner program (SI/consulting partners) | Channel sales | M | Partner program documentation |

**Marketing / Positioning**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Apply for CNCF/OpenSSF landscape inclusion | Industry validation | S | Landscape PR accepted |
| Analyst briefing (Gartner, Forrester) | Enterprise credibility | M | Briefing completed |
| Monthly security newsletter / blog | Sustained awareness | M | Email list with 1K+ subscribers |

**Founder Scaling**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Hire VP Engineering | Scale engineering org | L | Filled position |
| Hire DevRel/Community lead | Community growth | L | Filled position |
| Establish engineering processes (RFC, design review) | Team scaling | M | RFC template + process doc |

#### 5C) Fastest Path to Tier 4 ($100M)
1. **$500K+ ARR from enterprise customers** — revenue validation. (L)
2. **SOC 2 Type I completion** — enterprise procurement gate. (L)
3. **CNCF/OpenSSF landscape inclusion** — industry validation. (S)
4. **JFrog or similar integration** — enterprise distribution. (M)
5. **Team of 5+** — removes key-person risk. (L)

---

### Tier 4: $100M

#### 5A) What Must Be True
- **Technical:** v2.0+ with enterprise features (RBAC, audit logs, SSO). SOC 2 Type II certified. Multi-cloud deployment.
- **Product:** Self-serve SaaS with web dashboard. Enterprise on-prem option. Mobile app for device management.
- **Adoption:** 15,000+ GitHub stars. 200+ contributors. Ecosystem of 10+ third-party integrations.
- **Commercial:** $2–5M ARR. 20+ paying enterprise customers. Net revenue retention >120%.
- **Team:** 15–25 employees. Engineering, sales, marketing, customer success.

#### 5B) Actionable Tasks

**Engineering / Architecture**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Enterprise RBAC and SSO integration | Enterprise table stakes | L | SAML/OIDC SSO + role-based access |
| On-premises deployment option | Regulated industry requirement | L | Air-gapped deployment guide + Helm chart |
| Audit log and compliance reporting | GRC requirement | L | Structured audit log export (SIEM-ready) |
| API rate limiting and multi-tenancy hardening | SaaS scalability | M | Load testing report showing 10K+ tenants |

**Security / Compliance**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| SOC 2 Type II certification | Ongoing compliance | L | SOC 2 Type II report |
| ISO 27001 certification (if targeting EU) | EU enterprise gate | L | ISO 27001 certificate |
| Penetration test by third party | Continuous security validation | M | Annual pentest report |

**Go-to-Market (Sales)**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Build outbound sales team (3–5 AEs) | Revenue acceleration | L | Sales team hired + CRM configured |
| Launch enterprise support tiers (premium SLA) | Revenue expansion | M | Support tier documentation + pricing |
| Strategic partnerships (2–3 platform integrations) | Distribution leverage | L | Partnership agreements |

**Founder Scaling**

| Task | Why It Matters | Effort | Artifact |
|------|---------------|:------:|----------|
| Hire CTO (founder moves to CEO/CPO) | Organizational scaling | L | CTO hired |
| Series A fundraise ($5–15M) | Growth capital | L | Closed round |
| Establish board of directors | Governance maturity | M | Board formed |

#### 5C) Fastest Path to Tier 5 ($250M)
1. **$5M+ ARR with 120%+ NRR** — SaaS metrics that drive multiples. (L)
2. **SOC 2 Type II + ISO 27001** — removes compliance objections. (L)
3. **Strategic platform partnerships (GitHub/GitLab/JFrog)** — distribution at scale. (L)
4. **Series A closed** — external valuation anchor. (L)

---

### Tier 5: $250M

#### 5A) What Must Be True
- **Technical:** Platform-grade reliability (99.9% SLA). Global deployment. Plugin/extension ecosystem.
- **Product:** Full identity platform: developer identity + machine identity + org governance.
- **Adoption:** Industry standard for code provenance in 1–2 verticals (e.g., fintech, government).
- **Commercial:** $10–20M ARR. 100+ enterprise customers. Clear path to $50M ARR.
- **Team:** 50–80 employees. Multiple engineering teams.

#### 5B) Key Milestones
- Become the default identity provider for 1 major code hosting platform
- Win 3+ government/defense contracts requiring code provenance
- Launch marketplace for third-party identity attestation providers
- Series B fundraise ($30–50M)

#### 5C) Fastest Path to Tier 6 ($500M)
1. **Become default signing provider for GitHub or GitLab**
2. **Government/defense contract wins** (FedRAMP authorized)
3. **$30M+ ARR** with strong NRR
4. **Platform ecosystem** with third-party integrations

---

### Tier 6: $500M

#### 5A) What Must Be True
- **Technical:** Enterprise-grade platform with high availability, disaster recovery, compliance automation.
- **Product:** Developer identity platform comparable to Okta for workforce identity. Machine identity management.
- **Adoption:** Industry standard adoption. Regulatory mandates reference auths specifically.
- **Commercial:** $30–50M ARR. 500+ enterprise customers. International presence.
- **Team:** 150–250 employees. International offices.

#### 5B) Key Milestones
- Establish industry consortium for decentralized developer identity (standardization body influence)
- Launch identity marketplace (third-party attestation providers, compliance modules)
- Expand beyond code signing to full software supply chain identity (containers, packages, APIs)
- Series C fundraise ($80–120M) or strategic acquisition offer

#### 5C) Fastest Path to Tier 7 ($1B)
1. **$80M+ ARR with 130%+ NRR**
2. **Dominant market position in developer identity** (>30% market share in target segments)
3. **Platform network effects** (identity attestations across ecosystems)
4. **International expansion** (EU, APAC regulatory markets)

---

### Tier 7: $1B

#### 5A) What Must Be True
- **Technical:** Critical infrastructure for the software supply chain. Multi-protocol support (KERI, DID, Sigstore interop, OIDC).
- **Product:** The identity layer for all software development. Developer identity, machine identity, artifact provenance, compliance automation.
- **Adoption:** Millions of developers. Tens of thousands of organizations. Referenced in government regulations.
- **Commercial:** $80–150M ARR. IPO-ready or strategic acquisition by a top-5 tech company.
- **Team:** 400+ employees. Multiple product lines. International presence.

#### 5B) Key Milestones
- Auths identities used by 1M+ developers
- Regulatory mandates in US and EU reference auths as a compliance mechanism
- Platform processes 1B+ verification requests per month
- IPO or $1B+ acquisition by Microsoft, Google, or Atlassian

#### 5C) What Makes This Achievable
The decentralized identity market is projected at 70.8% CAGR through 2035. If auths captures even 1% of the projected $623B market, that's $6.2B. The software supply chain security market alone is $5.5B today growing to $10B by 2030. Comparables: Chainguard ($3.5B valuation, $892M raised, ~$100M ARR target), Wiz ($32B acquisition at 46x ARR), Snyk ($8.5B peak valuation).

The $1B outcome requires auths to become the de facto standard for developer identity — a "Stripe for identity verification in the software supply chain." This is achievable if the regulatory tailwinds (EO 14028, EU CRA, SLSA) mandate code provenance and auths is positioned as the open, decentralized alternative to vendor-locked solutions.

---

## 6) 90-Day Execution Plan (Solo-Founder Realistic)

### Guiding Principles
- **Focus on Tier 0 → Tier 1 transitions only.** Everything else is noise for 90 days.
- **Prioritize actions that create external proof points** (stars, LOIs, audit) over internal improvements.
- **De-scope aggressively.** The codebase is already strong — the gap is visibility and validation.

---

### Sprint 1: Weeks 1–2 — "Split & Go Public"
**Goal:** Execute the open-core repo split. Make the public repo visible.

**Epics:**
1. Open-core repo split
2. Prepare public repo for launch
3. Create launch content

**Deliverables:**
- [ ] Create `auths-cloud` private repo (registry-server, auth-server, oidc-bridge, cache, index, telemetry, chat-server, deploy configs)
- [ ] Move proprietary crates to `auths-cloud`; wire dependencies back to public crates via `path` or `git`
- [ ] Verify both repos build and test independently
- [ ] Fill in copyright notice in `LICENSE` (legal hygiene)
- [ ] Review and clean up any sensitive data in public repo history (no server configs, no Stripe keys, no `.env` secrets)
- [ ] Make `auths-dev/auths` public (open-source crates only)
- [ ] Write launch blog post: "Auths: Decentralized Identity for Developers" (1,500 words)
- [ ] Record 3-minute demo video (init → sign → verify)
- [ ] Submit to Hacker News, Reddit r/rust, r/netsec, r/programming
- [ ] Tweet/post announcement with demo video
- [ ] Deploy docs site to docs.auths.dev (MkDocs already configured)

**De-scope:** Do not spend time on new features. Do not refactor. The codebase is ready. Focus on the split and launch.

---

### Sprint 2: Weeks 3–4 — "Publish & Package"
**Goal:** Publish open-source crates to package managers. Do NOT publish proprietary crates.

**Epics:**
1. Publish open-source Rust crates only
2. Publish WASM verifier
3. SBOM generation and security hygiene

**Deliverables:**
- [ ] Publish `auths-crypto` v0.1.0 to crates.io
- [ ] Publish `auths-verifier` v0.1.0 to crates.io
- [ ] Publish `auths-core` v0.1.0 to crates.io
- [ ] Publish `auths-id` v0.1.0 to crates.io
- [ ] Publish `auths-sdk` v0.1.0 to crates.io
- [ ] Publish `auths-policy` v0.1.0 to crates.io
- [ ] Build and publish WASM verifier to npm (`@auths/verifier`)
- [ ] Add SBOM generation to CI (`cargo cyclonedx` or `syft`) — public repo only
- [ ] Add `SECURITY.md` vulnerability disclosure process
- [ ] Create GitHub issue templates (bug report, feature request, security report)
- [ ] Label 10 "good first issues"
- [ ] Update `auths-cloud` private repo to depend on published crates.io versions (not git refs)

**De-scope:** Python/Go bindings can wait. Focus on Rust + WASM (largest reach with least effort). Do NOT publish `auths-registry-server`, `auths-auth-server`, `auths-oidc-bridge`, `auths-cache`, `auths-index`, or `auths-telemetry`.

---

### Sprint 3: Weeks 5–6 — "Enterprise Signal"
**Goal:** Create artifacts that enterprise buyers and acquirers want to see.

**Epics:**
1. Security audit initiation
2. Design partner outreach
3. CI/CD integration

**Deliverables:**
- [ ] Send RFP to 2–3 security audit firms (Trail of Bits, NCC Group, Cure53) for `auths-verifier` + `auths-core`
- [ ] Build GitHub Action for commit verification (`auths-dev/auths-verify-action@v1`)
- [ ] Write "Auths for CI/CD" quickstart guide
- [ ] Identify and contact 10 potential design partners (Series B+ companies with supply chain compliance needs)
- [ ] Create design partner LOI template
- [ ] Write "Auths vs. Sigstore" technical comparison (differentiation positioning)
- [ ] Define pricing model draft: free (open-source CLI + self-hosted) / team (hosted registry) / enterprise (hosted registry + OIDC bridge + SLA)

**De-scope:** Do not launch hosted registry yet. Focus on self-hosted + GitHub Action path. The proprietary registry becomes the "upgrade" pitch in design partner conversations: "Try the open-source CLI for free; hosted registry for teams."

---

### Sprint 4: Weeks 7–8 — "Ecosystem Breadth"
**Goal:** Expand language support and integration surface.

**Epics:**
1. Python bindings
2. Go bindings
3. Documentation completion

**Deliverables:**
- [ ] Publish Python bindings to PyPI (`auths-verifier`)
- [ ] Publish Go bindings
- [ ] Complete SDK quickstart guides (Python, Go, JavaScript/WASM)
- [ ] Write 2 integration tutorials (GitHub Actions, GitLab CI)
- [ ] Submit talk proposal to 1–2 conferences (KubeCon, DevSecCon, RustConf)

**De-scope:** Swift/mobile bindings can wait. Prioritize server-side languages for enterprise.

---

### Sprint 5: Weeks 9–10 — "Validation"
**Goal:** Convert interest into signed LOIs. Process audit results.

**Epics:**
1. Design partner conversion
2. Security audit processing
3. Community building

**Deliverables:**
- [ ] Follow up with design partner prospects — aim for 2–3 signed LOIs
- [ ] Process security audit findings (if preliminary results available)
- [ ] Fix any critical or high findings from audit
- [ ] Write monthly project update blog post
- [ ] Engage with community contributions (review PRs, respond to issues)
- [ ] Apply for CNCF/OpenSSF landscape inclusion

**De-scope:** Do not start hosted registry. Do not hire yet.

---

### Sprint 6: Weeks 11–12 — "Package & Position"
**Goal:** Have a complete "acquisition-ready" package. Prepare for Tier 1 conversations.

**Epics:**
1. Acquisition readiness
2. Metrics and reporting
3. Next quarter planning

**Deliverables:**
- [ ] Compile metrics package: GitHub stars, npm/crates.io downloads, design partner LOIs, audit status
- [ ] Create 1-page executive summary for potential acquirers/investors
- [ ] Create technical architecture deck (10 slides)
- [ ] Write "State of Auths" report (traction, roadmap, market positioning)
- [ ] Plan Q2 priorities: hosted registry beta, first hire, enterprise pilots
- [ ] If design partners are ready: begin paid pilot negotiations ($5K–$20K)

**De-scope:** Do not start fundraising yet. Focus on validating demand first.

---

### 90-Day Success Criteria

| Metric | Target | Tier Impact |
|--------|--------|-------------|
| GitHub stars | 200+ | Tier 1 threshold |
| Open-source crates published (crates.io + npm) | 7+ | Distribution signal (open-core: client-side only) |
| Design partner LOIs | 2–3 | Enterprise validation |
| Security audit | Initiated (ideally preliminary results) | De-risks acquirer diligence |
| Conference talk | 1 submitted | Industry credibility |
| SBOM in CI | Yes | Regulatory compliance |
| Community contributors | 3–5 | Sustainability signal |
| Blog posts / content | 3+ | Awareness |

### What to Say No To (90-Day Anti-Goals)
- Do NOT build the hosted registry (too early, too much ops burden for solo founder)
- Do NOT hire yet (validate demand first, then hire into known gaps)
- Do NOT publish proprietary crates (registry-server, auth-server, oidc-bridge, cache, index, telemetry — these are your revenue moat)
- Do NOT add major new features (the codebase is feature-rich; the gap is distribution, not features)
- Do NOT chase enterprise sales without LOIs first (LOIs before contracts)
- Do NOT try to get SOC 2 (too expensive and time-consuming at this stage)
- Do NOT build a mobile app (server-side verification is the beachhead)

---

*This document should be updated quarterly as milestones are achieved and market conditions evolve. The valuation ranges assume no material changes in the competitive landscape or regulatory environment. All estimates are the analyst's professional judgment and should not be construed as guarantees.*
