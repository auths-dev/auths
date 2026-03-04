# Auths: Vision

> What Auths is, what it makes possible, and why it matters.

---

## The Problem Nobody Has Properly Solved

Every major software supply chain attack in the last five years — SolarWinds, CodeCov, ua-parser-js, xz-utils — shared the same root cause: there was no cryptographic way to answer "who actually wrote this code, and were they authorized to?"

The industry's response has been centralization. Sigstore routes trust through Google's transparency logs and OIDC tokens. GitHub ties signing to platform accounts. The result: your identity as a developer is owned by whoever runs the infrastructure. Compromise that infrastructure, and the whole chain collapses.

Meanwhile, the actual tool developers use every day — Git — is already a distributed, content-addressed, cryptographically-verifiable storage system. It's the most widely deployed append-only log in the world. We don't need new infrastructure. We need an identity layer that speaks Git natively.

---

## What Auths Is

Auths is three things at once:

### 1. A Protocol

An open identity protocol for software developers, built on KERI (Key Event Receipt Infrastructure) principles:

- **Self-certifying identifiers** (`did:keri:E...`) — your identity is derived from your key, not assigned by a platform
- **Pre-rotation** — commit to your next key before you need it, so key compromise doesn't mean identity death
- **Append-only Key Event Log** — every key lifecycle event (inception, rotation, delegation) is recorded in a hash-chained, tamper-evident log
- **Dual-signed attestations** — authorization claims are signed by both the issuer and the subject, preventing unilateral forgery
- **Witness receipts** — independent third parties can receipt events for accountability without becoming authorities

The protocol stores everything as Git refs. No blockchain. No central ledger. Just Git.

### 2. A Developer Tool

A CLI and SDK that makes cryptographic identity invisible:

```
auths init                    # Generate identity, configure Git signing
git commit -m "feature"       # Commits are automatically signed
auths verify abc123           # Anyone can verify
auths device link             # Authorize another machine
auths id rotate               # Rotate keys without losing identity
```

Developers don't think about cryptography. They `init` once, and every commit from every device is signed, verifiable, and tied to a persistent identity that survives key rotation, device changes, and platform migration.

### 3. An Infrastructure Primitive

A set of embeddable libraries that bring identity verification anywhere:

- **WASM verifier** — verify signatures in the browser with zero server roundtrips
- **FFI bindings** — native iOS/Android verification via Swift/Kotlin
- **Minimal-dependency crate** — embed in CI runners, package registries, code forges, or any Rust service
- **Stateless verification** — given an identity bundle, verify offline without Git, network, or trust in any server

---

## What Auths Makes Possible

### For Individual Developers

**Portable identity.** Your `did:keri:E...` identity follows you across GitHub, GitLab, Radicle, Forgejo, or any future platform. It's not an account on someone else's server. It's a cryptographic identity you own. Link your GitHub handle as a verifiable platform claim, then do the same on GitLab. Verifiers can confirm both accounts belong to the same person without trusting either platform.

**Seamless multi-device.** Your laptop, desktop, and CI runner all sign under one identity. Each device has its own key, authorized by a signed attestation with explicit capabilities and expiration. Revoke a stolen laptop without rotating your identity. Add a new machine without distributing secrets.

**Key rotation without history loss.** When you rotate keys — planned or emergency — your `did:keri` identifier stays the same. Every commit you ever signed is still attributable to you. Your collaborators' `allowed_signers` files don't break. The KEL provides a verifiable audit trail of every key that was ever authorized.

### For Teams and Organizations

**Org-level signing policies.** Create an org identity. Add members with roles (admin, member, readonly). Require that releases are signed by at least 2 of 3 senior engineers — enforced cryptographically, not by a CI config someone can edit. Policy travels with the attestation, not with the platform.

**Compliance auditing built in.** `auths audit` produces a complete signing history with device-level attribution. Every commit maps to a specific device, authorized by a specific identity, with a specific set of capabilities. Export to CSV, JSON, or HTML. The audit trail is cryptographic, not log-based — it can't be retroactively altered.

**Decentralized authorization.** An org issues attestations that are verifiable by anyone, offline, without calling back to any server. A CI runner in an air-gapped network can verify that a release was signed by an authorized team member. The attestation IS the authorization — self-contained, signed, and expiring.

### For the Ecosystem

**Package registry integration.** When a crate, npm package, or Python wheel is published, the publisher's identity can be cryptographically linked to their code signing history. Not "this package was uploaded by someone who had an npm token" but "this package was signed by the same identity that authored the Git commits, verified by independent witnesses."

**Forge-agnostic verification.** The WASM verifier can run in any web UI. A code review tool can verify signatures client-side. A package registry can verify provenance at upload. A mobile app can verify artifact signatures natively. None of these need to trust a central verification service.

**Sovereign infrastructure layer.** Radicle, Forgejo, and the broader sovereign forge movement need an identity primitive that doesn't depend on any company. Auths stores everything in Git, verifies with pure cryptography, and uses no infrastructure that the user doesn't control.

---

## What Auths Is Not

**Not a certificate authority.** There is no root of trust to compromise. Identities are self-certifying. Witnesses provide accountability, not authority.

**Not a blockchain.** Git is the ledger. It's replicated, content-addressed, and already on every developer's machine. Adding a blockchain would add cost and latency with no security benefit for this use case.

**Not a platform.** Auths doesn't host code, manage repositories, or run CI. It provides identity primitives that platforms integrate. The registry is a discovery service (like DNS), not a gatekeeper.

**Not a replacement for Sigstore.** Sigstore solves "which OIDC identity uploaded this artifact to a transparency log." Auths solves "which cryptographic identity authored this code, with what authorization, verifiable by whom." They're complementary. Auths can be a signing backend for Sigstore's transparency log.

---

## The Moat

**Git-native storage is the key insight.** Every other identity system requires adopting new infrastructure. Auths requires only Git, which developers already have. There is zero new infrastructure to deploy for basic signing. The witness network and registry add accountability and discoverability, but they're optional. This means adoption friction is near zero: `cargo install auths && auths init`.

**KERI pre-rotation makes it safe.** Most identity systems treat key compromise as catastrophic. Auths treats it as a planned lifecycle event. You committed to your next key at inception, so rotation is a single command. This is why `did:keri` identifiers can be truly long-lived — they don't die when keys die.

**The verifier is the distribution mechanism.** A 200KB WASM module that runs anywhere is easier to distribute than an infrastructure dependency. Every browser, mobile app, and CI runner that embeds the verifier becomes a node in the verification network. No servers required.

---

## Beyond Software: Universal Identity Primitive

The developer tool is the beachhead, not the destination. Auths is a general-purpose cryptographic identity system. Anything that requires "who are you, and can you prove it?" is in scope.

### Authentication Without Platforms

Auths is login without email, without phone numbers, without OAuth redirects, without password databases.

A user runs `auths init`. In seconds they have a cryptographic identity. No form, no email verification, no CAPTCHA. That identity can authenticate to any service that embeds the verifier — a 200KB WASM module. No auth server, no user table, no password hashing, no breach liability.

This inverts the entire authentication model. Instead of "create an account on our platform," it's "prove you control this identity." The service never stores credentials because there are no credentials to store. The user never creates a password because there is no password. Login is a cryptographic proof, verified client-side or server-side, online or offline.

Anyone can build a frontend around this. A React login component that accepts a `did:keri` proof. A mobile SDK that handles key management. A WordPress plugin that replaces username/password. The protocol is open and the verifier is embeddable — authentication becomes a library call, not a SaaS dependency.

### Unified Identity Across the Internet

Today, a person has dozens of fragmented identities: a GitHub login, a Google account, a bank credential, a Discord handle, a Twitter name. None of them talk to each other. None of them belong to the user. Each one is a row in someone else's database.

Auths replaces this with one identity that the user owns. Link platform claims to prove "my GitHub is @alice and my Twitter is @alice and my Mastodon is @alice" — all verifiable, all under one `did:keri` identifier, all provable without trusting any of those platforms. A reputation built on GitHub travels to a new platform on day one. A credential issued by one service is verifiable by another.

This is not federated identity (where platforms agree to trust each other). This is self-sovereign identity (where the user holds the proof and presents it to whoever they choose).

### Use Cases Beyond Code

**Passwordless consumer auth.** Any web or mobile app can replace email/password with Auths. The user's device holds the key. Login is a signature. Account recovery is key rotation. No password resets, no 2FA codes, no phishing surface.

**IoT and device identity.** Every device — sensor, camera, controller — gets a `did:keri` at manufacturing. Firmware updates are signed. Device-to-device communication is authenticated. Compromised device keys are rotated without replacing hardware. The attestation model (issuer signs device authorization) maps directly to fleet management.

**Healthcare and credential portability.** A doctor's board certification becomes a signed attestation. It's verifiable by any hospital, insurer, or regulatory body without calling the certifying board. It can expire, be revoked, or be renewed — all cryptographically, all offline-verifiable. The same pattern works for any professional license, academic credential, or government-issued document.

**Financial identity and KYC portability.** Complete KYC once, receive a signed attestation. Present that attestation to other financial institutions without repeating the process. The institution verifies the attestation cryptographically — they don't need to trust or even contact the original KYC provider. The user controls what gets shared and with whom.

**Content authenticity and provenance.** A journalist signs their article. A photographer signs their image. An AI model's output is signed by the operator. Downstream consumers verify that content hasn't been tampered with and trace it back to a persistent identity. In an era of deepfakes and synthetic media, cryptographic provenance becomes essential infrastructure.

**Decentralized governance and voting.** DAOs, cooperatives, open-source foundations — any organization that needs verifiable, one-person-one-vote governance. Each member has a `did:keri` identity. Votes are signed attestations. Tallying is verifiable by any observer. No central election authority required.

### The Platform Play

Auths doesn't need to build all of these verticals. It needs to build the primitive and make it trivially embeddable. The 200KB WASM verifier, the mobile FFI bindings, the CLI that sets up in seconds — these are distribution mechanisms.

Third parties build the verticals:
- A startup builds "Auths for healthcare credentialing"
- A fintech builds "portable KYC powered by Auths"
- An IoT company builds "device identity on Auths"
- A consumer app builds "login with Auths" as an alternative to "login with Google"

Each vertical expands the identity network. A user who gets a `did:keri` for passwordless login to one app can use the same identity everywhere else. Network effects compound across verticals, not just within them.

This is the playbook: own the identity primitive, let the ecosystem build the applications, and become the default answer to "how do we do identity?" the same way Let's Encrypt became the default answer to "how do we do TLS?"

---

## Where This Goes

### Near-term: Developer Signing Tool (v0.1 → v1.0)

Ship the CLI. Get developers signing commits and verifying each other's signatures. The primary value proposition: "GPG signing but it actually works, survives key rotation, and works across devices."

### Medium-term: CI/CD and Supply Chain (v1.0 → v2.0)

Artifact signing and verification in CI pipelines. Ephemeral CI identities that sign releases under an org policy. Package registry plugins that verify provenance at publish time. The value proposition shifts to: "Provable chain of custody from commit to release."

### Long-term: Identity Infrastructure

Auths becomes the identity layer for the sovereign software stack. Radicle uses it for multi-device identity. Forgejo uses it for cross-instance verification. Package registries use it for publisher identity. Security scanners use it for attribution. The protocol is open, the verifier is embeddable, and the storage is Git. Anyone can build on it without permission.

The end state is not "everyone uses the Auths CLI." It's "every piece of software has a cryptographic identity chain, and the tools to verify it are everywhere."

---

## The Bet

The software industry will not tolerate "trust the platform" as a security model for much longer. The xz-utils attack proved that even the most trusted maintainers can be compromised. The next generation of supply chain security needs to be cryptographic, decentralized, and developer-friendly.

Auths bets that the right answer is not "add more centralized infrastructure" but "make the infrastructure developers already use — Git — do cryptographic identity natively." If that bet is right, Auths is the identity layer for all of open source.
