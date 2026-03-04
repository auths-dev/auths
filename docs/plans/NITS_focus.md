# NIST NCCoE Alignment: Documentation Gaps

Assessment of README and docs against the NIST "Software and AI Agent Identity and Authorization" concept paper.

---

## What already maps well (but isn't framed for the NIST audience)

| NIST Concern | Auths Feature | Where it lives |
|---|---|---|
| Agent identification | `did:keri` (stable), `did:key` (per-device), `signer_type: Agent/Human/Workload` | `docs/architecture/identity-model.md`, `docs/architecture/attestation-format.md` |
| Key management lifecycle | KERI inception, rotation, revocation, pre-rotation | `docs/getting-started/identity-lifecycle.md`, `docs/getting-started/trust-model.md` |
| Delegation of authority | `delegated_by` field, attestation chains, `verify_chain()` | `docs/architecture/attestation-format.md` (briefly) |
| Least privilege | Capability-scoped attestations, expiration | `docs/architecture/attestation-format.md` |
| Non-repudiation / audit | KEL is tamper-evident hash chain, dual signatures, Git commit history | `docs/getting-started/trust-model.md`, `docs/architecture/git-as-storage.md` |
| Offline/zero-trust verification | Stateless `auths-verifier`, no server needed | `docs/architecture/crates/auths-verifier.md` |

The building blocks exist. The problem is they're framed entirely around "developers signing commits" -- the NIST paper cares about **agents acting autonomously in enterprise systems**.

---

## Gaps: What's missing or buried

### 1. No agent-specific framing anywhere

**Problem:** The README says "Decentralized identity for individuals, AI agents, and their organizations" in the first line, then never mentions agents again. The NIST audience needs to see agents as first-class citizens, not an afterthought.

The `signer_type` enum (`Human`, `Agent`, `Workload`) exists in code and is mentioned once in `attestation-format.md` but is never explained or motivated.

**Tasks:**

- [ ] **README.md** -- Add a section "Agent & Workload Identity" after "What can you do with Auths?" showing:
  - How a CI runner or AI agent gets a `did:keri` identity
  - How an org issues a scoped attestation to an agent (`signer_type: Agent`, time-limited, capability-restricted)
  - How a human delegates authority to an agent with `delegated_by`
  - Keep it to ~20 lines with a code example

- [ ] **docs/architecture/attestation-format.md** -- Expand the `signer_type` field documentation. Currently it's one cell in a table. Add a subsection "Signer Types: Human, Agent, Workload" explaining:
  - When to use each type
  - How `signer_type` enables policy engines to distinguish human vs. automated actions
  - Brief example of an agent attestation JSON

### 2. No delegation walkthrough

**Problem:** The NIST paper asks: "How do we handle delegation of authority for 'on behalf of' scenarios?" and "How do we bind agent identity with human identity to support 'human-in-the-loop' authorizations?"

Auths has `delegated_by`, attestation chains, and `verify_chain()` -- but there's no doc showing the full delegation flow.

**Tasks:**

- [ ] **docs/getting-started/delegation.md** (new file) -- A short guide:
  - Human creates identity, links device
  - Human issues attestation to an AI agent with `delegated_by` pointing to the human's attestation
  - Agent acts, signs artifacts
  - Verifier walks the chain back to the human
  - Show the JSON at each step
  - Explain how capabilities narrow at each delegation hop
  - Link from README's new "Agent & Workload Identity" section
  - Add to mkdocs.yml 's navigation

### 3. No OIDC / OAuth bridge documentation

**Problem:** The NIST paper lists OAuth 2.0/2.1 and OIDC as primary standards. Auths already does GitHub OAuth for platform claims. But there's no doc explaining how Auths identities bridge to enterprise OIDC -- how an org can issue attestations based on OIDC tokens, or how an Auths `did:keri` can be presented alongside an OIDC flow.

**Tasks:**

- [ ] **docs/architecture/oidc-bridge.md** (new file) -- Explain the design pattern:
  - base this on the
  - Auths identity is the root; OIDC is a claim/proof that can be linked
  - GitHub OAuth flow already works this way (show it)
  - How an enterprise IdP (Okta, Azure AD) could issue attestations after OIDC verification
  - How MCP's OAuth requirement maps: the MCP server verifies an OAuth token, then the Auths attestation chain provides the cryptographic identity behind it
  - Keep it architectural, not implementation-heavy -- this is a "here's how it fits" doc

### 4. No zero-trust framing

**Problem:** The NIST paper explicitly asks about zero-trust principles for agent authorization (SP 800-207). Auths IS zero-trust by design -- no implicit trust, verify every attestation, no central authority -- but the docs never use the phrase or map to zero-trust concepts.

**Tasks:**

- [ ] **docs/getting-started/trust-model.md** -- Add a section "Zero-Trust by Design" near the top, mapping:
  - "Never trust, always verify" = every attestation is verified cryptographically, no server trust
  - "Least privilege" = capability-scoped attestations with expiration
  - "Assume breach" = pre-rotation means key compromise is survivable
  - "Verify explicitly" = dual signatures, chain verification, witness receipts
  - Keep it to ~15 lines, referencing SP 800-207 in passing

### 5. No enterprise deployment or CI/CD agent story

**Problem:** The NIST paper's use case #3 is "Enterprise AI agents for software development and deployment." The vision doc mentions CI/CD but the actual docs don't show how a CI runner gets an identity and signs under an org policy.

**Tasks:**

- [ ] **docs/getting-started/sharing-your-identity.md** -- Expand the "Export an identity bundle for CI" section into a fuller "CI/CD & Automated Agent Identity" section:
  - How to create a dedicated agent identity (not just export a human's bundle)
  - How to issue a time-limited, capability-restricted attestation to a CI agent
  - How the CI agent signs artifacts and the org verifies them
  - Show the `signer_type: Workload` usage

### 6. No MCP integration story

**Problem:** MCP is the first standard listed in the NIST paper. There's no mention of MCP anywhere in Auths docs.

**Tasks:**

- [ ] **README.md** -- In the new "Agent & Workload Identity" section, add one sentence: "Auths attestations can serve as the cryptographic identity layer behind MCP's OAuth-based authorization, providing verifiable delegation chains from human principals to AI agents."

- [ ] **docs/architecture/oidc-bridge.md** -- Include an "MCP Integration" subsection showing where Auths fits in the MCP auth flow (MCP uses OAuth; Auths provides the identity that the OAuth token represents)

### 7. No comparison to SPIFFE/SPIRE

**Problem:** The NIST paper mentions SPIFFE/SPIRE for workload identity. Auths solves a similar problem differently. A brief comparison would help the NIST reader understand positioning.

**Tasks:**

- [ ] **docs/architecture/oidc-bridge.md** (or rename to `enterprise-integration.md`) -- Add a "Comparison with SPIFFE/SPIRE" subsection:
  - SPIFFE: centralized SPIRE server issues SVIDs, runtime attestation
  - Auths: self-certifying, no central issuer, Git-native, works offline
  - Complementary: SPIFFE for service mesh workload identity, Auths for developer/agent identity with delegation chains
  - 10-15 lines max

### 8. No logging/audit trail documentation

**Problem:** The NIST paper asks: "How can we ensure that agents log their actions and intent in a tamper-proof and verifiable manner?"

The KEL IS a tamper-proof log. Attestation lifecycle is tracked in Git commits. But there's no doc that explicitly frames this as an audit capability.

**Tasks:**

- [ ] **docs/getting-started/trust-model.md** -- Add a section "Audit Trail" after the trust boundaries summary:
  - KEL = tamper-evident history of every key operation
  - Attestation Git refs = lifecycle audit (creation, extension, revocation as commits)
  - Seals = cryptographic binding of external events to the identity timeline
  - Every agent action that produces a signature is traceable through the attestation chain back to the authorizing human
  - 10-15 lines

---

## Summary of file changes

| File | Action | Priority |
|---|---|---|
| `README.md` | Add "Agent & Workload Identity" section with MCP mention | High |
| `docs/getting-started/delegation.md` | New file: delegation walkthrough with agent examples | High |
| `docs/getting-started/trust-model.md` | Add "Zero-Trust by Design" and "Audit Trail" sections | High |
| `docs/architecture/attestation-format.md` | Expand `signer_type` documentation | Medium |
| `docs/architecture/oidc-bridge.md` (or `enterprise-integration.md`) | New file: OIDC bridge, MCP integration, SPIFFE comparison | Medium |
| `docs/getting-started/sharing-your-identity.md` | Expand CI/CD section for agent identities | Medium |

---

## Tone guidance

The NIST audience is enterprise security architects and standards people. They don't need to be sold on decentralization -- they need to see:

1. How Auths maps to their existing frameworks (OAuth, OIDC, SPIFFE, zero-trust)
2. How it solves the specific problems the paper raises (delegation, audit, non-repudiation, key management for agents)
3. Concrete examples, not philosophy

The vision doc is great for investors/community. The NIST-facing docs should be drier, more standards-aware, and show the mapping explicitly.
