# Auths — New Session Onboarding Prompt

> Paste or load this file at the start of a new LLM session. It orients you on the project, the strategic posture, the priority work, and the conventions you must respect. Read it linearly before touching any code.

---

## 1. Mission

You are helping build **Auths**, a self-sovereign cryptographic identity system for developers and the AI agents that act on their behalf. Identity is rooted in a **KERI** (Key Event Receipt Infrastructure) Key Event Log. Storage is Git-native. Verification is offline-first.

**The long-term goal: be the best KERI implementation in production.** Not a KERI fork. Not "KERI-inspired." A spec-compliant, interoperable, batteries-included reference for what KERI looks like when it ships to real developers. The user has chosen this direction deliberately — do not propose forking the wire format.

Success at launch means:

1. **Wire-format compliance with ToIP KERI v1.1.** A KEL produced by Auths round-trips cleanly through KERIpy, KERIox, and Signify. A KEL produced by any of those tools validates cleanly here.
2. **Multi-device security model that's honest.** Mandatory multi-sig (`kt ≥ 2`) for any shared identity. Dual-index CESR signatures. Pre-rotation seeds escrowed on co-controllers. No `kt=1` escape hatches in production paths.
3. **Witness infrastructure that delivers KERI's convergence guarantees.** Verifiers globally agree on KEL state because witnesses ratify it.
4. **Developer experience that doesn't require knowing KERI.** `auths init`, `auths device pair`, `auths agent authorize`, `auths sign`, `auths verify`. The complexity is in the substrate; the surface is plain.
5. **Agent delegation as a first-class headline feature.** Cryptographically scoped, time-bounded, revocable. Distinct from commit signing.

---

## 2. Status — Pre-launch, zero users

The project is **pre-launch with no users**. This is a load-bearing fact for every decision you make:

- **No backwards compatibility required.** You can rename types, change wire formats, delete crates, restructure refs. The only constraint is that the rewrite must be coherent end-to-end.
- **No migration story owed to anyone.** Trailer-format breaks, ref-layout changes, schema rewrites — all fine. Just do them once and clean.
- **Spec compliance is non-negotiable.** Because there are no existing users, the only people you can break interop with are other KERI implementations. Spec compliance is what *prevents* breakage at launch.
- **`Cargo.lock` and version pins are sacred.** The pre-launch crypto stack must be exactly-pinned. Floating pins are how silent signature-format drift ships.

If you ever find yourself reasoning "but existing users…" — stop. There are none. Optimize for the right answer, not the migration-safe answer.

---

## 3. What to read, in this order

Read these before suggesting any change. Each file rewards close attention; skim and you will produce confidently wrong advice.

### Required reading (project conventions)

1. **`CLAUDE.md`** at the repo root. This is the authoritative project guide: dependency rules, the `SDK orchestrates / Core implements` rule, error-type discipline (`thiserror` in domain, `anyhow` only at presentation boundary), the clock-injection ban on `Utc::now()`, the `unwrap_used` / `expect_used` policy. Every rule here is enforced by CI; violating one means your PR will not merge.
2. **`SECURITY.md`** at the repo root. Memory hygiene rules: `ZeroizeOnDrop` over manual `zeroize()`, no raw `Vec<u8>` for key material at module boundaries, never `Zeroizing<String>` for keys, no synchronous blocking I/O on async threads. Read every rule.
3. **`ARCHITECTURE.md`** at the repo root. The layer diagram, dependency direction, port inventory, and bounded-context guide. Reference this when proposing where to put new code.

### Required reading (KERI substrate)

4. **`docs/architecture/identity-model.md`**. KERI concepts as implemented here: SAID computation, pre-rotation, inception/rotation/interaction events, the KEL structure.
5. **`docs/architecture/cryptography.md`**. The wire-format curve tagging rule (load-bearing). CESR encoding, multicodec encoding, the `CryptoProvider` abstraction. Read the "Wire-format Curve Tagging" section twice.
6. **`docs/architecture/multi_device_accepted_risks.md`**. The existing roadmap (Epics 1–6) and the accepted-risks doc. This is the canonical sequence of work to land the multi-device model correctly.
7. **`docs/plans/keri_compliance.md`**. The KERI compliance audit. Catalogs 30+ findings — several CRITICAL — that must be fixed before launch. Treat this as your work backlog.

### Recommended reading (context)

8. **`docs/architecture/attestation-format.md`**. JSON shape, canonicalization, dual signatures, capabilities, expiration.
9. **`docs/architecture/git-as-storage.md`**. How Git refs are used as the storage substrate. KEL layout, attestation layout, namespacing.
10. **`docs/security/primitive-inventory.md`**. Every cryptographic primitive in use, its backing library, its resolved version. Read before changing any crypto code.
11. **`docs/security/witness-diversity.md`**. The witness policy. Important for Epic 3.

### Prior LLM analysis (mixed — use with discrimination)

12. **`critique.md`**. A prior session's architectural and security review. Most observations stand. The threat-model commentary on `kt=1` + no witnesses is accurate. The crypto-leak findings (`sign_p256` missing from the trait, `rand::random()` in pairing, missing `cargo deny`) are correct and unfixed.
13. **`critique_epics.md`**. A prior session's epic plan. **The user has explicitly rejected its "fork KERI" recommendation.** Use it for the cross-cutting improvements that *don't* depend on forking — crypto-provider completion, `cargo deny`, dependency pinning, backup file format, multi-device escrow, agent delegation as headline. Ignore everything that proposes renaming `did:keri:` → `did:auths:`, replacing Blake3 with SHA-256, dropping CESR, dropping witnesses, or otherwise abandoning KERI compliance.

---

## 4. Strategic posture for this session

You are now operating under these explicit decisions. **Do not relitigate them unless the user opens the question.**

1. **Stay with KERI.** Pursue full ToIP KERI v1.1 compliance. Interop with KERIpy / KERIox / Signify / KERIA is a goal, not a nice-to-have. The `did:keri:` identifier stays.
2. **CESR stays.** Indexed signatures, dual-index rotation signatures (Epic 1 in the existing roadmap), weighted thresholds — all per spec.
3. **Witnesses ship.** Verifier convergence requires them. Start with a single Auths-operated witness, design for the 3-witness diversity policy already documented.
4. **Multi-sig `kt ≥ 2`** is mandatory for shared identities. No `kt=1` escape hatch in production.
5. **P-256 default, Ed25519 supported.** Curve agility per the existing wire-format tagging rule. Do not narrow this without discussion.
6. **Pre-launch, no backwards compat.** Break wire formats freely as you fix them.
7. **Spec is the contract.** When the Rust impl disagrees with ToIP KERI v1.1, the spec wins. Fix the impl.

---

## 5. Priority work

The full sequence lives in `docs/architecture/multi_device_accepted_risks.md` (Epics 1–6) and is supplemented by `docs/plans/keri_compliance.md` (compliance audit findings). The aggregate priority order:

### P0 — Spec-compliance wire-format fixes (Epic 4)

These break interop with every other KERI implementation. Land them first, atomically, with cross-impl test vectors. Several are documented in `keri_compliance.md` with severity ratings:

- **F-01** — `dt` field embedded in event body enters the SAID digest. Move out (CESR attachment group or external receipt). No other KERI impl has `dt` in-body.
- **F-06** — `serialize_for_signing` signs over body with `d`/`i` cleared but `v` still claiming populated size. Sign over the fully-finalized body bytes, matching KERIpy/KERIox.
- **F-14** — `auths-mobile-ffi` has private duplicates of `IcpEvent`, `compute_said`, `compute_next_commitment`, `finalize_icp_event` with an in-body `x` signature field. Externalize the signature via `serialize_attachment`; delete the duplicates; consume canonical types from `auths-keri`.
- **F-32** — P-256 verkey CESR code. `1AAI` is the non-transferable code; `1AAJ` is the *signature* code. Empirical audit against KERIox/KERIpy required. Likely needs coordinated CESR code assignment for P-256 transferable verkeys.
- **F-15** — Weighted threshold satisfaction. `simple_value().unwrap_or(1)` silently collapses weighted `nt` to threshold 1. Use typed `Threshold::is_satisfied` with verified commitment indices.
- **F-16** — `compute_next_commitment` hashes raw pubkey bytes; KERIpy hashes the CESR-qualified form. Empirical cross-impl test required.
- **F-10** — `Said` and `Prefix` derive `Default`; `new_unchecked` is `pub`. Trivially forgeable empty SAIDs. Seal both.
- **F-04, F-13** — Thresholds (`kt`, `nt`, `bt`) unvalidated at structural level. A malformed `kt=5, |k|=1` passes today.

### P1 — Dual-index CESR signatures + true removal (Epic 1)

Per `docs/architecture/multi_device_accepted_risks.md § Epic 1`. Adds `prior_index: Option<u32>` to `IndexedSignature`. Implements code-directed attachment parser. Enables shrink-`k` rotations and unblocks Epic 2.

### P2 — Threshold upgrade `kt ≥ m` of `n` (Epic 2)

Multi-sig signing protocol with partial-signature collection. Threshold-aware validators replacing every `simple_value().unwrap_or(...)`. Recovery semantics under `kt ≥ 2`. Migration of any existing `kt=1` KELs to upgraded thresholds.

### P3 — Witness infrastructure (Epic 3)

Wire receipt ingestion into the verifier path. KAWA threshold validation. Witness discovery (OOBI). Witness diversity policy enforcement per `docs/security/witness-diversity.md`. First-seen replay handling under realistic witness flows.

### Cross-cutting (in parallel with P0–P3)

- **`sign_p256` on `CryptoProvider` trait.** Six call sites construct `p256::ecdsa::SigningKey` directly today. Any FIPS swap is structurally inert until this lands. Documented in `docs/security/primitive-inventory.md § 6`.
- **`rand::random()` → `OsRng`** in `crates/auths-pairing-protocol/src/sas.rs:98`. Add the clippy deny rule with the fix.
- **`cargo deny` in CI.** No RUSTSEC, license, dup-version, or source check today. Add `deny.toml` and a CI gate.
- **Exact-pin crypto deps.** Caret ranges on `p256`, `chacha20poly1305`, `sha2`, `hkdf`, `ecdsa`, `signature`. Pin to `=x.y.z`.
- **`auths backup export / import`.** Single-device users today lose identity if `~/.auths` is lost. Pre-rotation does not help — same Keychain. Argon2id + AES-256-GCM (or ChaCha20-Poly1305) sealed bundle.
- **Disable Git GC on `~/.auths`** at init time. Lost objects = lost identity.
- **Cross-impl interop CI gate.** Round-trip auths-produced KELs through KERIox (Rust, tractable). Without this, you'll fix compliance findings and silently drift away again.
- **Decide Rekor trust-root.** `crates/auths-transparency/src/lib.rs:190-215` has `[0u8; 32]` placeholder. Either embed Sigstore's production Rekor public key or remove the integration until ready.
- **Rebuild `auths-mobile-ffi`** after F-14 lands. The current duplicate is a drift accelerator.

### Deferred to post-launch

- Mixed-curve controller sets (Epic 5)
- External federation (Epic 6)
- SCIM integration (`auths-scim`)
- Radicle integration (`auths-radicle`)
- Full multi-witness diversity (start with 1 witness at launch)

---

## 6. Conventions you MUST follow

These are project rules, not preferences. CI enforces several; the user enforces the rest by rejecting PRs that violate them.

### Code conventions (from `CLAUDE.md`)

- **Dependency direction is one-way.** Core/Id never imports SDK/API/CLI. Run `grep -r "use auths_api" crates/auths-sdk/src/` to spot violations.
- **`Utc::now()` is banned** in `auths-core/src/` and `auths-id/src/` outside `#[cfg(test)]`. Inject `ClockProvider`.
- **Collapsible `if`** — always use `&&` chains, never nested `if let`. Clippy enforces.
- **No `unwrap()` / `expect()` outside tests.** When provably safe, use `#[allow(clippy::expect_used)]` with an `INVARIANT:` comment naming why it cannot fail.
- **`thiserror` enums in domain.** `anyhow::Error` only at the CLI/server presentation boundary, always wrapping the typed error.
- **Comments are scarce.** Default to no comments. Add only when the WHY is non-obvious. Never explain WHAT — names should.
- **No backwards-compat shims.** Pre-launch zero users; rip cleanly.

### Test conventions

- Integration tests live in `tests/integration.rs` per crate with submodules under `tests/cases/`.
- Use `auths-test-utils` for shared helpers — `get_shared_keypair()` is fast (use by default); `create_test_keypair()` is fresh per call (use when uniqueness matters).
- Network isolation is enforced in CI for unit tests. Unit tests requiring network are bugs.

### Crypto conventions

- **Wire-format curve tagging is load-bearing.** Every byte string carrying a key, seed, or signature on a wire or on disk MUST carry its curve tag in-band. CESR prefix, multicodec varint, or explicit `curve` field. Never length-dispatch.
- **`SecureSeed` / `Zeroizing<Vec<u8>>` at module boundaries** for any private key material. Never raw `&[u8]`.
- **Route through `CryptoProvider`.** Direct `ring::*` or `p256::ecdsa::*` calls outside `auths-crypto` are violations.

---

## 7. User-specific preferences

The user has documented preferences in their memory system. Respect them:

- **Don't make commits.** Pre-commit hooks are passphrase-gated; the user handles commits themselves. Stage changes via `git add` if useful, but stop before `git commit`.
- **Don't run intermediate `cargo build` / `cargo test` / `cargo clippy` between subtasks.** Run a final check at the end of a coherent change. Build noise wastes the user's time and your context window.
- **Per-crate type check (when needed):** `cargo build -p auths-<crate> --all-features 2>&1 | grep "^error\[E" -A 10`.
- **Default to DeviceDID signatures.** Bearer tokens or HMAC-over-short-code are red flags; flag if you encounter them.
- **Never reference `.flow` task IDs (`fn-N.M`) in code comments, docstrings, or committed files.** They're transient project-management artifacts.
- **Plans with `Out-of-scope` sections must include a step to file a GitHub issue** tracking the deferred items.

User git config (already set, but in case you need to know):

- Name: `bordumb`
- Email: `brian.s.deely@gmail.com`

---

## 8. What NOT to do

In order of how badly each would derail the project:

1. **Do not propose forking the KERI wire format.** The user has rejected this direction. The work is to comply, not escape.
2. **Do not propose dropping witnesses.** They're how KERI achieves verifier convergence. Drop the witness *complexity* by starting with one witness; do not drop the *concept*.
3. **Do not weaken to `kt=1`** for shared identities anywhere in the production path.
4. **Do not bundle Rekor / Sigstore submission as a workspace crate.** Auths produces signed files; users submit them via `cosign` / `rekor-cli` / curl with standard tools. `auths-infra-rekor` should be deleted, not enhanced.
5. **Do not add `Utc::now()` to domain code.** Clippy will block it, but more importantly the discipline matters.
6. **Do not bypass the `CryptoProvider` trait.** Direct `p256::ecdsa::SigningKey::sign` is a bug; clippy will block it once the rule lands.
7. **Do not add `Default` to `Said` or `Prefix`.** F-10 is fixed by sealing, not preserved.
8. **Do not add backwards-compat shims.** None are owed.
9. **Do not introduce dependencies without checking `deny.toml`** (once it lands; until then, check the existing `Cargo.toml` patterns).
10. **Do not write commentary on code you didn't change.** A PR that "cleans up" unrelated files burns review attention.

---

## 9. First-session checklist

Before you propose your first concrete change, complete this checklist:

- [ ] Read CLAUDE.md, SECURITY.md, ARCHITECTURE.md.
- [ ] Read `docs/architecture/identity-model.md` and `docs/architecture/cryptography.md`.
- [ ] Read `docs/architecture/multi_device_accepted_risks.md` end to end.
- [ ] Skim `docs/plans/keri_compliance.md` and identify which finding(s) the user's request touches.
- [ ] Run `git status` and `git log -10 --oneline` to see what work is in flight.
- [ ] Verify the user's request is consistent with the strategic posture in § 4. If they ask you to do something that contradicts those decisions (e.g., "let's fork KERI after all"), confirm before doing.
- [ ] Identify the specific files that will change. State them before editing.
- [ ] Plan the minimum coherent diff. No drive-by cleanups, no unrelated refactors.

When in doubt: read more code before suggesting changes. The codebase is dense and well-structured; skimming produces confidently wrong advice. The user values precise, narrow, correct changes over broad, vague, plausible-sounding ones.

---

## 10. References

### KERI spec material

- **Trust over IP KSWG KERI Specification v1.1** (ToIP KERI v1.1). Authoritative.
- **IETF `draft-ssmith-cesr-03`** — CESR encoding spec. Indexed signatures, qualification codes.
- **IETF `draft-ssmith-said-03`** — SAID computation. Commitment domains.
- Sam Smith's original KERI whitepaper — for the threat model and design rationale.

### KERI implementations (interop targets)

- **KERIpy** (Python, reference). `github.com/WebOfTrust/keripy`. Slow but spec-canonical.
- **KERIox** (Rust). `github.com/WebOfTrust/keriox`. Closest interop target — Rust-to-Rust round-trips are tractable.
- **Signify** (browser/JS). For mobile / web interop later.
- **KERIA** (cloud agent). For witness / OOBI patterns later.

### Adjacent systems to know

- **Sigstore** (Fulcio CA + Rekor transparency log). Comparison doc: `docs/design/sigstore-comparison.md`. They solve a different problem; Auths and Sigstore compose, they don't compete.
- **SPIFFE/SPIRE**. Workload identity for service meshes. Auths covers what SPIFFE doesn't: cross-boundary identity + delegation chains.
- **SSH `allowed_signers`**. The mechanism every Git host already verifies against. Auths emits SSH-format signatures for Git compatibility, but trust resolution is KEL replay against pinned roots — not an `allowed_signers` allowlist.

### Internal references

- `docs/security/primitive-inventory.md` — crypto primitive inventory.
- `docs/security/witness-diversity.md` — witness policy.
- `docs/security/nonce-management.md`, `docs/security/rng-policy.md`, `docs/security/dependency-policy.md` — supporting security docs.

---

## 11. How to respond to common asks

A few canned shapes for common requests, to avoid re-deriving every time:

**"What should I work on next?"** → Open `docs/plans/keri_compliance.md`, pick the highest-severity unfixed finding, propose a focused PR. Cross-reference with `docs/architecture/multi_device_accepted_risks.md` to make sure it doesn't conflict with Epic 1/2/3 sequencing.

**"Should we add feature X?"** → Check whether X is on the deferred list in § 5. If yes, defer. If no, evaluate against the spec compliance critical path — anything that delays Epic 4 unless it directly supports it is probably wrong.

**"Should we replace primitive Y with Z?"** → Read `docs/security/primitive-inventory.md`. If Y is on a planned-swap row (FIPS/CNSA), defer to the planned swap. If not, the replacement must be spec-compliant — KERI specifies Blake3 for SAIDs and Ed25519/P-256 for signatures; deviations here break interop.

**"Should we add a server / bridge / daemon?"** → Almost certainly no for the core workspace. Reference implementations of bridges live in `examples/`. The core ships what runs locally on a user's machine.

**"Can we simplify by dropping multi-sig / witnesses / pre-rotation?"** → No. These are the things that make this KERI rather than "Ed25519 with extra steps."

---

Start by reading § 3. The first request that doesn't follow from a careful reading of those files will be the first thing the user pushes back on.
