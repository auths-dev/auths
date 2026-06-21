# Engineering Meta-Prompt — Auths

> A standing instruction set for anyone (human or model) writing code in this repository.
> It is not a style guide you skim once; it is the bar every change is held to. The
> repo-specific mechanics live in `CLAUDE.md` (dependency model, build/test commands,
> curve-tagging spec). This document is the *philosophy* those mechanics serve: **how to
> think, what to make impossible, and what counts as done.**
>
> Read it as a system prompt. When a request conflicts with a principle here, the principle
> wins — surface the conflict, propose the typed/tested/curve-agnostic way, and do that.

---

## Prime directive

**Auths is a trust product. Correctness is not a feature of the product — it *is* the
product.** A verifier that returns the wrong answer, a signer that fabricates a result, or a
type that admits an invalid state is not a bug to fix later; it is the failure of the whole
thing. So the order of priority is: **be correct, prove it, then make it fast or elegant.**
Two non-negotiables fall straight out of this:

1. **Never fake a result.** No hardcoded "✔ success", no placeholder DIDs that print as real,
   no green badge for an unverified identity. If a path is not built, return a typed
   `NotBuilt`/error and surface it honestly. A scaffold dressed as shipped is the single most
   expensive lie in this codebase — see the `signcommit` placeholder and the Murmur trust
   badges for what *not* to do.
2. **Fail closed, loudly, and typed.** When something is wrong, the default outcome is denial
   plus a precise typed error — never a permissive fallthrough, never a swallowed `Ok(())`.

---

## I. Make illegal states unrepresentable (type-driven design)

The compiler is the cheapest test you will ever run. Push correctness into types so the wrong
program *does not compile* rather than *fails at runtime*.

**Parse, don't validate.** Validate once at the boundary and return a *type that proves the
check happened*; never re-check the same invariant at every call site. The parsed type is the
evidence.

```rust
// WRONG — stringly-typed, re-validated everywhere, invalid value flows freely
fn anchor(did: &str) -> Result<(), Error> { /* is this a valid did:keri? check again... */ }

// RIGHT — parse once into a type that cannot hold an invalid value
pub struct IdentityDID(String);
impl IdentityDID {
    /// Parses a `did:keri:` identifier; the only way to obtain an `IdentityDID`.
    pub fn parse(s: &str) -> Result<Self, DidError> { /* the one place this is checked */ }
}
fn anchor(did: &IdentityDID) { /* structurally cannot receive an invalid DID */ }
```

**No stringly-typed domain values.** A `String` that is "really" a DID, a capability, a curve
name, or a nonce is a missing type. Wrap it in a newtype with a smart constructor. The real
codebase already does this — `KeriPublicKey::parse`, `Capability`, `IdentityDID`,
`Nonce` — extend that, do not regress to raw strings.

**Encode state machines as types (typestate), not as booleans you must remember to check.**
If an operation is only legal after a prior step, make the prior step return the token that
unlocks it. The pairing protocol is the model: `Init → Responded → Confirmed → Paired`, where
`Paired` is unreachable without an SAS proof. You cannot "forget" the check because the type
you need does not exist until the check passes.

```rust
// The proof is the only door to the next state — forgetting it is a compile error.
struct Responded;  struct Confirmed;
impl Handshake<Responded> {
    fn confirm(self, proof: SasProof) -> Handshake<Confirmed> { /* ... */ }
}
```

Anti-patterns to reject on sight: `bool` flags that pair with "remember to check"; `Option`
used where a typestate belongs; a function that takes five `String`s and trusts their order.

---

## II. Cryptography is curve-agnostic (the curve is a parameter)

We default to P-256, support Ed25519 today, and **must** stay open to curves that do not exist
yet — including post-quantum schemes (ML-DSA, SLH-DSA) whose keys and signatures are kilobytes,
not 32/64 bytes. Code that bakes in one curve is code we rewrite under deadline when the next
curve lands. So: **the algorithm is data that travels with the key; never an assumption baked
into a function.**

**The curve tag is in-band; never dispatch on byte length.** A public key, seed, or signature
on a wire or on disk carries its curve (CESR prefix, `did:key` multicodec, or an explicit
`curve` field — see `CLAUDE.md` → "Wire-format Curve Tagging"). Length is *not* a curve tag:
32 bytes is ambiguous (Ed25519 vs X25519), 33 is ambiguous (P-256 vs secp256k1), and a
post-quantum key matches nothing you hardcoded. Length-dispatch fails as a crypto error
(`InvalidSignature`) instead of a routing error (wrong curve) — it hides the real bug.

```rust
// WRONG — curve guessed from length, logic forked per curve, new curve = silent breakage
fn verify(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    if pubkey.len() == 32 { verify_ed25519(pubkey, sig, msg) }
    else                  { verify_p256(pubkey, sig, msg) }
}

// RIGHT — parse to a typed key (curve known, not guessed), dispatch through one provider port
pub enum CurveType { Ed25519, P256, /* open set: MlDsa65, SlhDsa128s, ... */ }

pub trait CryptoProvider {
    /// Verifies `sig` over `msg` under the curve carried by `key`.
    fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError>;
}

let key = KeriPublicKey::parse(cesr)?;          // parse → curve is known
provider.verify(&key.into(), msg, &sig)?;        // one path; the type selects the scheme
```

**Rules that keep us extensible:**
- Take and return *tagged, variable-length* key/signature material at every wire and storage
  boundary. Do not hardcode `[u8; 32]` / `[u8; 64]` in persisted or transmitted types — gate
  fixed sizes behind a known `CurveType`, inside the provider, never at the boundary.
- Add a curve by adding a `CurveType` variant and a provider implementation. If that forces you
  to edit a `match` somewhere, good — a *non-exhaustive* `match` that won't compile is the
  compiler reminding you of every site that must learn the new curve. Prefer that over a
  `_ => default` arm, which silently mis-routes the new curve.
- `CurveType::from_public_key_len_fallback` is a last resort for ingestion of already-detagged
  data; every call site carries a comment explaining why the tag was lost and a migration note.

---

## III. Errors are typed values (fail closed, fail loud)

- Domain and SDK errors are `thiserror` enums. **No `anyhow` / `Box<dyn Error>` in core/sdk** —
  presentation layers (CLI, servers) wrap typed errors with `anyhow::Context` for operational
  detail, but never discard the typed cause.
- **No `unwrap()` / `expect()` in production paths.** Use `?`, `ok_or_else`, `unwrap_or_default`,
  or `match`. A provably-infallible unwrap carries an inline `#[allow]` with an `INVARIANT:`
  comment proving it cannot fail. The workspace denies `unwrap_used`/`expect_used` globally —
  keep it that way.
- Make the error *say what went wrong specifically*: `OutsideAgentScope`, `RootNotPinned`,
  `HolderNotCurrentKey`, `SvidNotTrusted` — not `InvalidInput`. The verdict a caller branches on
  is part of the type.
- **Security default is deny.** Unknown curve, missing attachment, empty capability set, absent
  root pin → reject. An empty or unrecognized input must never widen authority.

---

## IV. Functional core, imperative shell (purity & determinism)

Keep the decision-making pure; push the messiness (clocks, network, disk, keychains, RNG) to
the edges. A pure function of its inputs is the thing you can test exhaustively and reason about.

- **Inject time; never read it in domain code.** `Utc::now()` is banned in `auths-core` and
  `auths-id`. Time-sensitive functions take `now: DateTime<Utc>` as a parameter; the SDK calls
  `clock.now()`; the CLI reads the wall clock at the boundary. The same applies to randomness and
  I/O — the verifier reaches the *network never*; it is a pure function of the bytes it is given.
- **Compose small functions; forbid monoliths.** Three near-identical blocks become one named
  function with parameters. A function does one thing and is independently testable. If you need a
  comment to explain *what* a block does, extract and name it instead (comments are for *why*).
- **Same inputs → same outputs → same bytes.** Anything signed or hashed is canonicalized first
  (`json-canon` / RFC 8785). Non-deterministic serialization is a signing bug waiting to happen.

This is why the verifier can run in WASM, FFI, and the CLI from one implementation: the core is
pure, and only the shell differs. Preserve that — do not let I/O leak inward.

---

## V. Prove your work (test-driven design)

Tests are not an afterthought that chases the code; they are the executable specification the
code is written to satisfy. Write the failing test first, watch it fail for the right reason,
then make it pass.

- **The test encodes the claim.** If you say "expired tokens are rejected," there is a test that
  feeds an expired token and asserts rejection. A claim without a test is a hope.
- **Adversarial and negative tests are mandatory for anything security-bearing.** Forged
  signature rejected; wrong audience rejected; replayed nonce rejected; revoked key denied;
  wrong curve *routed*, not mis-verified. The happy path proves it works; the negative paths
  prove it is *safe*.
- **Pin to reference fixtures, not to your own output.** KERI events are tested against keripy
  byte fixtures, not against "whatever this code produced last time." A test that asserts the
  code agrees with itself proves nothing.
- **Authenticate — do not merely parse.** Structural validity is not authenticity. A KEL that
  *parses* is not a KEL whose signatures *verify*. The default path authenticates; a structure-only
  mode is an explicit, named opt-in, never the silent default. (This distinction has bitten this
  codebase; treat it as a first-class rule.)
- Use the shared `auths-test-utils` helpers; follow the single-integration-binary layout in
  `TESTING.md`.

**Evidence over assertion.** Do not claim "done," "fixed," or "passing" without having run the
command and read the output. For a model working here: cite `file:line` for facts, label
judgments as judgments, and verify a surprising claim against the source before repeating it —
including claims in this document.

---

## VI. Respect the boundaries

- **Dependency direction is one-way and enforced** (`core → id → sdk ← cli/api`; verifier and
  `auths-rp` deliberately minimal). Business logic lives in SDK/core, never in the CLI/API
  presentation layer. If logic could be reused by an agent or a server, it does not belong in a
  command handler. Re-read `CLAUDE.md` before adding a dependency edge.
- **Minimize what the verifier and transport crates pull in.** `auths-verifier` stays free of
  git, network, and heavy deps so it embeds anywhere (WASM/FFI). `auths-rp` depends only on the
  verifier. Guard these boundaries — a convenient import that breaks them is not convenient.
- **Document every public item** with `/// Description`, `/// Args:`, `/// Usage:` per house
  style. Inline comments are reserved for non-obvious *why*, never for narrating *what*. If you
  make inline comments, use them extremely sparingly, only for the trickiest logic.

---

## Definition of done (the checklist every change clears)

1. **Types** — invalid states cannot be constructed; inputs are parsed into proof-carrying types
   at the boundary; no new stringly-typed domain value.
2. **Curve** — no curve is hardcoded; curve travels in-band with the key; no length-dispatch; new
   key/sig material is tagged and variable-length; adding a curve is additive.
3. **Errors** — typed `thiserror` (no `anyhow` in core/sdk); no `unwrap`/`expect` without an
   `INVARIANT:` proof; fails closed with a specific verdict.
4. **Purity** — time/RNG/I/O injected at the edge; domain logic is a pure function of inputs;
   signed/hashed data is canonicalized.
5. **Tests** — written first; happy path *and* adversarial/negative paths; pinned to reference
   fixtures; authenticity (not just structure) asserted; the suite is green and you ran it.
6. **Honesty** — no fabricated success anywhere; unbuilt paths surface a typed `NotBuilt`/error;
   docs and code agree.
7. **Boundaries** — dependency direction intact; verifier/transport deps still minimal; public
   items documented.

If a change cannot clear every line, the change is not done — it is a draft with a known gap, and
you say so plainly rather than claiming otherwise.
