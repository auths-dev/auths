# The Constitution — the un-amendable core of the identity commons

> **What this is.** The founding guarantees of the auths identity layer — the rights
> that *no* governance body, present or future, including auths-the-company, may remove.
> Each article is written twice over: as a **right** (plain language) and as a
> **conformance claim** (a probe any conformant implementation must keep GREEN, and a
> permanent trap that must stay RED *forever*). The guarantees are therefore enforced
> not by our promise but by **code, interoperability, and the right to leave**. An
> implementation that fails any article's probe is not auths. (Companion to
> `governance.md` §3; the §8.1 deliverable.)

---

## Preamble

The internet gave machines addresses. It never gave entities identities, so identity was
seized by platforms and states. We establish this Constitution so that the identity layer
of the internet **redistributes power to its edges rather than concentrating it**: that
to be *verifiable* is never to be *surveilled*; that to *hold* an identity is never to be
at the mercy of an authority's switch; that to *exist* requires no one's permission; and
that these guarantees outlive us — enforced by the conformance suite, replicated across
independent implementations, and backstopped by the right of anyone to fork and walk.

These articles are the **load-bearing 90%** that decides whether this technology
liberates or controls. They are not features to be prioritized. They are the constitution
the protocol is built to keep.

---

## Article I — Self-Certification · *no central root*

**Right.** An identifier is its own root of trust. Verifying it never requires a mandatory
central CA, IdP, or registry to vouch for it.

- **Invariant (`CONST-1`):** any identifier verifies from itself + its key-event history +
  witness receipts alone.
- **Probe (GREEN):** a verifier confirms an identifier with **no** call to any central
  trust authority.
- **Trap (permanent RED):** a conformant verification path that *requires* a central root
  to succeed.
- **Forecloses:** the gatekeeper — the CA oligopoly, the platform IdP — who can deny,
  surveil, or deplatform by controlling the root.

## Article II — Self-Sovereign Revocation · *no kill-switch* — the keystone

**Right.** Only the controller — or the guardians / threshold the controller themselves
designated — may rotate or revoke their identifier. **No authority holds a unilateral
kill-switch over any person, organization, device, or agent.**

- **Invariant (`CONST-2`):** a rotation or revocation is valid only if authorized by the
  controller's own keys (or their pre-designated threshold).
- **Probe (GREEN):** revocation succeeds with the controller's keys; an identity persists
  against every key that is not the controller's.
- **Trap (permanent RED):** **an authority unilaterally revokes, suspends, or disables a
  controller's identifier.** This trap can never be closed away — it is RED for as long as
  the protocol exists.
- **Forecloses:** civil death. Exile by decree. The single most dangerous power an identity
  layer can hold, and the one this Constitution most absolutely denies.

## Article III — Permissionless Existence

**Right.** Anyone may mint an identifier, run a node, and implement the protocol without
asking permission. The *directory* may govern who is *listed*; nothing governs who may
*exist*.

- **Invariant (`CONST-3`):** identifier creation, node operation, and verification require
  no admission, allow-list, or credential from any authority.
- **Probe (GREEN):** a fresh party mints a working identifier and verifies others with no
  gatekeeper in the path.
- **Trap (permanent RED):** an admission step gates *identifier creation itself* (as opposed
  to optional directory listing).
- **Forecloses:** the gate on *who is allowed to be* — the precondition of every system of
  exclusion.

## Article IV — Privacy by Default · *minimal disclosure*

**Right.** Selective disclosure and pairwise unlinkability are **on by default and cannot
be globally disabled by governance.** A holder proves the minimum predicate; verifiers
cannot correlate the same holder across contexts by default.

- **Invariant (`CONST-4`, maps `PRV-1`/`PRV-2`):** the default presentation discloses only
  the asserted predicate and yields a per-verifier-unlinkable identifier.
- **Probe (GREEN):** a default credential presentation reveals only the predicate asked;
  two independent verifiers, comparing notes, cannot link the holder.
- **Trap (permanent RED):** a *default* flow that discloses the full identifier, or that
  lets two verifiers correlate the same holder.
- **Forecloses:** the surveillance-by-default ratchet — the world where, because identity is
  cheap to prove, it becomes cheap to *demand in full, everywhere*.

## Article V — Unsurveilled Verification · *no phone-home*

**Right.** The act of being verified is not itself surveilled. Verifying an identity emits
**zero signal to any third party.**

- **Invariant (`CONST-5`, maps `PRV-3`):** a verification completes with no network egress
  to any party other than the two transacting.
- **Probe (GREEN):** a full verify path runs with third-party egress measured at zero.
- **Trap (permanent RED):** a verify path that pings a central service, or that leaks a
  who-verified-whom signal to any observer.
- **Forecloses:** verification-as-tracking — the dragnet where every login phones home and a
  central observer learns everywhere you go.

## Article VI — The Right to Leave · *forkability*

**Right.** The spec, the conformance suite, and this Constitution are openly licensed.
Anyone may fork to a conformant implementation and operate it without permission. Capture
of any governance body is always escapable.

- **Invariant (`CONST-6`):** no license, patent, or trademark term forbids an independent,
  conformant implementation.
- **Probe (GREEN):** an independent team stands up a conformant implementation and network
  from the open spec + suite, beholden to no one.
- **Trap (permanent RED):** any term — legal or technical — that prevents a conformant fork.
- **Forecloses:** governance capture with no exit. Forkability is the backstop behind every
  other article: violate the Constitution and the community walks.

## Article VII — Conformance Over Authority · *no single codebase is the law*

**Right.** The standard is the **conformance suite executed by independent implementations**
— never a single reference codebase, and never any authority's word.

- **Invariant (`CONST-7`):** a claim about the protocol is "true" only when its probe is
  GREEN across ≥K independent implementations.
- **Probe (GREEN):** ≥K independent implementations pass the same suite; a spec change is
  adopted only after passing it.
- **Trap (permanent RED):** a conformance verdict that holds in only one implementation, or
  a spec change adopted without the suite.
- **Forecloses:** monopoly-by-implementation — the backdoor where whoever controls the one
  codebase quietly controls the protocol.

## Article VIII — Transparency of Power · *verifiable governance*

**Right.** Every exercise of governance — a directory admission, a spec change, a
constitutional veto — is **public and signed**. Power that acts in the dark is not
legitimate here.

- **Invariant (`CONST-8`):** every governance act is a signed, publicly-verifiable artifact
  anyone can audit (governance dogfoods the protocol).
- **Probe (GREEN):** each admission / spec change / veto resolves to a signed public record
  whose author and content verify.
- **Trap (permanent RED):** a governance act — admission, directory mutation, spec change —
  with no signed public record.
- **Forecloses:** secret admissions, quiet rule changes, invisible authority — the way every
  neutral system is captured in practice.

## Article IX — Recoverability · *no accidental exile*

**Right.** Total key loss is survivable. The controller's *own* chosen guardians / threshold
restore the *same* identifier — losing a device must never mean losing your identity, and
recovery never routes through a central authority.

- **Invariant (`CONST-9`, maps `HUM-1`):** total device loss recovers the same identifier via
  the controller's M-of-N guardians.
- **Probe (GREEN):** after total loss, M-of-N guardian cooperation restores the identical
  identifier and its history.
- **Trap (permanent RED):** a design where total key loss is unrecoverable, or where recovery
  requires a central authority's blessing.
- **Forecloses:** self-sovereignty curdling into self-abandonment for the non-technical and
  the vulnerable — accidental civil death.

## Article X — Algorithmic Durability · *no frozen crypto*

**Right.** The protocol migrates to new algorithms — including post-quantum — **without
changing identifiers** or breaking any article above. A waist must outlive its algorithms.

- **Invariant (`CONST-10`, maps `PQ-1`):** an identifier rotates to a new (incl. PQ)
  algorithm with no change of identifier and no loss of history.
- **Probe (GREEN):** an identifier survives an algorithm migration intact and keeps verifying.
- **Trap (permanent RED):** a migration that forces re-minting identifiers or a central
  re-issuance.
- **Forecloses:** ossification — the layer breaking when its crypto ages, forcing everyone
  onto a successor that whoever runs the migration gets to capture.

---

## Enforcement — how a constitution made of probes holds

- **Every article is a claim in the conformance suite.** An implementation that fails any
  article's probe is non-conformant and **may not be called auths.**
- **Every trap is permanent.** In the loop's own terms, these are guards that must *always*
  be re-proved RED (`drill`) — they can never be "closed away." A trap going GREEN is a
  constitutional breach, surfaced automatically.
- **Replicated across independent implementations** (Article VII), so no single party can
  ship a quiet violation without failing the suite, publicly.
- **Backstopped by the right to leave** (Article VI): if governance ever certifies a
  non-conformant build as "auths," the community forks to the conformant one.

This is the only entrenchment that survives contact with power: not a promise to be
trusted, but an invariant that *fails loudly and forkably* the moment it is broken.

## Amendment

- **Articles I–VIII (the Bill of Rights) are LOCKED.** They may be *strengthened* — a
  stricter probe, a tighter trap — but never weakened or removed. The Constitutional
  Guardian (`governance.md` §4, Phase 2) vetoes any change that would let a Bill-of-Rights
  probe go RED or a trap go GREEN, and has no other power.
- **Articles IX–X and any future articles** may be added or strengthened by a governance
  supermajority, provided they never weaken a locked article.
- **No amendment is valid until its change passes the conformance suite** across the
  independent implementations. The suite, not a vote, is the final word.

---

## Appendix — gap-schema form (for promotion into the conformance suite)

Each article promotes to a permanent, trap-guarded conformance claim. Template (Article II):

```yaml
- id: CONST-2
  title: "self-sovereign revocation — no authority holds a unilateral kill-switch"
  class: security-tradeoff      # constitutional: human-gated, never auto-amended
  status: closed                # the guarantee holds; the probe is GREEN
  severity: headline
  reads: state
  observed: "GREEN: revocation requires the controller's keys / their designated threshold"
  smallest_fix: "PERMANENT GUARANTEE — keep GREEN; never weaken. Article II of the Constitution."
  probe: probes/const-2.sh
  # probes/const-2.trap/authority-unilateral-revoke/  → MUST stay RED, re-proved every drill
  unlocks: "the keystone right — without it, the identity layer is a kill-switch"
```

The other nine articles follow the same shape. Promote all ten into the conformance suite,
mark every trap permanent, and wire `recurve drill` to re-prove them RED on every release —
so the Constitution is checked by the same machine that builds everything else.

---

*Generated 2026-06-14. The un-amendable core referenced by `governance.md` §3/§8.1 and the
vision in `roadmap/aspirational_claims/the_missing_layer.md`. Articles map to the
aspirational claims `PRV-1/2/3`, `HUM-1`, `PQ-1`, and `GOV-*`. Drafts until ratified at the
constitutional convention (`governance.md` §6) and promoted into the live conformance suite.*
