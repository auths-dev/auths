# Governance — the constitution of an identity commons

> **Why this document exists.** Identity is not a feature; it is the substrate of
> power — whoever decides who is *seen*, *trusted*, and *allowed to act* holds the
> deepest lever in any society. If auths becomes the internet's identity layer, that
> lever is being built for everyone, and handed to whoever the governance says. The
> cryptography is morally neutral and **radically dual-use**: the *same* properties
> that liberate can control. Which world we get is decided downstream of the math —
> by the **defaults**, the **governance**, and the **law**. This document is how we
> make the liberating one on purpose, and weld it in before the world that wants the
> cage gets its hands on the lever.

---

## 1. The stakes (why governance is existential, not administrative)

A universal, self-sovereign identity layer is one artifact with two faces.

**The liberation face.** Platform disintermediation (Google/Apple/Okta no longer sit
between you and every service); *prove-without-revealing* (selective disclosure +
unlinkability make verification and privacy stop being opposites); inclusion (a
self-sovereign identifier for the billion-plus with no formal ID); resistance to
arbitrary erasure (your identity is your keys, not a company's database row); and an
**agentic internet that stays accountable** instead of drowning in unattributable AI
noise. Done right, it is the largest re-distribution of power toward individuals since
the open web.

**The control face — from the very same code.** When proving identity becomes
frictionless, *demanding* it becomes frictionless — and the pressure to demand it is
relentless. The danger is a ratchet from "anonymous by default" to "identified by
default": age-verification, real-name, and KYC creep everywhere, cheaply mandated.
Anonymity and pseudonymity are load-bearing for democracy (whistleblowers, dissidents,
journalists, the vulnerable). Revocation — a beautiful feature — becomes *civil death*
if an authority, not the controller, holds the switch. And a "decentralized" layer
**captured** by a company, a state, or a witness cartel is simply the most powerful
surveillance-and-control instrument ever built, wearing the costume of self-sovereignty.

**The conclusion that drives everything below:** we are not choosing *whether* identity
gets a universal layer — the agentic internet forces that. We are choosing *which kind*.
The technology to do it well and the technology to do it terribly are the **same
artifact**, separated only by defaults and governance most people will never read. So
the defaults and the governance must be **constitutional** — designed first, entrenched
hard, and not removable by whoever later wants the cage.

## 2. The three constitutional choices

Three design decisions are *political acts wearing the costume of engineering.* They are
the hinge between the two faces, and they are non-negotiable.

1. **Privacy by default — not disclosure by default.** Selective disclosure and
   pairwise unlinkability are *on by default and cannot be globally disabled by
   governance.* (This is why `PRV-1/2/3` are constitutional, not features.)
2. **A neutral commons — not capture.** No single entity — including auths-the-company,
   any state, or any operator cartel — can unilaterally change the wire format, capture
   the directory, or revoke the layer. (This is why `GOV` is the whole political stake,
   not a footnote.)
3. **Self-sovereign revocation — not authority revocation.** Only the controller (or
   their chosen guardians/threshold) can revoke their own identity. No authority gets a
   unilateral kill-switch over a person, org, device, or agent.

## 3. The core mechanism — a constitution enforced by *probes*, not promises

A governance promise is worth nothing if a future body can quietly delete it. So we do
not write the constitution as prose to be trusted; we write it the way this whole
project writes everything — **as falsifiable claims, each with a probe a conformant
implementation must pass and a trap that must stay RED forever.** Dogfood the method
onto the governance itself.

The **un-amendable core** is a set of constitutional claims. Examples:

| Constitutional claim | Probe (must stay GREEN) | Permanent trap (must stay RED) |
| --- | --- | --- |
| Privacy by default | a default integration discloses only the asserted predicate; two verifiers cannot correlate the same holder | an implementation that links a holder across two verifiers by default |
| Self-sovereign revocation | only the controller / their threshold can revoke their identifier | **an authority unilaterally revokes a controller** — RED, forever |
| No central root | verification needs no mandatory central CA/IdP/registry | a conformant path that requires a central trust root |
| Permissionless | anyone can mint an identifier, run a node, implement the spec | an admission step that gates *identifier creation* (vs. directory listing) |
| No phone-home | verification emits zero signal to a third party | a verify path that pings a central service |

Because these are enforced by the **conformance suite** (the `interop/` precedent,
generalized) and by **multiple independent implementations**, a governance body
*cannot* remove a guarantee without producing an implementation that fails conformance —
visibly, publicly, and forkably. **The constitution is enforced by code and interop, not
by trust.** That is the only kind of entrenchment that survives contact with power.

## 4. The institution — staged from company-led to neutral commons

Credible neutrality is earned over a disclosed path, not declared on day one.

- **Phase 0 — Disclosed interim authority (now).** auths-the-company stewards the spec
  and counter-signs directory admissions. This is **acceptable only because it is
  disclosed as interim and time/milestone-boxed** — the directory itself shows the
  interim status (already decided in `auths-network` ADJUDICATE-2). An undisclosed
  company-controlled identity layer is the cage; a disclosed, exit-committed one is a
  bridge.
- **Phase 1 — A neutral foundation.** A nonprofit (a new "Identity Commons" foundation,
  or a home under the Linux Foundation / an ISRG-style 501(c)(3)) holds the trademark,
  the conformance suite, and the spec process. The company becomes *one contributor
  among many*; it can no longer change the protocol alone.
- **Phase 2 — Separation of powers.** Three bodies, none holding all the levers:
  - a **Technical Steering** group (the spec, IETF-style "rough consensus and running
    code," conformance suite as the arbiter);
  - a **Directory & Network** group (witness admission policy, the diversity rule that
    no operator or jurisdiction dominates a threshold);
  - a **Constitutional Guardian** (the *only* job is ensuring the §3 un-amendable core
    holds; it can veto a change that fails a constitutional probe, and nothing else).
  Multiple independent implementations pass the suite, so no single codebase dictates.
- **Phase 3 — Credible neutrality.** The vendor-exit drill (`GOV-1`) passes for real:
  auths-the-company can disappear and **nothing breaks** — identifiers still resolve,
  the directory still runs, the spec still evolves. The commons is self-sustaining.

## 5. Capture-resistance (the concrete mechanisms)

- **Separation of powers** (§4 Phase 2): spec ≠ directory ≠ constitution. Capturing one
  body captures nothing decisive.
- **Diversity rules**, already in the witness design: receipts counting toward a
  threshold must come from distinct operators (and optionally distinct jurisdictions) —
  the CA-oligopoly, default-closed.
- **Conformance-as-standard, not a codebase.** The standard is the suite + ≥K
  independent implementations. A single reference implementation is never the law.
- **Radical transparency.** Every governance act — admissions, spec changes, guardian
  vetoes — is public and *signed* (dogfood: governance decisions are themselves
  verifiable artifacts anyone can audit).
- **Forkability is the ultimate check.** The spec, the suite, and the constitution are
  open. If governance is captured, the community can fork to a conformant implementation
  and walk — credible exit for *the community*, not just for one user.
- **State-resistance by construction.** Because the protocol is self-sovereign and
  privacy-preserving, even a body that captures a *governance seat* cannot retroactively
  surveil or unilaterally revoke — the §3 core, enforced by conformance, forbids
  shipping those powers. The worst a captured body can do is fail the suite and get
  forked.

## 6. Transition commitments (the credible exit, on the record)

Neutrality is a promise only if it has triggers and dates.

- **Define the triggers now.** Control transfers from company to foundation at named
  milestones — e.g. *N independent witnesses live*, *M independent conformant
  implementations*, *the directory opens to permissionless (conformant) admission*.
- **Time-box the interim authority.** A public sunset for company counter-signing of
  admissions; disclosed in the directory until it ends.
- **A constitutional convention.** When the foundation forms, the founding constitution
  (§3) is ratified and its un-amendable clauses locked — amendable only by a
  supermajority that *cannot* touch the locked core.
- **Assign the IP and trademark to the foundation** at Phase 1, irreversibly.

## 7. The honest hard problems (no pretending)

- **No governance is fully un-capturable.** Conformance + forkability is the best
  available entrenchment, not a guarantee. A determined state can mandate a
  *non-conformant national fork* and call it "auths."
- **Geopolitical fragmentation.** The EU (eIDAS wallets), India (Aadhaar), China (state
  stack) will want control. Bridge to national IDs as a *check* on them, or refuse and
  risk being routed around? An unresolved, load-bearing question.
- **Funding the commons without capturing it.** Whoever pays for the foundation must not
  thereby own it. (ISRG/Let's Encrypt is the model to study.)
- **Revocation politics for orgs and the vulnerable.** Guardians and thresholds decide
  who *really* holds the keys for a company, a minor, an at-risk person. Self-sovereign
  in the spec can still be coercion in practice.
- **The gravity pulls toward the cage.** Power, commerce, and the state all prefer to
  *know who they're dealing with*. The liberating version does not happen by default; it
  is *won*, politically, and defended.

## 8. Immediate next steps

1. **Write the founding Constitution** as `roadmap/governance/constitution.md` — the §3
   un-amendable claims, each with its probe and permanent trap, in the demos' gap schema
   so they can be promoted into the conformance suite. *Govern with the method you
   already trust.*
2. **Formalize the disclosed-interim-authority + transition triggers** (§6) as an
   ADJUDICATE-style record, public from day one.
3. **Choose the neutral-home path** (new foundation vs. Linux Foundation vs. ISRG-style
   nonprofit vs. Trust-over-IP) — Open Question #1 below; pick before Phase 1 is forced.
4. **Keep `PRV` and `GOV` claims out of the "later" pile.** They are constitutional, not
   features; deferring them is choosing the cage by omission.
5. **Commit to multiple implementations.** The conformance suite is the standard; fund a
   second independent implementation early, precisely so no one (including us) is the law.

## Appendix — precedents to copy and to avoid

- **IETF** — "rough consensus and running code," conformance over authority. *Copy: the
  spec process and the no-single-owner ethos.*
- **ISRG / Let's Encrypt** — a neutral 501(c)(3) running planet-scale critical
  infrastructure, funded without capture. *Copy: the funding + neutral-steward model.*
- **Linux Foundation / CNCF (Sigstore's home)** — a credible neutral host for security
  infrastructure. *Copy: the hosting + trademark-stewardship structure.*
- **Apache** — the foundation owns the IP; meritocratic contribution. *Copy: IP custody.*
- **W3C / DIF / Trust-over-IP** — the standards homes identity work already lives near.
  *Copy: the standards-body legitimacy; avoid their slow, low-adoption fate by leading
  with the wedge.*
- **Bitcoin / Ethereum** — instructive on credible neutrality *and* on governance
  capture, client politics, and contentious forks. *Avoid: governance by whoever shouts
  loudest; learn: forkability as a real check.*
- **Signal Foundation** — a nonprofit stewarding a privacy tool against commercial
  gravity. *Copy: privacy as a non-negotiable mission, structurally protected.*

---

*Generated 2026-06-14. Companion to `roadmap/aspirational_claims/the_missing_layer.md`
(the vision) and `auths-network/.recurve/ADJUDICATE.md` (the disclosed-interim-authority
decision). The vision says what to build; this says how to keep it from becoming the
thing it was meant to replace.*
