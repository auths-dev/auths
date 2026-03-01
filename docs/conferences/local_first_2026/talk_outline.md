⏺ For a local-first audience, 25 minutes is tight. You need one clear thesis with 3-4 supporting segments, not a feature tour. Here's  
  how I'd think about it.                                                                                                              
                                                                                                                                       
  The thesis that ties everything together                                                                                             
                                                                                                                                       
  "Identity is the last centralized dependency in local-first software — here's how to remove it."                                     

  Every segment should serve that thesis. If a topic doesn't help the audience remove centralized identity from their stack, cut it.

  Recommended structure (25 min)

  1. The problem (3 min)
  Why every local-first app eventually hits the OAuth wall. You build beautiful offline-first sync with CRDTs/automerge, then you need
  auth and suddenly there's a hard dependency on Google/Auth0/Okta. Show the architectural contradiction: your data is local-first, but
   your identity is server-first.

  This is the hook. Every developer in the room has felt this pain.

  2. The design space (4 min)
  Brief tour of why existing solutions fail for local-first:
  - GPG: works offline but UX is catastrophic, no device management, no revocation
  - OAuth/OIDC: requires online IdP, central point of failure
  - Blockchain identity: overkill, slow, expensive, philosophical baggage
  - Sigstore: ephemeral keys, requires online CA + transparency log

  Then: what properties does a local-first identity system actually need? Offline creation, multi-device without coordination,
  cryptographic verification without phoning home, portable across platforms. This frames your design decisions as derived from
  requirements, not arbitrary.

  3. The architecture (10 min) — the meat

  This is where you earn the audience's trust. Pick 3 specific engineering decisions and go deep on each:

  a) Git as the replication layer (3 min)
  Identity state stored as Git refs (refs/auths/, refs/keri/). No new sync protocol — just git push/git fetch. The audience already
  understands Git's replication model. Show why an append-only KEL maps naturally to Git's content-addressed storage. This is your
  strongest local-first signal — you're building on infrastructure they already have.

  b) Conflict-free multi-device authority (4 min)
  This is the most technically interesting part for this audience. How do two devices establish authority over the same identity
  without a coordinator? Walk through the attestation model: identity key signs device attestations, devices can sign independently,
  the KEL provides total ordering. Show the CAS mechanism and what happens when two devices try to act concurrently. CRDT people will
  appreciate the parallels.

  c) Verification without connectivity (3 min)
  The verifier runs in WASM — same code in CI, browser, and mobile. Show that verification is a pure function: attestation chain in,
  boolean out, no network call. This is the payoff: a system where both signing and verification work air-gapped.

  4. Recovery — the honest tradeoff (4 min)

  Don't skip this. It's the most important segment for credibility. As we discussed: removing the central authority means the user owns
   their recovery. Walk through the three escape hatches (pre-committed recovery key, social recovery, org-admin recovery) and be
  explicit that if none are set up, the identity is gone. Frame it as a design choice, not a limitation.

  5. What I got wrong / lessons learned (3 min)

  This is what separates a great talk from a good one. Pick 2 concrete mistakes:
  - A design decision you reversed and why (e.g., something about the clock injection story, or the redb-to-Redis migration, or
  extracting the SDK from the CLI)
  - A place where local-first constraints forced a counterintuitive choice

  The audience will remember the mistakes more than the successes.

  6. One-slide call to action (1 min)

  brew install bordumb/auths-cli/auths && auths init — try it in 30 seconds. Link to the repo and docs.

  What to cut

  - Stripe/billing/SaaS architecture — irrelevant to this audience
  - OIDC bridge / AWS STS integration — enterprise story, wrong crowd
  - Full KERI protocol explanation — you'll lose the room. Say "KERI-inspired" and link to the spec for the curious
  - Mobile FFI / UniFFI — interesting but not 25-minute-talk interesting
  - Live demo — too risky for 25 minutes. Pre-recorded terminal GIF embedded in a slide is safer and faster

  Likely Q&A questions to prepare for

  1. "How does this compare to DIDs / Verifiable Credentials?" (Answer: we use did:keri and did:key but skip the W3C VC complexity —
  attestations are simpler and purpose-built)
  2. "Why not just use SSH keys?" (Answer: no rotation, no revocation, no multi-device, no attestation chain)
  3. "What about key discovery? How does a verifier find my public key?" (Answer: Git refs are the discovery mechanism — push your
  identity to any Git remote)
  4. "Does this work with automerge / Yjs / CRDT sync engines?" (Answer: identity layer is orthogonal to data sync — they compose, not
  compete)
  5. "What happens at scale with thousands of attestations in Git?" (Answer: SQLite index for O(1) lookups, Redis cache tier, Git
  remains source of truth)