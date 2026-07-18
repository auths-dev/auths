# PRD (hard) — read, deliberate, decide

> **Run mode: stop-for-approval.** These claims change crypto, key-custody,
> verification, or protocol logic; depend on an open policy decision; alter
> user-facing or wire behavior; or are perf-sensitive / statistically flaky.
> A green gate is necessary but NOT sufficient here — each needs human review
> per the review protocol. The endlessly-runnable half is PRD-mechanical.md.
> Section 13 lists the open decisions; resolved ones are in DECISIONS.md.
> Claim IDs are stable across both files. Source of record: PRD.md.

## 3 · CR — Cryptographic core
The primitives are sound; the composition has holes an adversary aims at:
storage tampering, replay, malleability, split-view. These claims close them.

- CR-1: Local KEL replay must re-verify controller signatures on every event, so a stored event whose bytes were altered after ingestion fails replay with a named error (auths-keri/src/validate.rs:506,1244; #263).
- CR-2: Presentation verification must bind each envelope to a verifier-supplied nonce and audience, and a replayed envelope reusing a spent nonce must be refused (auths-verifier/src/verify.rs:27,281).
- CR-3: Signature checks must reject malleable encodings: ECDSA P-256 high-S values and Ed25519 non-strict forms are refused on native and WASM paths alike (Cargo.toml:25, auths-keri/src/keys.rs:319, auths-verifier/src/software_verify.rs:54).
- CR-4: Default verification must obtain a second independent KEL view (witness receipt or transparency log) so a split-view of one prefix is detected rather than warned past (#349).
- CR-6: Crypto call paths must be panic-free by type: the production expect() sites become typed errors or infallible constructions (auths-crypto/src/key_ops.rs:280, auths-crypto/src/signer.rs:39).
- CR-8: The constant-time comparison gate must hold a measured separation margin of at least 10x across three consecutive CI runs, replacing today's thin margin near the control floor (#353).
- CR-9: Agent-held private keys should live in mlock'd non-swappable memory during the unlock window, retiring the documented accepted-risk entry in SECURITY.md.

## 4 · KL — Key lifecycle and custody
A signing product is its custody story. Today the gate that checks revocation
sees only keychain-resident keys, the agent trusts every same-user process,
and losing one device can mean losing the identity. Membership changes are
also tiered by volume: human device links ride establishment-grade rotation
events (superseding-recovery protection), while agent fleets join through
delegated inception or anchored interactions, so onboarding at scale never
burns the root's pre-rotation chain. The full custody architecture is three
layers, following the KERI org-identity design (keripy discussion 602) and
the measured scale data in tests/scale: a small control plane of
weighted-threshold officer and recovery keys governs the org root (KL-10 to
KL-12); human members and devices join as delegated identities with
rotation-grade membership (KL-8); agent and workflow fleets join behind
cohort anchors and, at the largest sizes, registrar shards (KL-9, KL-13).

- KL-1: The producer signing gate must check revocation and rotation state for raw-seed (Direct) and hardware or enclave-backed keys, and signing with a revoked key of any custody type must fail with a distinct error (#355).
- KL-2: The signing agent must require per-signature re-authentication or a process-bound capability, so a different same-user process requesting a signature during an unlock window is refused and audit-logged (#354).
- KL-3: Artifact signing must resolve the issuer key explicitly for multi-key identities, and an ambiguous resolution must abort naming the candidate keys instead of falling back to device_key (#352).
- KL-4: Inception must never orphan hardware keys: the git-direct initialize_keri_identity either binds every created hardware key into the KEL or deletes it on rollback (#250).
- KL-5: auths init must offer a recovery device during setup and record an explicit single-device-lockout acknowledgment in the audit log when the user declines (#321).
- KL-6: Guardian recovery must restore control after total device loss through an M-of-N guardian quorum, and any set of fewer than M guardian approvals must never rotate the identity (#278; mechanism per KL-10 split authority, keripy discussion 602).
- KL-7: Custody claims must be provable: enclave-backed keys carry a hardware attestation root (App Attest / Android Key Attestation), and a software key presenting an enclave custody claim fails verification (#277).
- KL-8: Human device membership must change through establishment events: link, unlink, and update land as rotations on the account KEL, and a membership change carried only by an interaction event fails verification for human identities.
- KL-9: Agent onboarding must not consume the root's pre-rotation chain: high-volume agent identities join through delegated inception or anchored interaction events, and provisioning 10k agents appends zero rotation events to the org root KEL (#255).
- KL-10: The org root must separate signing authority from rotation authority: officer keys sign routine events while a distinct quorum holds rotation, and a signing-only key that attempts a root rotation must be refused (#202; keripy discussion 602).
- KL-11: Root rotation must support weighted and nested thresholds so personnel changes rotate keys without changing the org identifier, and a rotation signed below threshold must be refused (#202; keripy discussion 602).
- KL-12: Removing a member from a multi-sig group must be a rotation that excludes their key, and the removed key's signature on any later group event must fail verification (keripy discussion 602).
- KL-13: Fleet enrollment should shard across delegated registrar identities, each appending cohort anchors to its own KEL in parallel, so the org root gains one event per registrar and no single KEL becomes the write bottleneck.
- KL-14: A KEL approaching 1,024 events should roll over to a new delegated identity so append and replay stay flat; the measured length-degradation curve lives in tests/scale/REPORT.md.

## 5 · VF — Verification surface
Verification is the product's public face: it runs in strangers' CI, browsers,
and gateways. Every path needs the same answer to the same evidence, and the
whole surface needs to fail closed on tampered input.

- VF-1: The verifier must accept kt>1 delegated devices: a 2-of-3 indexed signature set at threshold verifies, and a below-threshold 1-of-3 set is rejected (#207).
- VF-2: Artifact verification must be KEL-native like commit verification: the signer resolves through the KEL at signing time, and a signature from a rotated-away key fails (#206).
- VF-3: auths trust pin and auths verify must share one trust store, so a pin written by either surface is honored by both (#210).
- VF-5: Every untrusted KEL transport must carry signatures on the wire: --oobi fetches, --remote stranger resolution, and the WASM device-link, credential, and presentation entry points refuse unsigned KEL bytes (#262).
- VF-7: A lean verify build must finish a warm deep-chain verification in under 10 ms by dropping the enclave-framework linkage from the verify-only path (#272).
- VF-8: auths verify must support --require-rooted-signer so a bare did:key self-attestation is refused where policy demands a KERI-rooted identity (PR #324).
- VF-9: KEL validation must verify asymmetric key-count rotations through dual-index CESR signatures per SPEC Epic B, instead of rejecting every prior next-count mismatch (SPEC.md:126).

## 6 · PQ — Post-quantum readiness and crypto agility
Harvest-now-decrypt-later does not threaten signatures, but a KERI identity
is a long-lived commitment chain: the pre-rotation digest committed today is
the key that signs in 2032. Agility work is cheap now and impossible later.

- PQ-2: auths-keri must define CESR derivation codes for ML-DSA-65 public keys and signatures so a post-quantum rotation target is expressible in a KEL event (#276).
- PQ-3: auths-crypto must ship an ML-DSA-65 signer behind a pq feature, validated by known-answer tests from the FIPS 204 vectors (#276).
- PQ-4: A KERI rotation from an Ed25519 root to ML-DSA keys must round-trip in an integration test, with later events verifying under the new key type.

## 7 · TL — Transparency and supply chain
Auths asks strangers to trust its evidence; the evidence chain has to be
independently checkable, starting with Auths' own releases and commits.

- TL-1: An open-source transparency-log server must implement the /v1/log/* endpoints so outside parties run an independent log, proven by a conformance suite against auths-transparency (#322).
- TL-2: Release attestations must carry a Rekor inclusion proof that auths verify --release checks offline against a pinned log key (#300).
- TL-3: Release signing must resolve to the org root: an ephemeral-only chain is refused for release artifacts, closing the chain-resolution shortcut (#302).
- TL-7: Witness key rotation must exist in code (rct rot with CT re-pin), and receipts signed after rotation must fail against the pre-rotation witness key (#241).

## 10 · FT — New product surfaces
Ordered by leverage: each unlocks a user class that today has no path at all.

- FT-1: Key-state lookup should ride a verifiable map (CONIKS-style) so current-key resolution costs an O(log n) proof instead of a full KEL replay (#268).
- FT-2: Credential rails should offer pairwise per-relying-party identifiers so two verifiers cannot correlate one holder by root AID and registry (#273).
- FT-3: Credentials should support selective disclosure: a holder reveals chosen fields under predicate proofs while issuer signatures still verify (#275).
- FT-4: An independent verifier must resolve a foreign issuer's live credential revocation state through a documented propagation surface (#274).
- FT-5: Cross-org introduction should run live: org B's gateway honors a scoped A-to-B introduction, proven by a two-gateway runtime test (#279).
- FT-6: The auth-server must persist sessions and OIDC clients in Postgres so a process restart preserves active sessions (#319).
- FT-7: Client registration must enforce the oidc:client:register capability again, refusing tokens that lack it (#318).
- FT-8: The single-org self-host Postgres registry backend should implement every port-trait method end to end for one org per instance, with no cross-tenant isolation layer, retiring the NotImplemented stubs (auths-storage/src/postgres/adapter.rs:46; decision 4 in section 13).
- FT-13: The existing witness-independence gate (spans_distinct over org/jurisdiction/infra) must also gate the KEL verdict, not only the CT-bundle path, so a KEL lacking an independent witness receipt verifies locally but fails an outside-view check (decision 4; ties CR-4, TL-7).
- FT-9: auths-api should mount the org control-plane routes promised in ARCHITECTURE.md layer 6, growing past the lone health check (crates/auths-api/src/lib.rs:1).
- FT-12: auths pair --offline could complete a pairing over KERI delegation with no network path, covered by an e2e test (#203).
