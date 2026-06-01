# Multi-Device Identity: Status, Vision, Roadmap

This document is the operational source of truth for the multi-device identity
ladder: what we have shipped, what we are building toward, and the epics
between the two.

The architectural rationale for the ladder lives in
`/Users/bordumb/workspace/repositories/auths-base/essays/design/multi_device.md`.
The Stage 1 implementation plan lives in
`docs/plans/toward_keri_witnesses.md`. KERI spec-compliance findings that
shape several epics below are catalogued in `docs/plans/keri_compliance.md`.

---

## 1. Current Status

We have shipped Stage 1 of the design ladder: every device runs its own KERI
KEL, and the user's identity is a shared KEL whose controllers are those
device DIDs.

### What's working

- **Per-device KEL.** Each device has a stable `did:keri:` prefix that
  survives its own key rotations. Defined in
  `crates/auths-id/src/keri/device_kel.rs`, stored under
  `refs/auths/device-kel/{prefix}/*`.
- **Shared identity KEL.** Multi-controller KEL whose `k` list is the user's
  device DIDs. Defined in `crates/auths-id/src/keri/shared_kel.rs`, stored
  under `refs/auths/shared-kel/{prefix}/*`.
- **Pair flow.** Mutual inception verification + `rot` on the shared KEL
  adding the new device as a controller.
- **Local rotation.** A device rotates its own keys via a local `rot` on its
  own device KEL — no session, no ceremony. Pre-rotation reveal is committed
  in the same event.
- **Stolen-laptop recovery (swap).** A surviving controller signs a `rot` on
  the shared KEL that drops the lost device's DID and adds a new one in a
  single event. Wired up to `auths device pair --recover`. Implemented via
  `rot_swap_controller` in `shared_kel.rs:256-265`.
- **Duplicity detector.** `auths_verifier::duplicity::detect_duplicity`
  read-only scan flags diverging shared-KEL forks, with the resolution path
  surfaced in `auths status` and iOS `IdentityView`.

### Risks we are shipping with

These are accepted at this phase and tracked to the epic that closes them.

#### Duplicity under `kt=1` → closed by Epic 2

The shared identity KEL runs with a threshold of one — any single controller
can sign a rotation. With no witness infrastructure, two controllers can
each author a valid `rot` at the same sequence number independently,
producing a permanently diverging KEL. Mitigation: `detect_duplicity`
reports `DuplicityReport::Diverging` with conflicting event SAIDs; users
resolve by running `auths device remove <other-controller-did>` on the
trusted device. The detector is fail-open — duplicitous shared KELs do not
invalidate signatures whose signers are current controllers on their own
device KELs.

#### No witnesses → closed by Epic 3

Verifiers trust "first valid event seen locally" — no network-wide source of
truth for ordering KEL events. A compromised controller that signs a
rotation before a verifier learns of the authoritative one can present the
wrong controller set until out-of-band repair. Blast radius is bounded
because each controller device replicates the full shared KEL locally;
verifiers are limited to controllers' devices rather than arbitrary third
parties. `detect_duplicity` flags divergence on reconnect.

#### Pure removal blocked → closed by Epic 1

`rot_remove_controller` returns `RemovalNotYetSupported`. Removal that
shrinks `k` (rather than swap-in-place via `rot_swap_controller`) requires
CESR indexed-signature support that distinguishes "prior-next slot N
revealed" from "new-current slot M fresh." Until then, recovery uses swap
exclusively. See `shared_kel.rs:120-134` and `keri_compliance.md` finding
F-19.

#### Pair-URI size bound → revisited by Epic 2

The pairing URI carries the initiator's device-KEL inception event
(base64url-encoded JSON) in-band. `SubmitResponseRequest::validate()`
enforces `SHARED_KEL_INCEPTION_EVENT_MAX_BYTES = 1024`. Single-sig P-256
inceptions weigh ~300 bytes encoded, so the cap reserves headroom while
refusing to ship anything that would overflow QR capacity. Multi-sig
inceptions (Epic 2) will exceed this cap and require a different
out-of-band exchange medium (NFC, Bluetooth, file handoff).

#### KERI wire-format divergence → closed by Epic 4

Several deviations from ToIP KERI v1.1 ship today (catalogued in
`docs/plans/keri_compliance.md`): an in-body `dt` field that enters the
SAID, a signing path that clears `d`/`i` after computing `v`, a mobile FFI
duplicate of `IcpEvent` with an in-body `x` signature, and use of `1AAI`
(non-transferable) as the P-256 verkey code for transferable identities.
Internally consistent; cross-implementation interop with KERIpy / KERIox /
Signify is currently broken. Pre-launch posture means we ship and fix.

#### Trailer-format break (one-shot, complete)

Commits signed before this phase carry trailers of the form
`Auths-Signer: did:key:z…`. Verifiers now only accept
`Auths-Signer: did:keri:E…`. Pre-launch zero-user migration: dev machines
that signed under the old format must `rm -rf ~/.auths && auths init`
followed by re-signing. No code epic — this is a status acknowledgement,
not a future task. Authoritative migration note in
`docs/plans/toward_keri_witnesses.md`.

---

## 2. Vision

The end state is a multi-device KERI identity that survives realistic
attacker models and interoperates with the broader KERI ecosystem.

- **Co-signed rotations** (`kt ≥ m` of `n`). No single device can solo-rotate
  the identity; loss of one device cannot lock a user out, and compromise of
  one device cannot rewrite the controller set.
- **Network-wide event ordering.** Witness infrastructure (KERI-native,
  Rekor-style anchor, or OOBI-discovered) gives verifiers a consistent view
  of the authoritative KEL state independent of which controller they last
  synced with.
- **True device removal.** Surviving controllers can shrink the controller
  set without needing to add a replacement in the same event. Backed by
  CESR dual-index signatures.
- **Heterogeneous-curve controller sets.** A user can have a P-256 SE-backed
  iPhone and an Ed25519-backed Linux laptop as co-controllers of the same
  shared identity, with attachments that parse cleanly across curves.
- **Cross-impl interop.** Auths-produced KELs round-trip with KERIpy,
  KERIox, Signify, and KERIA. Auths-consumed KELs from those impls verify
  here without translation.
- **External federation.** `did:keri:You` is publishable to third-party
  relying parties (sigstore-style transparency log, KERI registry, or
  domain-bound discovery). Out of scope for this document; gated on
  witnesses and spec compliance landing first.

---

## 3. Roadmap: Epics

Epics are sequenced by dependency, not by calendar. Each epic names the
risk(s) it closes from §1 and its prerequisites.

### Epic 1 — Dual-index CESR signatures, true removal

**Closes:** "Pure removal blocked" risk; unblocks Epic 2.
**Prerequisites:** None — can start today.
**Why first:** Multi-sig rotations under `kt ≥ 2` (Epic 2) need the same
dual-index machinery to bind each signature to both a new-key index and a
prior-commitment index. Building it once for removal and reusing it for
multi-sig saves a re-design.

Tasks:

- **1.1 Extend `IndexedSignature`.** Add `prior_index: Option<u32>` to
  `crates/auths-keri/src/events.rs:1049-1056`. Single-index sigs
  (icp / ixn) use `None`; rotation sigs carry `Some(j)` binding to prior
  `n[j]`.
- **1.2 Dual-index CESR codec emission.** Update `serialize_attachment` in
  `events.rs:1106-1135` to choose `indexer::Codex::Ed25519_Big` (or curve
  equivalent) when `prior_index.is_some()`. Match on the parsing side in
  `parse_attachment`.
- **1.3 Code-directed attachment parser.** Replace the fixed-width
  88-char-per-siger assumption in `parse_attachment` (`events.rs:1139-1185`)
  with code-directed dispatch via cesride's width table. Required for
  mixed-curve controller sets (Vision item 4).
- **1.4 True-remove rotation validator.** In
  `crates/auths-id/src/keri/shared_kel.rs`, replace `RemovalNotYetSupported`
  with the actual implementation. Validator must verify each prior `n[j]`
  has a matching reveal among new keys, indexed by the dual-index
  attachment. Keep `rot_swap_controller` as the convenience path for the
  common recovery case.
- **1.5 CLI surface.** `auths device remove <did:keri:...>` signs a
  shrink-`k` rotation. Update `auths status` and iOS `DevicesView` removal
  action.
- **1.6 Spec-compliance fix F-15.** While here, fix the weighted-threshold
  pre-rotation check in `validate_rotation` (`validate.rs:438-454`): use
  `Threshold::is_satisfied` with explicit `verified_commitment_indices`
  instead of `simple_value().unwrap_or(1)`. The current code silently
  reduces weighted `nt` to threshold 1 — same root cause as the dual-index
  gap.

Verification: a shared KEL with three controllers can be rotated to two via
a pure removal; the resulting KEL replays cleanly under
`validate_kel_with_lookup`; KERIpy round-trips the resulting events.

### Epic 2 — Threshold upgrade (`kt ≥ m` of `n`)

**Closes:** "Duplicity under `kt=1`" risk.
**Prerequisites:** Epic 1 (dual-index sigs).
**Why second:** Duplicity is the single largest unmitigated security gap
under the current model. m-of-n co-signing kills the race — two controllers
cannot independently produce diverging valid rotations because no single
signature satisfies threshold.

Tasks:

- **2.1 Multi-sig signing protocol.** Add a partial-signature collection
  step to the pair / rotate flows: one controller drafts the event, peers
  sign it, the originator assembles the dual-index attachment when threshold
  is met. New protocol message types in
  `crates/auths-pairing-protocol/src/types.rs`.
- **2.2 Threshold-aware validators.** Audit every `simple_value().unwrap_or(…)`
  call site in `auths-keri/src/validate.rs` (compliance findings F-04, F-13,
  F-15, F-31). Replace with typed threshold satisfaction checks. Includes
  full inception-time `kt` vs `|k|` validation and `bt` vs `|b|` validation.
- **2.3 UX for partial signing.** iOS: a "co-sign rotation" notification
  flow. CLI: `auths rotate --request <event-said>` and
  `auths rotate --sign <event-said>`. Both surfaces show the threshold
  progress (1 of 2 sigs collected, etc.).
- **2.4 Recovery semantics under `kt ≥ 2`.** Define and implement: what
  happens when `m` controllers are available but `m - 1` is required for
  recovery rotation? Current Stage 1 swap relies on solo signing; under
  multi-sig, recovery requires either `m` surviving controllers or a
  pre-staged recovery quorum. Document trade-off in
  `essays/design/multi_device.md`.
- **2.5 Pair-URI medium upgrade.** Multi-sig inception events exceed the
  1024-byte QR cap. Add a fallback handshake — file handoff + QR pointer is
  the simplest; NFC and Bluetooth are alternatives. Drop the size cap
  enforcement once the fallback is wired.
- **2.6 Migration of existing kt=1 KELs.** Decide and implement the upgrade
  rotation: a `kt=1` shared KEL signs one final `rot` raising `kt` to the
  new threshold. No lock-out risk because kt=1 still allows the upgrade
  itself.

Verification: a 2-of-3 shared KEL rejects a solo rotation from any single
controller; accepts a co-signed rotation from any two; survives loss of any
one device via co-signed recovery from the remaining two.

### Epic 3 — Witness infrastructure

**Closes:** "No witnesses" risk.
**Prerequisites:** Epic 2 (multi-sig is the foundation; witnesses ratify
threshold-met events).
**Why third:** Without multi-sig, witness receipts only attest that "we
saw the kt=1 controller's solo rotation first" — they reduce duplicity but
don't eliminate the attacker model where one compromised device wins the
race. Witnesses are most useful when stacked on top of co-signing.

Sub-decisions to resolve before sub-tasks (default proposal in parens):

- **3.0 Mechanism choice.** KERI-native witnesses (default), Rekor-style
  append-only log, or OOBI-discovered witness set. Comparison lives in
  `essays/design/multi_device.md` § "Direction of travel"; pick before
  detailed planning.

Tasks (witness-flavor-agnostic):

- **3.1 Witness receipt ingestion.** `auths-keri/src/witness/receipt.rs` and
  `first_seen.rs` are scaffolded; wire them into the verifier path so a KEL
  event is "stronger" once a witness threshold (`bt`) has acknowledged it.
- **3.2 KAWA threshold validation.** Replace
  `agreement.rs:89-111`'s `bt.simple_value().unwrap_or(0)` with typed
  threshold satisfaction over verified-witness indices (compliance F-31).
- **3.3 Witness discovery / OOBI.** If we go KERI-native, implement OOBI
  exchange. If Rekor-style, implement anchor-publication and
  inclusion-proof verification.
- **3.4 Witness diversity policy.** `docs/security/witness-diversity.md`
  has the design; implement the policy enforcement during witness-set
  selection and `bt` validation.
- **3.5 First-seen replay.** First-seen policy from
  `auths-keri/src/witness/first_seen.rs` becomes load-bearing once
  witnesses ratify; ensure recovery-rotation supersedes interaction per
  spec (compliance F-30 confirms current implementation is correct, but
  needs integration tests under realistic witness flows).

Verification: a verifier with access to `bt`-of-`b` witnesses always
converges on the authoritative KEL state regardless of which controller it
last synced with directly.

### Epic 4 — KERI spec-compliance / cross-impl interop

**Closes:** "KERI wire-format divergence" risk.
**Prerequisites:** None functionally; can run in parallel with Epics 1–3.
**Why parallel:** Each fix lands one spec deviation at a time. Bundling
behind Epics 1–3 would block interop on multi-sig schedule.

Tasks (numbered by `keri_compliance.md` finding ID):

- **4.1 (F-01) Move `dt` out of event body.** Either CESR attachment group
  or external receipt anchor. Stops timestamps from entering SAID digest.
- **4.2 (F-06) Sign over finalized event bytes.** Remove the `d`/`i`-clearing
  in `serialize_for_signing` (`validate.rs:766-797`); sign the bytes that
  carry the populated SAID and prefix, matching KERIpy/KERIox.
- **4.3 (F-14) Delete mobile FFI KERI duplicate.** `crates/auths-mobile-ffi`
  reuses `auths_keri::{IcpEvent, compute_said, compute_next_commitment,
  finalize_icp_event}`. Externalize the `x` signature via
  `serialize_attachment`.
- **4.4 (F-32) Fix P-256 verkey CESR code.** `1AAJ` for transferable,
  `1AAI` for non-transferable. Update `keys.rs::cesr_prefix` and
  `auths-crypto::key_ops` together; `KeriPublicKey::parse` accepts both
  with transferability variant on the parsed type.
- **4.5 (F-16) Pre-rotation commitment domain.** Decide: hash raw pubkey
  bytes (current) or CESR-qualified bytes (KERIpy convention). Empirical
  cross-impl test required. If we keep raw, document as deliberate
  deviation.
- **4.6 (F-04, F-13) Threshold sanity at structural validation.** `kt`,
  `nt`, `bt` validated against their respective list lengths at every
  ingestion point.
- **4.7 (F-10, T-01) Seal `Said`/`Prefix` types.** Remove `Default` derive,
  scope `new_unchecked` to `pub(crate)`. Eliminates the empty-SAID forgery
  surface that interacts with finding F-06.
- **4.8 (F-35, F-36) Seal-shape spec compliance.** Migrate off `SealType`
  enum; implement the spec's Event Location seal; isolate
  `MerkleRoot` / `RegistrarBacker` extensions behind a feature flag.

Verification: KERIpy ingests an auths-produced KEL and replays it without
errors; auths ingests a KERIpy-produced KEL and validates every event.

### Epic 5 — Heterogeneous-curve controller sets

**Closes:** Mixed P-256 + Ed25519 controllers (Vision item 4).
**Prerequisites:** Epic 1 (code-directed attachment parser) and Epic 4
(P-256 verkey code fix).
**Why fifth:** Useful but lower urgency than the security epics. Most
users will pair iPhones (P-256 SE-only) with macOS (P-256 by default),
making this a secondary need.

Tasks:

- **5.1 Mixed-curve attachment serialization.** Already supported by
  Epic 1.3 (code-directed parser); validation pass to confirm
  multi-curve KELs replay end-to-end.
- **5.2 Curve-aware threshold satisfaction.** Verify
  `validate_signed_event` correctly maps each controller's CESR code to
  its position in `k[]` regardless of curve mix.
- **5.3 UX surfacing.** `auths status` and iOS `IdentityView` show each
  controller's curve. No special UX; just don't paper over the diversity.

### Epic 6 — External federation (post-Stage-4)

**Closes:** Vision item 6.
**Prerequisites:** Epics 2, 3, 4 all landed.
**Why last:** Federation is meaningful only when the local identity
substrate is sound. Out of scope for this document beyond noting it
exists; design will live in a successor doc once Epic 3 picks a witness
mechanism.

---

## 4. References

- `essays/design/multi_device.md` — ladder design rationale, decision-axis
  tables, market comparison.
- `essays/philosophy/reply_to_isi_pre_rotation.md` — semantic framing of
  linking vs. updating vs. unlinking.
- `docs/plans/toward_keri_witnesses.md` — Stage 1 implementation plan
  (mostly executed).
- `docs/plans/keri_compliance.md` — full KERI spec-compliance audit;
  source of Epic 4 task IDs.
- `docs/security/witness-diversity.md` — witness selection policy for
  Epic 3.
- `auths_verifier::duplicity` — current duplicity detector
  implementation.
- `crates/auths-id/src/keri/shared_kel.rs` — shared-KEL operations,
  including the swap-only recovery path and the `RemovalNotYetSupported`
  guard that Epic 1 lifts.
