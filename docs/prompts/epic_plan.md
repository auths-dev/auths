# Auths — Launch-Readiness Epic Plan

> Path from the current pre-launch state to a spec-compliant, interoperable KERI implementation. Epics A–H. Sequencing, estimates, and the critical path are in the summary below.

## Grounding & method

Every **Files** path, line number, and code snippet in this plan was verified against the working tree on branch `dev-keriCompliantDevices` this session — not taken from the audit or design docs, several of which are behind this branch. `keri_compliance.md` finding IDs (`F-NN`, `T-NN`) are used only as **traceability labels**; the underlying facts were re-confirmed in source. Three doc-derived claims were caught and corrected against code:

- **`sign_p256` / `generate_p256_keypair` already exist** on the `CryptoProvider` trait (`crates/auths-crypto/src/provider.rs:202,214,228`) — `primitive-inventory.md §6` says they don't. Epic E is rerouting bypasses, not adding methods.
- **`deny.toml` + a `cargo-deny` CI gate already exist** (`.github/workflows/cargo-deny.yml`), and `sas.rs:98`'s `rand::random()` is already fixed (`sas.rs:179-186`). `primitive-inventory.md` predates all three.
- **The verifier already enforces delegation scope-down** via capability intersection across a chain (`crates/auths-verifier/src/verifier.rs:137-165`). Epic G is *not* "add scope-down to the verifier"; the gaps are narrower (below).

Conversely, the KERI wire-format findings driving Epic A were each confirmed *still open* in code (`dt` at `events.rs:364`; `serialize_for_signing` clears `d`/`i` at `validate.rs:770-792`; `keys.rs` still rejects `1AAJ`). This branch has done crypto/deps hardening but not the wire-format compliance work — which is why Epic A is the bulk of what remains.

---

## Summary

### Priority & estimates

| Epic | Name | Status (code-verified) | Focused | Buffered ×1.5 |
|---|---|---|---|---|
| **A** | Spec-compliance wire-format fixes | Supplements roadmap Epic 4; closes F-01/F-06 (CRIT) + F-03/04/05/07/08/10/13/15/16/22/23/35/36/37, C-04/05, T-01/05/07 | 24 d / 4.8 wk | 36 d |
| **B** | Dual-index CESR signatures + true removal | Supplements roadmap Epic 1; closes F-18/F-19/F-20/F-33/T-03 | 10 d / 2.0 wk | 15 d |
| **C** | Multi-sig threshold (`kt ≥ m` of `n`) | Supplements roadmap Epic 2; closes `kt=1` duplicity + pair-URI-size risks | 12 d / 2.4 wk | 18 d |
| **D** | Witness infrastructure (MVP, 1 witness) | Supplements roadmap Epic 3; closes F-31/F-27 + unverified-receipt gap | 10 d / 2.0 wk | 15 d |
| **E** | Crypto provider + dependency hardening | New (fn-128); mostly landed — narrowed to live gaps | 4 d / 0.8 wk | 6 d |
| **F** | Backup, recovery, durability | New gap (no finding IDs) | 9 d / 1.8 wk | 13.5 d |
| **G** | Agent delegation (headline) | New; hardens substantial existing impl | 7 d / 1.4 wk | 10.5 d |
| **H** | Scope consolidation + interop CI gate | New; deletes dormant code, gates Epic A | 9 d / 1.8 wk | 13.5 d |
| | **Total** | | **85 d / 17 wk** | **127.5 d / 25.5 wk** |

### Totals (calendar)

- **Focused:** 85 eng-days ≈ 17 eng-weeks. **Buffered (+50%):** 127.5 eng-days ≈ 25.5 eng-weeks.
- **One engineer:** ~3.9 months focused; ~5.9 months buffered.
- **Two engineers:** bounded by the **A → B → C → D critical path (56 eng-days)**, not headcount — ~2.6 months focused; ~3.9 months buffered. The second engineer runs E/F/H alongside A and G after A; all fit inside the critical path with slack.

### Critical path

```
   ┌──────────────── H.3 interop gate must be GREEN before A is "done" ─────────────┐
   │                                                                                │
 ▶ A (spec compliance, P0) ──▶ B (dual-index) ──▶ C (multi-sig kt≥m) ──▶ D (witnesses)
   │                                                                          ▲
   ├─ E (crypto/deps)         ∥ parallel, no dep on A                         │
   ├─ F (backup/durability)   ∥ parallel, must not block launch     (witnesses ratify
   ├─ H.1/H.2 (consolidation) ∥ runs throughout                      threshold-met events
   └─ G (agent delegation) ───── starts after A (event model frozen) ─▶   → needs C first)
```

**Rationale:** A first (interop is the launch gate). B before C (multi-sig rotations need dual-index signatures). C before D (a witness ratifying a `kt=1` solo rotation only attests the race winner — convergence needs threshold-met events). E/F/H parallel with A. G after A (the attestation/event model must be frozen before the headline surface). H.3 (KERIox round-trip) must be green before A is declared complete.

---

## Epic A — Spec-compliance wire-format fixes

**Goal:** A KEL produced by Auths round-trips through KERIox/KERIpy and vice-versa; every CRITICAL/MAJOR wire-format, structural, and validation defect is closed.

**Closes:** F-01, F-06 (CRIT); F-04, F-05, F-10, F-13, F-15, F-16, F-23, F-35, F-36, C-04, C-05, T-01, T-05, T-07 (MAJOR); F-03, F-07, F-08, F-22, F-37 (MINOR); F-14/C-01 and F-32/C-03 (CRIT — duplicate deletion + P-256 code). Dual-index findings F-18/F-19/F-20/F-33/T-03 are closed by **Epic B**.

**Prerequisites:** None — P0, sequenced first. H.3 interop gate must be live before this epic is declared complete.

**Parallel-safe with:** E, F, H.

**Maps to roadmap:** Epic 4 (`multi_device_accepted_risks.md §Epic 4`).

### A.1 Move `dt` out of the event body (F-01)

**Why:** Each event carries `dt: Option<DateTime<Utc>>`; when present it serializes inside the body and enters the SAID digest. No KERI peer has `dt` in-body — they reject the field or compute a different SAID. Single largest interop break.

**Files:**
- `crates/auths-keri/src/events.rs:363-364, 483-484, 584-585, 691-692, 812-813` (the five `dt` fields)
- `crates/auths-keri/src/events.rs:408-416, 529-534, 613-618, 734-739, 859-864` (`with_dt` builders)
- serializer arms emitting `dt`: `events.rs:421-438, 540-559, 624-635, 745-763, 870-890`
- `crates/auths-keri/src/validate.rs:1560-1623` (`validate_kel_with_policy` reads `e.dt`); error variants `validate.rs:165-213`

**Spec reference:** ToIP KERI v1.1 §5 (normative `icp`/`rot`/`ixn`/`dip`/`drt` field sets — no `dt`).

**Change:** Delete the `dt` field, `with_dt`, and the `dt` serializer arm from all five structs; drop the `chrono` import. Time-aware policy reads a CESR attachment timestamp passed alongside the events, never the SAID-bearing body.

```rust
// BEFORE (events.rs IcpEvent; same on Rot/Ixn/Dip/Drt)
#[serde(default, skip_serializing_if = "Option::is_none")]
pub dt: Option<DateTime<Utc>>,
// serializer: let field_count = 13 + usize::from(self.dt.is_some()); ... if let Some(dt) = &self.dt { map.serialize_entry("dt", dt)?; }

// AFTER — field/builder/serializer arm deleted; field_count constant.
```

```rust
// AFTER (validate.rs) — policy takes timestamps from attachments, not the body
pub fn validate_kel_with_policy(
    events: &[Event],
    timestamps: &[Option<chrono::DateTime<chrono::Utc>>], // 1:1 with events, from attachments
    policy: &KelPolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<KeyState, ValidationError> { /* monotonicity/cooldown/skew driven by timestamps[idx] */ }
```

**Decisions deferred to implementation:** Carrier for the timestamp — a CESR `-X` extension group vs. a witness `rct` reply. Proposed: a per-event signed attachment group (controller-attested, no witness round-trip). Flag before starting.

**Estimate:** 2.5 eng-days.

### A.2 Sign over finalized event bytes (F-06)

**Why:** `serialize_for_signing` clears `d`/`i` *after* `finalize_*_event` wrote the byte count into `v` (`validate.rs:770-792`). Signed bytes declare size X in `v` but are X−88 (icp) / X−44 (rot). A spec verifier parses `v` first and refuses to frame the body. KERIpy/KERIox sign the fully-formed event.

**Files:** `crates/auths-keri/src/validate.rs:762-797` (`serialize_for_signing`), `:834` (verify call site), and signers calling it (`crates/auths-id/src/keri/inception.rs:602, 688`).

**Spec reference:** ToIP KERI v1.1 §5 (version string MUST equal signed body length).

**Change:**

```rust
// BEFORE
Event::Icp(e) => { let mut e = e.clone(); e.d = Said::default(); e.i = Prefix::default(); serde_json::to_vec(&Event::Icp(e)) }

// AFTER — sign the finalized bytes; d/i/v already populated by finalize_*_event
pub fn serialize_for_signing(event: &Event) -> Result<Vec<u8>, ValidationError> {
    serde_json::to_vec(event).map_err(|e| ValidationError::Serialization(e.to_string()))
}
```

**Estimate:** 1.5 eng-days.

### A.3 Seal `Said` / `Prefix` against empty-value forgery (F-10, T-01)

**Why:** Both derive `Default` (`types.rs:83, 183`) and expose `pub fn new_unchecked` (`:99, :198`). With A.2 done, `Default` has no legitimate use and an empty SAID is forgeable; `#[serde(default)]` on `d` lets a malformed event deserialize with an empty SAID, caught only downstream.

**Files:** `crates/auths-keri/src/types.rs:83, 99-101, 183, 198-200`; `Said::default()`/`Prefix::default()` call sites (after A.2, mostly test code, plus `inception.rs:671-672`).

**Spec reference:** `draft-ssmith-said-03`.

**Change:** Drop `Default`; scope `new_unchecked` to `pub(crate)`; keep validated `new` public.

```rust
// AFTER
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Said(String);
impl Said {
    pub fn new(s: String) -> Result<Self, KeriTypeError> { validate_said_derivation_code(&s)?; Ok(Self(s)) }
    pub(crate) fn new_unchecked(s: String) -> Self { Self(s) } // compute_said + storage-load only
}
```

**Decisions deferred to implementation:** `auths-id`/storage construct these from disk; expose a validated `from_storage` or widen `new_unchecked` to `pub(crate)` + public `new`. Proposed: validated `new` outside `auths-keri`. Flag.

**Estimate:** 2 eng-days (call-site churn dominates).

### A.4 Threshold satisfiability at structural validation (F-04, F-13, F-15, T-05)

**Why:** `kt` is never checked against `|k|`; `bt` only rejects "empty `b`, `bt>0`" (`validate.rs:391-397`); pre-rotation uses `state.next_threshold.simple_value().unwrap_or(1)` (`validate.rs:439, 574, 661`), collapsing any weighted `nt` to threshold 1 — a `[["1/2","1/2","1/2"]]` commit is satisfiable by revealing one key.

**Files:** `crates/auths-keri/src/types.rs:390-453` (add `validate_satisfiable`); `validate.rs:386-410, 432-482, 505-548, 555-609`; the three pre-rotation loops at `validate.rs:438-454, 573-589, 660-675`.

**Spec reference:** ToIP KERI v1.1 §5.4.

**Change:**

```rust
// types.rs
impl Threshold {
    pub fn validate_satisfiable(&self, count: usize) -> Result<(), KeriTypeError> {
        match self {
            Threshold::Simple(0) if count > 0 => Err(/* threshold 0 with non-empty list */),
            Threshold::Simple(n) if *n as usize > count => Err(/* exceeds list length */),
            Threshold::Weighted(c) if c.iter().any(|cl| cl.len() != count) => Err(/* clause len != count */),
            _ => Ok(()),
        }
    }
}
```

```rust
// validate.rs — record WHICH prior commitment each new key matches, then check typed threshold
let mut matched: Vec<u32> = Vec::new();
for (j, commitment) in state.next_commitment.iter().enumerate() {
    if rot.k.iter().any(|key| key.parse().map(|pk| verify_commitment(pk.as_bytes(), commitment)).unwrap_or(false)) {
        matched.push(j as u32);
    }
}
if !state.next_threshold.is_satisfied(&matched, state.next_commitment.len()) {
    return Err(ValidationError::CommitmentMismatch { sequence });
}
```

**Decisions deferred to implementation:** Enforce `validate_satisfiable` at deserialization too, or only at validation entry points? Proposed: validation entry points (keep `Deserialize` total). Flag.

**Estimate:** 2.5 eng-days.

### A.5 Delete the mobile-FFI KERI duplicate (F-14, C-01)

**Why:** `auths-mobile-ffi/src/lib.rs:157-188` defines a private `IcpEvent` with an in-body `x: String` signature field; `:201-218` is a duplicate `compute_said` that — verified — omits the two-pass version-string update the canonical one does (`said.rs:64-77`); `:221-235` duplicate `compute_next_commitment`/`finalize_icp_event`. A `TODO(stage-2)` at `:152-156` acknowledges it. Mobile-originated events are wire-incompatible with Auths and every KERI peer.

**Files:** `crates/auths-mobile-ffi/src/lib.rs:146-239`; `crates/auths-mobile-ffi/tests/icp_event_drift.rs`.

**Spec reference:** ToIP KERI v1.1 §5 (signatures externalized; no in-body `x`).

**Change:** Delete the duplicates; consume `auths_keri::{IcpEvent, IcpEventInit, finalize_icp_event, compute_next_commitment, serialize_attachment, SignedEvent, IndexedSignature}`; externalize the signature via `serialize_attachment` instead of the in-body `x`.

**Coordination:** Epic H decides whether `auths-mobile-ffi` is kept (rerouted) or quarantined until the mobile surface stabilizes. If H quarantines it, A.5 collapses to "delete."

**Estimate:** 1 eng-day.

### A.6 Fix the P-256 verkey CESR code (F-32, C-03, C-04)

**Why:** `KeriPublicKey::parse` accepts only `1AAI` and rejects `1AAJ` (`keys.rs:96-112`), while the `cesr`-feature codec emits `1AAJ` via `matter::Codex::ECDSA_256r1` (`codec.rs:119-123`) — encoder produces what the decoder refuses. Per CESR, `1AAI` is non-transferable and `1AAJ` is the transferable P-256 verkey code; Auths identities rotate, so `1AAJ` is correct. The mislabel is visible in situ: `inception.rs:127` comments "1AAJ prefix (P-256 transferable)" while `:128` emits `"1AAI{...}"`.

**Files:** `crates/auths-keri/src/keys.rs:89-135, 165-170, 5-6, 45-47, 83-88, 163-164`; `crates/auths-keri/src/codec.rs:119-123`; `crates/auths-crypto/src/key_ops.rs:256-264`, `crates/auths-crypto/src/testing.rs:133`; `crates/auths-id/src/keri/inception.rs:127-128`; `crates/auths-keri/src/types.rs:529-535` (`CesrKey::parse` doc, T-02).

**Spec reference:** `draft-ssmith-cesr-03` master code table (`1AAI` non-transferable / `1AAJ` transferable secp256r1 verkey).

**Change:** Start with a **0.5-day empirical spike** confirming the cesride `ECDSA_256r1`↔`1AAJ` mapping and a KERIox round-trip. Then accept both codes and carry transferability:

```rust
// keys.rs
pub enum KeriPublicKey {
    Ed25519([u8; 32]),
    P256 { key: [u8; 33], transferable: bool }, // 1AAJ => true, 1AAI => false
}
// parse: "1AAJ" => transferable: true; "1AAI" => false. cesr_prefix: transferable => "1AAJ" else "1AAI".
```

**Decisions deferred to implementation:** Transferability as a struct-variant field (above) vs. separate flag. Proposed: the field above. Surface the spike result before committing the wire change.

**Estimate:** 2.5 eng-days (incl. 0.5d spike).

### A.7 Pre-rotation commitment digest domain (F-16, C-05)

**Why:** `compute_next_commitment` hashes raw pubkey bytes (`crypto.rs:31-35`); KERIpy hashes the CESR-qualified key string. Different digests → no rotation against a KERIpy `n[]` succeeds here, and vice-versa. Callers pass raw bytes at `validate.rs:442-445, 577-580, 664-667` and `inception.rs:656`.

**Files:** `crates/auths-keri/src/crypto.rs:31-35, 53-60`; the caller sites above.

**Spec reference:** `draft-ssmith-said-03` (confirm empirically vs KERIpy/KERIox).

**Change:** **0.5-day cross-impl spike first** (audit flags this NEEDS DEEPER REVIEW). Then, if confirmed:

```rust
// AFTER — qualified-string domain
pub fn compute_next_commitment(qualified_pubkey: &str) -> Said {
    let hash = blake3::hash(qualified_pubkey.as_bytes());
    Said::new_unchecked(format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}
```

**Decisions deferred to implementation:** Raw vs. qualified is spec-ambiguous; KERIpy uses qualified. Proposed: switch to qualified. If the spike shows KERIox differs, escalate before changing the wire format; if we keep raw, document the deviation in `SPEC.md` (A.16).

**Estimate:** 1.5 eng-days (incl. 0.5d spike).

### A.8 Seal-shape spec compliance (F-35, F-36, F-37)

**Why:** `SealType` is a deprecated non-spec discriminator (`events.rs:290-316`); the `Seal` enum carries `MerkleRoot`/`RegistrarBacker` (`events.rs:121-132`) not in the spec table and lacks the Event-Location seal; the untagged deserializer drops `s` for a malformed `{i,s}` seal (`events.rs:253-260`).

**Files:** `crates/auths-keri/src/events.rs:92-133, 165-204, 206-288, 290-316`.

**Spec reference:** ToIP KERI v1.1 §7.

**Change:** Delete `SealType` (pre-launch, zero users); add Event-Location seal `{i,s,p,t,d}`; feature-gate `MerkleRoot`/`RegistrarBacker` behind `seal-extensions`; make the deserializer error on unrecognized field combos.

```rust
pub enum Seal {
    Digest { d: Said },
    SourceEvent { s: KeriSequence, d: Said },
    KeyEvent { i: Prefix, s: KeriSequence, d: Said },
    EventLocation { i: Prefix, s: KeriSequence, p: Said, t: String, d: Said }, // NEW (§7)
    LatestEstablishment { i: Prefix },
    #[cfg(feature = "seal-extensions")] MerkleRoot { rd: Said },
    #[cfg(feature = "seal-extensions")] RegistrarBacker { bi: Prefix, d: Said },
}
```

**Estimate:** 2 eng-days.

### A.9 Bind basic-derivation inception prefixes to `k[0]` (F-03)

**Why:** `verify_event_crypto` enforces `i == d` only for `E`-prefixed inception (`validate.rs:638-643`); a `D…`/`1AAI…` `i` is accepted unconditionally — a basic-derivation prefix can point at any key list.

**Files:** `crates/auths-keri/src/validate.rs:626-647`.

**Spec reference:** ToIP KERI v1.1 §5.

**Change:** When `i` is a basic-derivation code, decode it and require equality with `k[0]`'s bytes.

**Estimate:** 1 eng-day.

### A.10 Cross-check rotation backer deltas (F-05)

**Why:** `validate_rotation` checks `br`/`ba` internal uniqueness and `br ∩ ba = ∅` (`validate.rs:456-466`) but never that `br ⊆ prior backers`; `apply_rotation` then `retain`s + `extend`s (`state.rs:146-147`), so a `ba` of a surviving backer duplicates an entry, corrupting `bt`.

**Files:** `crates/auths-keri/src/validate.rs:456-466`; `crates/auths-keri/src/state.rs:145-148`.

**Spec reference:** ToIP KERI v1.1 §5.5.

**Change:** Before `apply_rotation`, require each `br` ∈ prior backers and each `ba` ∉ post-removal set.

**Estimate:** 1 eng-day.

### A.11 Reject legacy short version strings (F-07)

**Why:** `VersionString::Deserialize` accepts `KERI10…` shorter than 17 chars, returning `size: 0` (`types.rs:660-663`). KERI v1.1 mandates the 17-char form.

**Files:** `crates/auths-keri/src/types.rs:649-670`.

**Spec reference:** `draft-ssmith-cesr-03`.

**Change:** Delete the `else if s.starts_with("KERI10")` branch; update the `version_string_parse_legacy` test (`types.rs:977-982`) to assert rejection.

**Estimate:** 0.5 eng-days.

### A.12 Distinguish non-transferable from abandoned (F-22)

**Why:** `from_inception` sets `is_abandoned = true` when `n[]` is empty (`state.rs:105`), collapsing "born non-rotating" with "abandoned after rotation"; diagnostics misreport.

**Files:** `crates/auths-keri/src/state.rs:97-114`.

**Change:** `is_abandoned: false` at inception; rely on `is_non_transferable` (`state.rs:98`) and the existing `inception_n_is_empty` guard (`validate.rs:336-338`).

**Estimate:** 0.5 eng-days.

### A.13 Enforce `RB`/`NRB`/`DID` config traits (F-23)

**Why:** Verified by grep — `RegistrarBackers`/`NoRegistrarBackers`/`DelegateIsDelegator` have **zero usages outside `types.rs:582-590`**. RB and NRB carry different backer-list semantics; a rotation can flip them silently.

**Files:** `crates/auths-keri/src/state.rs:18-60` (track backer role); `crates/auths-keri/src/validate.rs:432-482` (reject role flip without `b[]` reconstruction), `:225-270` (`validate_delegation` — `DID`).

**Spec reference:** ToIP KERI v1.1 §10.

**Change:** Add `backer_role` to `KeyState` from the latest RB/NRB; reject role flips that don't rebuild `b[]`; implement `DID` in `validate_delegation`.

**Decisions deferred to implementation:** Full registrar-backer `bt` accounting is under-specified in our model. Proposed A.13 scope: reject silent role flips + `DID`; defer full RB accounting to a tracked issue. Flag.

**Estimate:** 1.5 eng-days.

### A.14 Seal `KeyState` against forged validation results (T-07)

**Why:** `KeyState` has all-`pub` fields (`state.rs:18-60`); any consumer can fabricate a "validated" state.

**Files:** `crates/auths-keri/src/state.rs:18-60`; in-crate literal construction at `validate.rs:532-547` is unaffected by `pub(crate)`.

**Change:** Fields → `pub(crate)`, add read accessors; `from_inception`/`apply_*` remain the only constructors. Route `auths-id`/`auths-verifier` field reads through accessors.

**Decisions deferred to implementation:** `KeyState` derives serde and is persisted; serde bypasses field privacy, so sealing constructors suffices. Proposed: keep serde on the sealed struct. Flag if a DTO split is preferred.

**Estimate:** 1 eng-day.

### A.15 `SPEC.md` conformance document + cross-impl vectors

**Why:** Without a written conformance statement and committed vectors, fixed findings drift back. (The one documentation deliverable permitted inside an epic.)

**Files:** `SPEC.md` (new); `crates/auths-keri/tests/cases/interop_vectors.rs` (new); `crates/auths-keri/tests/fixtures/keriox/*.cesr`.

**Change:** Document each closed finding, the chosen answer for the two ambiguous ones (F-16, F-32), and the emitted field sets. Commit KERIox vectors that A.1/A.2/A.6/A.7 must round-trip. The live CI gate is Epic H.3.

**Estimate:** 1.5 eng-days.

### Verification

- `cargo nextest run -p auths-keri` green with new tests: `dt_absent_from_event_body`, `said_stable_without_dt`, `sign_over_finalized_bytes_roundtrips`, `said_has_no_default` (trybuild), `threshold_rejects_kt_gt_k`, `prerotation_weighted_nt_requires_quorum`, `p256_parses_both_1aai_and_1aaj`, `commitment_domain_matches_keriox`, `seal_event_location_roundtrips`, `seal_rejects_malformed_i_s`, `basic_derivation_i_must_equal_k0`, `rotation_rejects_br_not_in_prior`, `version_string_rejects_legacy_short`.
- `grep -rn "\.dt\b\|with_dt\|SealType\|Said::default\|Prefix::default" crates/ | grep -v test` empty.
- **Cross-impl (Epic H.3):** KERIox replays an Auths-produced `icp`+`rot`+`ixn` KEL without error; Auths `validate_kel` accepts every event of a KERIox-produced KEL. Must pass before A is declared complete.

### Epic A total: 24 eng-days ≈ 4.8 eng-weeks focused.

---

## Epic B — Dual-index CESR signatures + true removal

**Goal:** Rotations that change key-list cardinality (true removal, `kt>1` asymmetric rotations, mixed-curve signers) are expressible and cryptographically verified.

**Closes:** F-18, F-19, F-20, F-33, T-03; lifts the "Pure removal blocked" risk; unblocks Epic C.

**Prerequisites:** Epic A (A.2 signing-byte canonicalization + A.4 typed thresholds are the foundation).

**Parallel-safe with:** E, F.

**Maps to roadmap:** Epic 1 (`multi_device_accepted_risks.md §Epic 1`).

### B.1 Add `prior_index` to `IndexedSignature` (F-19, T-03)

**Why:** `IndexedSignature` carries a single `index` (`events.rs:1049-1056`); a rotation signature must bind to both a new-key index and the prior-commitment index it reveals — which is why `validate_signed_event` falls back to `AsymmetricKeyRotation` (`validate.rs:904`).

**Files:** `crates/auths-keri/src/events.rs:1049-1056`.

**Spec reference:** `draft-ssmith-cesr-03` (dual-index codes).

**Change:**

```rust
pub struct IndexedSignature {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_index: Option<u32>,   // Some(_) for rotation sigs
    #[serde(with = "hex::serde")]
    pub sig: Vec<u8>,
}
```

**Estimate:** 1 eng-day.

### B.2 Dual-index CESR emission (F-19)

**Why:** `serialize_attachment` hardcodes single-index `indexer::Codex::Ed25519` (`events.rs:1117-1126`). With a `prior_index`, it must emit the dual-index ("big") code. The codec already supports per-curve sig codes (`codec.rs:138-169`) and is the place to centralize this.

**Files:** `crates/auths-keri/src/events.rs:1106-1135`; `crates/auths-keri/src/codec.rs:138-169`.

**Change:** Select `Ed25519_Big` / P-256 dual-index code when `prior_index.is_some()`, passing both indices to `Siger::new`.

**Estimate:** 1.5 eng-days.

### B.3 Code-directed attachment parser (F-33)

**Why:** `parse_attachment` assumes every siger is 88 chars (`events.rs:1161-1170`); heterogeneous groups (mixed curve, or single+dual index) misalign. CESR is code-directed.

**Files:** `crates/auths-keri/src/events.rs:1139-1185`.

**Spec reference:** `draft-ssmith-cesr-03`.

**Change:** Read the hard code, look up its qb64 width via cesride, consume exactly that; populate `prior_index` from the siger's other-index when dual.

**Estimate:** 2 eng-days.

### B.4 Dual-index rotation validator (F-18, F-20)

**Why:** `validate_signed_event` assumes new-key index `i` maps to prior commitment `i` (`validate.rs:861-874`); the kt=1 path only checks "some verified key matches some prior commitment" (`:875-899`). Neither binds each signature to the prior `n[j]` it reveals. F-20: the symmetric branch passes `keys.len()` for the prior threshold instead of `state.next_commitment.len()` (`validate.rs:871`).

**Files:** `crates/auths-keri/src/validate.rs:806-913`.

**Spec reference:** ToIP KERI v1.1 §10.5.

**Change:** Use each signature's `prior_index` to build the verified prior-commitment index set, then check the prior `nt` over `state.next_commitment.len()`; `AsymmetricKeyRotation` becomes unreachable for well-formed dual-index rotations.

**Estimate:** 2.5 eng-days.

### B.5 True-remove rotation in the shared KEL

**Why:** `rot_remove_controller` returns `RemovalNotYetSupported` (`shared_kel.rs:124-134`) because shrinking `k` needs dual-index sigs. B.1–B.4 supply them.

**Files:** `crates/auths-id/src/keri/shared_kel.rs:124-134` and the rotation-authorship path it wraps.

**Change:** Build a shrink-`k` `rot` whose dual-index attachment binds each surviving controller's signature to its prior commitment; validate via B.4. Keep `rot_swap_controller` (`shared_kel.rs:256-265`) as the recovery convenience path.

**Estimate:** 2 eng-days.

### B.6 CLI surface for true removal

**Why:** `auths device remove <did:keri:...>` should sign a shrink-`k` rotation, not force the swap workaround.

**Files:** `crates/auths-cli/src/commands/device/` (removal action); `crates/auths-cli/src/commands/status.rs`.

**Change:** Wire to B.5; surface threshold/controller-count feedback. Presentation only.

**Estimate:** 1 eng-day.

### Verification

- `cargo nextest run -p auths-keri -E 'test(dual_index)'`: `dual_index_rotation_binds_prior_commitment`, `mixed_curve_attachment_parses`, `asymmetric_rotation_kt2_now_accepted`.
- A 3-controller shared KEL rotates to 2 via pure removal; the result replays under `validate_kel_with_lookup` and round-trips through KERIox (H.3).
- `grep -rn "RemovalNotYetSupported" crates/` shows the variant unused/removed.

### Epic B total: 10 eng-days ≈ 2 eng-weeks focused.

---

## Epic C — Multi-sig threshold upgrade (`kt ≥ m` of `n`)

**Goal:** A shared identity requires `m`-of-`n` co-signatures for any rotation; no single device can solo-rotate the controller set.

**Closes:** "Duplicity under `kt=1`" and "Pair-URI size bound" risks; consumes A.4 typed validators and Epic B dual-index machinery.

**Prerequisites:** Epic B.

**Parallel-safe with:** F, G.

**Maps to roadmap:** Epic 2 (`multi_device_accepted_risks.md §Epic 2`).

### C.1 Partial-signature collection protocol

**Why:** Under `kt ≥ 2`, one controller drafts a rotation, peers sign, the originator assembles the dual-index attachment when threshold is met. `shared_kel.rs` assumes solo signing (`SharedKelArtifacts.kt` hardcoded to 1 at `shared_kel.rs:61`).

**Files:** `crates/auths-pairing-protocol/src/types.rs` (message types); `crates/auths-id/src/keri/shared_kel.rs` (assembly); `crates/auths-sdk/src/` (orchestrating workflow).

**Change:** `RotationDraft`, `PartialSignature`, and an assembler that collects until `kt` distinct controller signatures verify, then emits the `SignedEvent`. Signatures are `DeviceDID`-attributable indexed signatures (never bearer).

**Estimate:** 3 eng-days.

### C.2 Threshold-aware signing + recovery

**Why:** A.4 fixed structural threshold checks; C.2 enforces the *signing* threshold at assembly and defines recovery below quorum.

**Files:** `crates/auths-keri/src/validate.rs:806-913`; `crates/auths-id/src/keri/shared_kel.rs`.

**Change:** Assembly refuses to emit until `kt.is_satisfied(&verified, n)`; recovery requires `m` surviving controllers (or a pre-staged quorum — C.4).

**Estimate:** 2 eng-days.

### C.3 Partial-signing UX (CLI)

**Files:** `crates/auths-cli/src/commands/` — `auths rotate --request <said>` and `auths rotate --sign <said>`; `auths status` shows collection progress.

**Change:** Presentation over C.1; no domain logic in the CLI.

**Estimate:** 2 eng-days.

### C.4 Recovery semantics under `kt ≥ 2`

**Files:** `crates/auths-id/src/keri/shared_kel.rs`; `essays/design/multi_device.md`.

**Change:** Co-signed recovery from the surviving quorum; define behaviour at exactly `m-1` survivors.

**Decisions deferred to implementation:** Default `m`/`n` for a two-device user. Proposed: 2-of-3 with the third a pre-staged offline recovery key. Flag.

**Estimate:** 2 eng-days.

### C.5 Pair-URI medium upgrade (>1024 B)

**Why:** Multi-sig inception exceeds `SHARED_KEL_INCEPTION_EVENT_MAX_BYTES = 1024` (the QR cap).

**Files:** `crates/auths-pairing-protocol/src/` handshake; the `SubmitResponseRequest::validate()` cap site.

**Change:** File-handoff + QR-pointer fallback; remove the cap once wired.

**Estimate:** 1.5 eng-days.

### C.6 Migrate existing `kt=1` shared KELs

**Why:** Existing dev `kt=1` KELs sign one final upgrade `rot` raising `kt` (no lock-out: `kt=1` authorizes the upgrade). One-shot, no compat shim.

**Files:** `crates/auths-id/src/keri/shared_kel.rs` (`SharedKelArtifacts.kt` at `:61` stops being hardcoded); `crates/auths-cli/src/commands/device/`.

**Estimate:** 1.5 eng-days.

### Verification

- A 2-of-3 KEL: `solo_rotation_rejected`, `cosigned_rotation_accepted`, `survives_single_device_loss_via_cosigned_recovery`.
- `auths rotate --request`/`--sign` round-trip with two `TempDir` identities.
- `grep -rn "SHARED_KEL_INCEPTION_EVENT_MAX_BYTES" crates/` shows the cap removed.

### Epic C total: 12 eng-days ≈ 2.4 eng-weeks focused.

---

## Epic D — Witness infrastructure (minimum viable for launch)

**Goal:** A verifier converges on the authoritative KEL state because a single Auths-operated witness ratifies threshold-met events, with the architecture to add more later.

**Closes:** "No witnesses" risk; F-31, F-27; the unverified-receipt gap.

**Prerequisites:** Epic C (witnesses ratifying a `kt=1` solo rotation only attest the race winner).

**Parallel-safe with:** F, G.

**Maps to roadmap:** Epic 3 (`multi_device_accepted_risks.md §Epic 3`), scoped to one witness.

### D.1 Verify witness receipt signatures

**Why:** Verified in code — `collect_and_store_receipts` stores receipts whose signatures are never checked: the comment at `witness_integration.rs:104-105` literally reads "SECURITY: witness API returns unsigned Receipt — signatures not verified at collection time."

**Files:** `crates/auths-id/src/keri/witness_integration.rs:104-131`; `crates/auths-keri/src/witness/receipt.rs:58-68` (`SignedReceipt`).

**Spec reference:** ToIP KERI v1.1 §8 (`rct`).

**Change:** Verify each `SignedReceipt` against the witness verkey (resolved from `b[]`) over the receipted SAID before storing; drop failures.

**Estimate:** 2 eng-days.

### D.2 Wire receipts + KAWA into the verifier path

**Why:** `WitnessAgreement` (`agreement.rs`) and `first_seen.rs` are scaffolded but not consumed by `auths-verifier`. An event should strengthen once a `bt` quorum of verified receipts is seen.

**Files:** `crates/auths-verifier/src/verifier.rs` (already has `verify_chain_with_witnesses` at `:173` — extend it to feed verified receipts into KAWA); `crates/auths-keri/src/witness/agreement.rs`, `first_seen.rs`.

**Change:** Feed verified receipts into `WitnessAgreement::add_receipt`; expose acceptance state on the verification report.

**Estimate:** 2.5 eng-days.

### D.3 Typed `bt` threshold in KAWA (F-31)

**Why:** `submit_event` collapses weighted `bt` via `bt.simple_value().unwrap_or(0)` (`agreement.rs:98`); weighted witness thresholds have no effect.

**Files:** `crates/auths-keri/src/witness/agreement.rs:89-166`.

**Change:** Track verified-witness indices (witness AID → position in `b[]`) and use `Threshold::is_satisfied(&indices, b.len())` instead of the simple counter.

**Estimate:** 1 eng-day.

### D.4 Type `Receipt.t` (F-27, T-04)

**Why:** `Receipt.t` is a free-form `String` (`receipt.rs:46`); a `Receipt { t: "icp", .. }` serializes and verifies locally.

**Files:** `crates/auths-keri/src/witness/receipt.rs:40-56`.

**Change:** Remove `t` from the struct; serialize the constant `"rct"` via custom serde, rejecting other values on parse.

**Estimate:** 0.5 eng-days.

### D.5 Single Auths-operated witness + minimal OOBI

**Why:** The HTTP witness client (`HttpAsyncWitnessClient`) and `ReceiptCollector` exist (`witness_integration.rs:91-110`); discovery does not.

**Files:** `crates/auths-infra-http/` (client present); `crates/auths-id/src/keri/witness_integration.rs`; a minimal OOBI resolve path.

**Change:** OOBI resolution for one configured witness URL; the `b[]`/`bt` plumbing already supports adding more.

**Decisions deferred to implementation:** Witness mechanism (KERI-native vs OOBI-discovered) — roadmap §3.0 leaves this open. Proposed: KERI-native single witness with OOBI discovery, per `docs/security/witness-diversity.md`. Flag.

**Estimate:** 3 eng-days.

### D.6 First-seen replay integration tests (F-30)

**Files:** `crates/auths-keri/tests/cases/witness_flows.rs` (new).

**Change:** Tests exercising receipt ingestion + first-seen superseding (recovery rotation supersedes interaction) under a simulated witness.

**Estimate:** 1 eng-day.

### Verification

- `cargo nextest run -p auths-keri -E 'test(witness)'` and `-p auths-verifier`: `receipt_signature_rejected_when_forged`, `event_accepted_after_bt_quorum`, `weighted_bt_requires_quorum`, `receipt_t_must_be_rct`, `recovery_supersedes_interaction_under_witness`.
- A verifier with the witness converges on the same controller set across two diverging local views.

### Epic D total: 10 eng-days ≈ 2 eng-weeks focused.

---

## Epic E — Crypto provider trait completion + dependency hardening

**Goal:** Domain-layer P-256 keygen/signing flows through `CryptoProvider`, the remaining `rand::random()` sites use `OsRng`, the last caret-range crypto deps are exact-pinned, and the dead Rekor trust-root placeholder is removed.

**Closes:** cross-cutting items in `prompt.md §5`. No `keri_compliance.md` IDs — security hardening, not spec compliance.

**Prerequisites:** None — fully parallel-safe with Epic A.

**Parallel-safe with:** A, B, F, H.

**Maps to roadmap:** Cross-cutting (fn-128). **Status:** much of fn-128 has landed since `primitive-inventory.md` (2026-04-19) — verified in code below. Subtasks are scoped to what is *actually* still open.

### E.1 Route domain-layer P-256 keygen/signing through `CryptoProvider`

**Why:** The trait already exposes `sign_p256`/`generate_p256_keypair`/`p256_public_key_from_seed` (`provider.rs:202,214,228`, implemented by `RingCryptoProvider`) — so the "trait incomplete" claim in `primitive-inventory.md §6` is stale. The live gap is domain code that bypasses the provider: `inception.rs:115-134` builds a P-256 key via `SigningKey::random(&mut OsRng)`, and `inception.rs:602-603, 688-689` sign with `ring`'s `Ed25519KeyPair` directly. (The `key_ops.rs` sites are inside `auths-crypto` — legitimate; test sites are fine.)

**Files:** `crates/auths-id/src/keri/inception.rs:115-134, 602-603, 688-689`; `clippy.toml` (add a `disallowed-types` ban on `p256::ecdsa::SigningKey` outside `auths-crypto`).

**Change:**

```rust
// BEFORE (inception.rs P-256 keygen)
let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
// ... sign: let sig = current_keypair.sign(&canonical);

// AFTER — provider-routed
let (seed, public_key) = provider.generate_p256_keypair().await?;
let sig = provider.sign_p256(&seed, &canonical).await?;
```

**Decisions deferred to implementation:** Inception is sync; the `CryptoProvider` trait is async. Proposed: a sync `Signer` port in `auths-core` backed by `RingCryptoProvider`'s inherent sync methods (the `witness_integration.rs:23-32` shared-runtime pattern is the precedent). Flag.

**Estimate:** 2 eng-days.

### E.2 Migrate remaining `rand::random()` sites to `OsRng`

**Why:** `sas.rs:98` is already fixed (`sas.rs:179-186` uses `OsRng` with a fn-128.T6 comment). The live offenders are in `auths-core`: `crypto/encryption.rs:94, 106` and `storage/encrypted_file.rs:143, 222` (salt/nonce). The clippy ban exists (`clippy.toml:23-29`, `allow-invalid = true`); these sites must be migrated and the ban made enforcing in `auths-core`.

**Files:** `crates/auths-core/src/crypto/encryption.rs:94, 106`; `crates/auths-core/src/storage/encrypted_file.rs:143, 222`.

**Change:**

```rust
// BEFORE: let salt: [u8; SALT_LEN] = rand::random();
// AFTER:
use rand::{rngs::OsRng, RngCore};
let mut salt = [0u8; SALT_LEN];
OsRng.fill_bytes(&mut salt);
```

**Estimate:** 0.5 eng-days.

### E.3 Exact-pin the remaining caret-range crypto deps

**Why:** `ring`/`subtle`/`zeroize`/`sha2`/`hkdf`/`hmac`/`chacha20poly1305`/`aes-gcm`/`json-canon` are already `=`-pinned at `[workspace.dependencies]`. Still caret: `p256 = "0.13"` (many crates), `blake3 = "1.5"`, `argon2 = "0.5"`, `rand = "0.8"`, `rand_core = "0.6"`. A `p256`/`ecdsa` minor bump can change signature DER and silently invalidate signatures.

**Files:** root `Cargo.toml` `[workspace.dependencies]` and the per-crate `Cargo.toml`s overriding `p256`/`blake3`; `.github/workflows/cargo-deny.yml:46-52` (extend the existing `cargo tree -d` grep to include `p256|blake3|argon2`).

**Change:** Pin `p256 = "=0.13.2"`, `blake3`, `argon2`, `rand`, `rand_core` to exact patch from `Cargo.lock`; add them to the existing duplicate-version guard. The `deny.toml` + `cargo deny check` job already exists — this completes the pin set it assumes.

**Estimate:** 1 eng-day.

### E.4 Remove the dead Rekor Ed25519 trust-root placeholder

**Why:** `transparency/src/lib.rs:256-263` builds a `TrustRoot` whose `log_public_key` is `Ed25519PublicKey::from_bytes([0u8; 32])` — unused, because production Rekor is `EcdsaP256` and the real key loads into `ecdsa_log_public_key_der`. The zero field reads as a missing trust root. `prompt.md §8`: `auths-infra-rekor` is to be deleted (Epic H), not enhanced.

**Files:** `crates/auths-transparency/src/lib.rs:256-263`.

**Change:** Drop the `[0u8; 32]` field; keep only the live ECDSA path, or remove Rekor verification entirely for launch (coordinate with H's `auths-infra-rekor` deletion).

**Decisions deferred to implementation:** Keep ECDSA Rekor verification for launch vs. remove until post-launch federation. Proposed: remove for launch (no consumer ships it). Flag.

**Estimate:** 0.5 eng-days.

### Verification

- `grep -rn "p256::ecdsa::SigningKey" crates/ | grep -v '/tests/' | grep -v 'auths-crypto'` empty; clippy fails a reintroduction in `auths-id`.
- `grep -rn "rand::random()" crates/ | grep -v '/tests/'` empty.
- `grep -rnE '"\^?0\.13"|"1\.5"|"0\.5"' crates/*/Cargo.toml` shows `p256`/`blake3`/`argon2` exact-pinned.
- `cargo deny check advisories bans licenses sources` green; the `cargo tree -d` guard now covers `p256`/`blake3`/`argon2`.
- `grep -rn "0u8; 32" crates/auths-transparency/src/lib.rs` empty.

### Epic E total: 4 eng-days ≈ 0.8 eng-weeks focused.

---

## Epic F — Backup, recovery, and durability

**Goal:** A single-device user can recover after losing `~/.auths`, Git GC can never silently destroy KEL objects, and the next-rotation secret survives device loss.

**Closes:** new gaps (no finding IDs), all verified by filesystem search: no `auths backup`/`export`/`import` command exists; no `gc.auto`/`pruneExpire` anywhere; no `escrow` anywhere; the only `handle_sync` is git-signer sync (`signers.rs:232`).

**Prerequisites:** None — parallel-safe with Epic A. Launch-critical but independent of the spec-compliance chain.

**Parallel-safe with:** A, B, C, D, E.

**Maps to roadmap:** New (durability gap, not in the Epics 1–6 sequence).

### F.1 `auths backup export` / `import`

**Why:** Verified — no backup/export/import command file exists under `crates/auths-cli/src/commands/`. A single-device user who loses `~/.auths` loses their identity; pre-rotation doesn't help (same keychain).

**Files:** `crates/auths-cli/src/commands/backup.rs` (new); `crates/auths-sdk/src/domains/backup/` (new workflow); reuse `crates/auths-core/src/storage/encrypted_file.rs` (existing AEAD sealed-file primitive).

**Change:** A sealed bundle of keychain seeds + `~/.auths` refs, Argon2id-derived key + AES-256-GCM/ChaCha20-Poly1305 (both already deps). Key material crosses boundaries as `SecureSeed`/`Zeroizing<Vec<u8>>` (`SECURITY.md` Rule 1); passphrase never `Zeroizing<String>` (Rule 2).

```rust
// auths-sdk/src/domains/backup/service.rs (orchestration; crypto via CryptoProvider)
pub struct BackupBundle { pub version: u32, pub kdf: Argon2Params, pub nonce: [u8; 12], pub ciphertext: Vec<u8> }
pub async fn export_backup(repo: &Path, keychain: &dyn KeyStorage, passphrase: &Zeroizing<Vec<u8>>, provider: &dyn CryptoProvider) -> Result<BackupBundle, BackupError>;
pub async fn import_backup(bundle: &BackupBundle, passphrase: &Zeroizing<Vec<u8>>, /* targets */) -> Result<(), BackupError>;
```

**Estimate:** 3 eng-days.

### F.2 Disable Git GC on `~/.auths` at init

**Why:** Verified — `rg "gc.auto|pruneExpire"` returns nothing. `ensure_git_repo` (`agent_identity.rs:236-244`) and the CLI init path call `git2::Repository::init` without disabling GC. A `git gc` that prunes an unreferenced KEL object is silent identity loss.

**Files:** `crates/auths-id/src/agent_identity.rs:236-244`; `crates/auths-id/src/keri/inception.rs` repo creation; `crates/auths-cli/src/commands/init/mod.rs`.

**Change:**

```rust
let repo = git2::Repository::init(path)?;
let mut cfg = repo.config()?;
cfg.set_i32("gc.auto", 0)?;
cfg.set_str("gc.pruneExpire", "never")?;
```

**Estimate:** 1 eng-day.

### F.3 `auths sync` as a first-class command

**Why:** Verified — the only `sync` is `auths signers sync` (`signers.rs:232`, git commit signers), unrelated to identity state. No command replicates the KEL/refs for durability.

**Files:** `crates/auths-cli/src/commands/sync.rs` (new); `crates/auths-sdk/src/domains/sync/` (new); reuse `RefReader`/`RefWriter` (`auths-core/src/ports/storage/`).

**Change:** Push/pull `refs/auths/*` and `refs/keri/*` to a remote or paired device, surfacing conflicts via `auths_verifier::duplicity`.

**Decisions deferred to implementation:** Transport — git remote vs. registry server vs. device-to-device over the pairing channel. Proposed: git remote first. Flag.

**Estimate:** 2.5 eng-days.

### F.4 Pre-rotation seed escrow on co-controllers

**Why:** Verified — `rg "escrow"` returns nothing. The next-rotation seed lives only in the local keychain; sole-device loss takes the pre-committed rotation key with it.

**Files:** `crates/auths-id/src/keri/` (escrow on rotation); `crates/auths-cli/src/commands/device/pair/` (distribute during pairing); `crates/auths-pairing-protocol/src/` (transport).

**Change:** On each rotation, seal the new next-seed to each co-controller's device key and replicate it as an escrow blob; recovery reconstructs from a co-controller's escrow. Always `DeviceDID`-encrypted, never bearer.

**Decisions deferred to implementation:** Single-controller escrow vs. quorum-gated (Shamir). Proposed: quorum-gated, aligned with Epic C's `kt≥2`; sequence after C if quorum-gated. Flag.

**Estimate:** 2.5 eng-days.

### Verification

- `auths backup export` → `rm -rf ~/.auths` → `auths backup import` round-trips; the restored KEL replays under `validate_kel` and signs a verifying commit (`backup_roundtrip_restores_signing`).
- New repos have `gc.auto=0` (`git -C ~/.auths config gc.auto` → `0`); test `init_disables_gc`.
- `auths sync` replicates a rotation to a second `TempDir`; duplicity detector stays clean.
- Single-device-loss test recovers the next key from a peer's escrow.

### Epic F total: 9 eng-days ≈ 1.8 eng-weeks focused.

---

## Epic G — Agent delegation as the headline feature

**Goal:** A developer issues a cryptographically scoped, time-bounded, revocable delegation to an AI agent; any relying party enforces the scope offline; a runnable demo proves it.

**Closes:** new (headline). Hardens a substantial existing implementation.

**Prerequisites:** Epic A (the attestation/event model must be frozen before the headline surface is).

**Parallel-safe with:** C, D, F.

**Maps to roadmap:** New (`prompt.md §1.5` headline).

**Current state (code-verified):** Delegation is largely built — `provision_agent_identity` (`agent_identity.rs:148-210`), `AgentService::provision` (`sdk/domains/agents/service.rs:31-134`), `validate_delegation_constraints` (`sdk/domains/agents/delegation.rs:33-62`: capability-subset + TTL-limit + depth-limit at provision), `Attestation { capabilities, delegated_by, signer_type }` (`verifier/core.rs:1243-1247`), `SignerType::{Human, Agent, Workload}`, `AgentSession { delegation_depth, max_delegation_depth }`. **The verifier already enforces scope-down at verify time:** `verify_chain_with_capability` (`verifier.rs:137-165`) computes the capability **intersection** across the chain and rejects anything outside it, and `verify.rs:1447/1477` reject tampered `capabilities`/`delegated_by`. Examples exist under `examples/agent/{single_agent,agent_swarm}`. The real gaps are below.

### G.1 Verify-time subset check for a *standalone* delegated attestation

**Why:** `verify_chain_with_capability` enforces narrowing across a full chain (`verifier.rs:152-163`), but `verify_with_capability` on a *single* attestation only checks capability *presence* (`verifier.rs:87`) — it does not resolve `delegated_by` and assert `child.capabilities ⊆ delegator.capabilities` (or `child.expires_at ≤ delegator.expires_at`, or delegator-not-revoked). A relying party handed one delegated attestation without the chain gets no scope-down.

**Files:** `crates/auths-verifier/src/verifier.rs:80-94`; `crates/auths-verifier/src/verify.rs` (the `verify_with_keys` path); `crates/auths-verifier/src/core.rs:1243-1247` (`Attestation` fields).

**Change:** Add a delegation-aware verify that, when `delegated_by.is_some()`, resolves the delegator attestation and enforces capability-subset, `expires_at ≤ delegator`, and delegator-not-revoked — failing closed if the delegator can't be resolved.

```rust
fn enforce_delegation_scope(child: &Attestation, delegator: &Attestation, now: DateTime<Utc>) -> Result<(), AttestationError> {
    if !child.capabilities.iter().all(|c| delegator.capabilities.contains(c)) {
        return Err(AttestationError::CapabilityEscalation);
    }
    if let (Some(ce), Some(de)) = (child.expires_at, delegator.expires_at) && ce > de {
        return Err(AttestationError::DelegationOutlivesParent);
    }
    if delegator.revoked_at.is_some_and(|r| r <= now) { return Err(AttestationError::DelegatorRevoked); }
    Ok(())
}
```

**Decisions deferred to implementation:** Whether TTL-≤-parent at verify time is already implied by per-link expiry in `verify_chain_inner` (needs confirmation while implementing) — if so, G.1 only adds the standalone-attestation subset check. Flag.

**Estimate:** 2 eng-days.

### G.2 `auths agent authorize` headline CLI verb

**Why:** Verified — `AgentSubcommand` is Start/Stop/Status/Env/Lock/Unlock/InstallService/UninstallService (`cli/commands/agent/mod.rs:35-182`). There is **no `authorize`** verb, yet `prompt.md §1.5` names `auths agent authorize` as the headline.

**Files:** `crates/auths-cli/src/commands/agent/authorize.rs` (new); wire to `AgentService::provision`.

**Change:** `auths agent authorize --name <n> --capability <cap>... --ttl <dur>` provisions a delegated agent identity + attestation and prints the agent DID. Presentation only; logic stays in the SDK.

**Estimate:** 2 eng-days.

### G.3 Delegated-agent revocation

**Why:** `Attestation.revoked_at` exists (`core.rs`); delegation must be revocable (`prompt.md §1.5`). Needs a first-class revoke verb + verifier honoring (G.1).

**Files:** `crates/auths-cli/src/commands/agent/` (revoke verb); `crates/auths-id/src/attestation/revoke.rs`.

**Change:** `auths agent revoke <agent-did>` writes a revocation attestation; verifiers reject from `revoked_at` onward.

**Estimate:** 1 eng-day.

### G.4 End-to-end headline demo + `SPEC.md` delegation section

**Why:** `examples/agent/{single_agent,agent_swarm}` exist but aren't framed as the headline, and the delegation wire format isn't in `SPEC.md`.

**Files:** `examples/agent/`; `SPEC.md` (delegation attestation shape + scope-down rules).

**Change:** A scripted demo: authorize → agent signs → relying party verifies + scope-down → revoke; document the attestation fields and verifier rules.

**Estimate:** 2 eng-days.

### Verification

- `cargo nextest run -p auths-verifier -E 'test(delegation)'`: `standalone_delegated_attestation_rejects_escalation`, `verifier_rejects_delegation_outliving_parent`, `verifier_rejects_revoked_delegator` (complementing the existing `verify_chain_with_capability_uses_intersection`).
- `auths agent authorize` → agent signs → `auths verify` enforces scope-down offline.
- `auths agent revoke` → subsequent verification fails with `DelegatorRevoked`.
- The `examples/agent` demo runs green in CI.

### Epic G total: 7 eng-days ≈ 1.4 eng-weeks focused.

---

## Epic H — Scope consolidation + cross-impl interop CI gate

**Goal:** Shrink the workspace from ~28 crates by merging thin adapters and deleting dormant code, and stand up a CI gate that round-trips Auths-produced KELs through KERIox so spec-compliance can't silently regress.

**Closes:** new (workspace hygiene); deletes dormant `auths-infra-rekor`; quarantines deferred `auths-scim`/`auths-radicle`; resolves `auths-mobile-ffi` drift (with A.5); stands up the interop gate that gates Epic A.

**Prerequisites:** None for merges; H.3 must be live **before Epic A is declared complete**.

**Parallel-safe with:** all (runs throughout); coordinate H.2 with A.5 (mobile-ffi) and E.4 (Rekor).

**Maps to roadmap:** New (consolidation per `critique.md`; interop gate per `prompt.md §5`).

**Current inventory (verified by `ls crates/` + Cargo.toml scan):** 29 directories; `auths-deployment` is config-only (no `src/`), leaving ~28 Rust crates (25 in the root `[workspace] members`, plus `auths-test-utils`, `auths-mobile-ffi` (own workspace), and `xtask`). (`critique.md`'s "32" predates removals.)

### H.1 Merge thin adapters

**Why:** Several crates are thin enough that the boundary costs more than it buys (build graph, import clutter, version churn). Dependency edges verified by scanning each `Cargo.toml`.

**Merges (each: move modules, update `[dependencies]` + `use` paths, drop from `[workspace] members`):**
- `auths-infra-git` (~720 LOC) → `auths-storage` (thin git2 wrapper over storage ports)
- `auths-infra-http` (~3.9k) + `auths-oidc-port` (~536) → `auths-infra` (network adapters)
- `auths-utils` (~56) + `auths-jwt` (~435) → `auths-support` (`auths-test-utils` stays — it's a `dev-dependency`-only crate)

**Change:** Respect the layer diagram — no merge creates an upward edge.

**Decisions deferred to implementation:** Whether `auths-pairing-protocol` (~3.4k) folds into `auths-core`. It is consumed by `auths-mobile-ffi`'s separate workspace, so folding may complicate the mobile build. Proposed: keep it separate (so ~28 → ~22 from the safe merges); the aggressive target of ~12 from `critique.md` requires folding pairing + collapsing the specialized adapters, which I do **not** recommend pre-launch. Flag if the smaller count is a hard requirement.

**Estimate:** 4 eng-days.

### H.2 Delete dormant code; quarantine deferred crates

**Why:** `prompt.md §8`: `auths-infra-rekor` is to be deleted, not enhanced. `auths-scim` (publish=false, 0 tests) and `auths-radicle` are on the post-launch deferred list (`prompt.md §5`).

**Files:**
- `crates/auths-infra-rekor/` — **delete**; remove the `auths-cli` dependency. Users submit to Rekor via `cosign`/`rekor-cli`.
- `crates/auths-mobile-ffi/` — after A.5 reroutes it to canonical `auths_keri` types, decide keep vs. quarantine until the mobile surface re-stabilizes.
- `crates/auths-scim/`, `crates/auths-radicle/` — **feature-gate behind non-default features**; keep building in CI, out of the default surface.

**Change:** Delete `auths-infra-rekor`; gate `auths-scim`/`auths-radicle`; resolve `auths-mobile-ffi` per A.5. `log` what was dropped so the consolidation isn't a silent truncation.

**Estimate:** 2 eng-days.

### H.3 Cross-impl interop CI gate (KERIox round-trip)

**Why:** Without an automated round-trip, the Epic A fixes drift back. `prompt.md §5`: round-trip Auths-produced KELs through KERIox (Rust, tractable). **Must be live before Epic A is declared complete.**

**Files:** `crates/auths-keri/tests/cases/interop_keriox.rs` (new); `.github/workflows/ci.yml` (new `interop` job pinning a KERIox version); `crates/auths-keri/tests/fixtures/keriox/`.

**Change:** A CI job that (1) feeds Auths-produced `icp`+`rot`+`ixn`(+`dip`/`drt`) KELs to KERIox and asserts clean replay, and (2) validates KERIox-produced KELs in `auths-keri`. Seeded by A.15 vectors; expanded as A.1/A.2/A.6/A.7 land.

**Decisions deferred to implementation:** KERIox in the blocking gate; KERIpy (Python, higher-fidelity but heavier) as a nightly non-blocking job. Flag.

**Estimate:** 3 eng-days.

### Verification

- `cargo metadata --format-version 1 | jq '.workspace_members | length'` reflects the reduced count (~22 with the safe merges).
- `grep -rn "auths-infra-rekor\|auths_infra_rekor" crates/ Cargo.toml` empty.
- `auths-scim`/`auths-radicle` absent from `cargo build` (default) but present in `cargo build --all-features`.
- The `interop` CI job is green and **required** on the branch protecting `main` before Epic A is marked complete.

### Epic H total: 9 eng-days ≈ 1.8 eng-weeks focused.

---

## Deferred to post-launch

Per the recorded preference, **file one GitHub issue per item** (`gh issue create`) so each deferral is tracked. None are launch-blocking.

| Item | Rationale | Issue to file |
|---|---|---|
| Mixed-curve controller sets (roadmap Epic 5) | Depends on B.3 (code-directed parser) + A.6; most users pair P-256 devices. | "Epic 5: heterogeneous-curve controller sets" |
| External federation (roadmap Epic 6) | `did:keri:` publishable to third parties; gated on D + A. | "Epic 6: external federation" |
| Full multi-witness diversity (`docs/security/witness-diversity.md`) | Launch ships one witness (D.5); diversity policy is design-only until ≥3. | "Witness diversity policy enforcement" |
| SCIM integration (`auths-scim`) | On the `prompt.md §5` deferred list; feature-gated in H.2. | "SCIM 2.0 agent provisioning" |
| Radicle integration (`auths-radicle`) | On the deferred list; feature-gated in H.2. | "Radicle protocol bridge" |
| FIPS/CNSA provider swap (`aws-lc-rs`/`p384`) | `primitive-inventory.md §5` planned swap; E.1 makes it reachable, not launch-critical. | "FIPS/CNSA CryptoProvider" |
| Full RB/NRB registrar-backer semantics (F-23 remainder) | A.13 rejects silent role flips + implements `DID`; full RB accounting is under-specified. | "KERI RB/NRB registrar-backer semantics" |
| `KeriSequence` arbitrary precision (F-11) | u128 permits ~3.4×10³⁸ events; bound is immaterial in practice. | "KeriSequence u128 vs arbitrary precision" |
| MINOR/type-ergonomics: F-17 (ct compare note), F-34 (CESR codec consolidation), T-02 (`CesrKey` curve typing), T-06 (`KeriMessage` umbrella enum) | No interop impact. | "KERI minor type-safety cleanups (F-17, F-34, T-02, T-06)" |
| `auths-verifier` result sealing (T-08) | Verification outputs constructible without running the verifier; needs a dedicated audit, out of scope here. | "auths-verifier unsealed-result audit (T-08)" |

---

Ready for review.
