# Launch-Readiness — Final Decisions + Build Plan (self-contained)

This is a context-free pickup doc for finishing launch-readiness epics B–H
(`fn-136..142`). It assumes **no prior conversation**. Read §0, then build from §2/§3
using the settled decisions in §1. Per-task acceptance criteria live in the `.flow`
specs (`flowctl cat <id>`); this doc is the decisions + sequence + gotchas that aren't
in those specs.

Status when written: **20/55 tasks done**, branch `dev-keriCompliantDevices`, working
tree clean. The big `DeviceDID → CanonicalDid` refactor is **committed** (`54a1bc2`) — it
is no longer a blocker (earlier versions of this doc said it was; ignore that).

---

## 0. Orientation (read first)

**Repo:** Rust workspace, KERI-based decentralized identity. Layer order is enforced:
`auths-crypto → auths-keri → auths-verifier → auths-core → auths-id → {auths-storage,
auths-sdk} → {auths-infra-*, auths-cli}`. Authoritative conventions: **`CLAUDE.md` at repo
root** (SDK orchestrates / core implements; `thiserror` in domain, `anyhow` only at CLI/API
boundary; no `unwrap`/`expect` outside tests; `Utc::now()` banned in core/id — inject
`now`; collapse nested `if` with `&&`). Wire-format curve-tag rules and the normative event
field sets are in **`SPEC.md`** (repo root) — keep it in sync with any wire change.

**flowctl** (task tracker, bundled — `which flowctl` fails, this is expected):
```
FLOWCTL="/Users/bordumb/.claude/plugins/cache/gmickel-claude-marketplace/flow-next/0.5.8/scripts/flowctl"
$FLOWCTL cat fn-136.1            # read a task spec (file paths, acceptance)
$FLOWCTL tasks --epic fn-136 --json
$FLOWCTL start fn-136.1 --force --json
$FLOWCTL done fn-136.1 --force --summary-file /tmp/s.md --evidence-json /tmp/e.json --json
```
`.flow/` is **gitignored** — task state is local-only, nothing to commit there. `--force` is
needed because cross-task deps will otherwise block `start`.

### COMMIT MECHANICS — important, you will get this wrong otherwise
This repo signs commits with an **SSH/Secretive key that needs a TouchID approval**
(`commit.gpgsign=true`, `gpg.format=ssh`, `user.signingkey=auths:main`). A normal
`git commit` **hangs forever** waiting for that prompt — the `prek` pre-commit hook itself
passes; it's the *signing* step that blocks. So:

```bash
git add <explicit files>     # NEVER `git add -A`/`git add *` unless tree is yours-only
git -c commit.gpgsign=false commit --no-verify -m "type(scope): subject

body"
```
- `gpgsign=false` avoids the hang. Commits are **unsigned**; that's fine for these.
- `--no-verify` skips the slow hook **only because you ran its gates yourself first** (below).
- **Never** attribute to Claude / no `Co-Authored-By`.
- Do **not** put `.flow` task IDs (`fn-N.M`) in code comments or commit messages. Finding
  IDs (`F-23`) and epic labels (`A.13`) are fine — they match existing code style.

### Gates the pre-commit hook runs — run these manually before each commit
```bash
cargo fmt --all
cargo clippy --all-targets --all-features --keep-going -- -D warnings      # workspace
# packages (separate manifests, shared target):
for d in packages/auths-node packages/auths-python packages/auths-verifier-swift; do
  CARGO_TARGET_DIR=../../target cargo clippy --manifest-path "$d/Cargo.toml" --all-targets --keep-going -- -D warnings; done
cargo run --package xtask -- check-clippy-sync     # if any clippy.toml changed (must stay identical across crates)
bash scripts/check_sdk_boundary.sh                  # if auths-cli/src changed (CLI must not import core/id/storage)
```
Tests: `cargo nextest run -p <crate> --all-features` (nextest can't run doctests);
doctests `cargo test -p <crate> --doc --all-features`. Per-crate fast error check:
`cargo build -p auths-<crate> --all-features 2>&1 | grep "^error\[E" -A 10`.
zsh gotcha: `grep --include=*.rs` silently finds nothing — use `grep -rn PAT crates | grep '\.rs:'`.

---

## 1. Settled decisions (FINAL — implement exactly as written)

### A.3 — events require a non-empty `d` on the wire (`fn-135.3`)
KERI events always carry their SAID `d`; there is no valid event with a missing/empty `d`.
The SAID is computed by filling `d` with a fixed-length dummy, serializing, hashing, then
writing the digest back. So:
- Remove `#[serde(default)]` from `d` on the 5 event structs in `crates/auths-keri/src/events.rs`
  (icp/rot/ixn/dip/drt) → deserialization now *requires* `d`.
- The finalization path (`finalize_icp_event`/`finalize_rot_event`/`finalize_ixn_event` in
  `validate.rs`, and the dip/drt builders) must seed `d` with a **44-char dummy filler**
  (`"#".repeat(44)` style, matching SAID length) before SAID computation — not `Said::default()`/`""`.
- Add empty-string rejection at the validating boundary: give `Said`/`Prefix`
  (`crates/auths-keri/src/types.rs`, structs at the `#[derive(... Default ...)]` lines) a
  validating `new()` that errors on empty; keep `new_unchecked()` for the internal placeholder.
  **Gotcha:** there are ~95 `Said::default()`/`Prefix::default()` call sites (~50 in prod). You do
  NOT have to remove the `Default` derive — keep it for internal placeholder use; the security
  win is "wire parse requires non-empty `d`," which the serde-default removal + empty-reject gives.
- Acceptance: an event JSON without `d`, or with `d:""`, fails to parse; finalized events
  round-trip; `cargo nextest run -p auths-keri` green. Mark `fn-135.3` done (it is `blocked` — `start --force`).

### A.7 — pre-rotation commitment hashes the CESR-qualified `qb64`, not raw bytes (`fn-135.7`)
This is the clearest interop bug. keripy computes the next-key commitment as
`Diger(ser=verfer.qb64b).qb64` — i.e. `Blake3-256` over the **qualified key string**
(`D…`/`1AAJ…`), CESR-coded `E…`. Current code in `crates/auths-keri/src/crypto.rs`
(`compute_next_commitment(public_key: &[u8])`) hashes raw bytes → curve-ambiguous, won't
interop.
- Change the signature to take the **qualified verkey** (a `&CesrKey` or `&KeriPublicKey`,
  which carry curve + transferability) and hash its qb64 string bytes; keep the `E` prefix.
- Update callers (they hold the next key being committed; pass the qualified form).
- This changes on-disk digests → **A.16** (`fn-135.16`) regenerates `tests/fixtures/*` and any
  golden vectors. Cross-validate against a keripy/keriox vector when H.3 lands.
- Acceptance: a known keripy commitment vector round-trips; `auths-keri` green. Confidence: high.

### A.13 — `DelegateIsDelegator` ("DID"): remove it (`fn-135.13`, role-flip half already done)
`DID` is not a confirmed standard KERI config trait and is **never consumed**. A config trait
that *waives* the delegation seal is a delegation-authorization bypass if guessed. Pre-launch,
zero users → **remove the variant** `ConfigTrait::DelegateIsDelegator` (`crates/auths-keri/src/types.rs`,
its `#[serde(rename = "DID")]`, and the test that lists it ~`types.rs:986`). `validate_delegation`
(`crates/auths-keri/src/validate.rs`) already fail-closes (requires the anchoring seal; handles
`DND`) — leave that. Do **not** implement a waiver. Then mark `fn-135.13` done (role-flip +
`BackerRoleFlip` already shipped in commit `0f9c011`). Confidence: high it's not load-bearing.

### C.4 — multisig threshold is a **configurable default**, never hardcoded (`fn-137.4`/`fn-137.6`)
`kt`/`nt` are controller-sovereign values recorded in the KEL; KERI mandates no value. Three layers:
1. **Protocol (auths-keri):** `kt`/`nt` stay pure `Threshold`; validation only enforces
   "≥kt sigs satisfied" (already true post-A.4). No constant.
2. **SDK default:** un-hardcode `SharedKelArtifacts.kt` (currently `pub kt: u32` fixed to 1 in
   `crates/auths-id/src/keri/shared_kel.rs`). Make it a parameter — `SharedKelConfig { threshold: Threshold }`
   (or a `kt` arg) plumbed through the inception/pair path. **Default = strict majority
   `⌈(n+1)/2⌉` floored at 1; set `nt = kt`.** Expose `--threshold m-of-n` to override. This also
   ends the kt=1 duplicity fork. C.6 = author one upgrade `rot` raising kt for existing kt=1 KELs.
3. **Platform floor (optional, separate):** a verifier/registry *admission* policy
   ("reject identities whose current kt < X"), read from the KEL at verify time — lives in the
   policy/`TrustResolver` layer, additive, opt-in. **Witnesses do NOT enforce this** (they gate
   their own `bt` + first-seen, and serve the controller). Don't bake a floor into keygen.
Rationale for not hardcoding: legitimate postures vary (1-of-1 CI bot, 3-of-5 org, 2-of-2 brittle
pair), and `nt` must be re-derived per event from the then-current controller set.

### B wire-format — code-directed parser is the unlock; dual-index on diverging rotations (`fn-136.*`)
CESR has single-indexed and dual-("big")-indexed siger codes; a rotation sig must bind both its
position in the new `k[]` and the prior `n[]` commitment it reveals. keripy emits dual-indexed
sigers for `rot`.
- **B.3 (parser) is mandatory and the real unlock:** the attachment parser must dispatch on the
  CESR code and read whichever (single or dual) is present. Without it nothing else verifies.
- **B.1:** add `prior_index: Option<u32>` to `IndexedSignature` (`crates/auths-keri/src/events.rs`)
  with `#[serde(default, skip_serializing_if = "Option::is_none")]` → wire-stable (absent when
  `None`). Then fix the ~10 construction sites (`auths-id` inception/rotate/anchor/rotation/
  initialize, `auths-sdk` multi_sig) by adding `prior_index: None`.
- **B.2 (emit):** dual-index when a sig's current-key index ≠ its prior-commitment index (always
  for key removal/reorder); inception/interaction stay single-index; same-index 1-key rotations
  may stay single-index (still parseable via B.3).
- **B.4 (validate):** verify rotation sigs against both lists using the dual index; this removes
  the `AsymmetricKeyRotation` rejection. **B.5** (true-remove rotation in `auths-id`
  `keri/shared_kel.rs`, replacing `RemovalNotYetSupported`) and **B.6** (CLI `auths device remove`)
  build on B.4.

### A.5 — mobile-ffi: KEEP + reroute to canonical types (`fn-135.5`)
`crates/auths-mobile-ffi/src/lib.rs` has a duplicate `IcpEvent` with an in-body `x` signature
(non-conformant — KERI sigs are externalized) plus duplicate `compute_said`/
`compute_next_commitment`/`finalize_icp_event`. Delete those; consume
`auths_keri::{IcpEvent, finalize_icp_event, compute_next_commitment, serialize_attachment,
SignedEvent, IndexedSignature}`; externalize the signature via `serialize_attachment` (no `x`).
**Separate cargo workspace** — build/test with `cd crates/auths-mobile-ffi && cargo build`
(its own `target/`, own `Cargo.lock`). Remove/update `tests/icp_event_drift.rs`. Do A.5 after
A.7 (it reuses `compute_next_commitment`, whose signature changes).

---

## 1.5 Validation strategy — prove the risky decisions, don't re-ask

Interop tests + property tests + an optional model are **validation layered after the build**
(§2). Most decisions (A.3, A.13, C.4, A.5, all F/G/SDK/CLI work) never touch interop. **Two
exceptions** fold validation *into* the build so a fresh session doesn't rebuild fixtures twice
or implement a wire format blind:

- **A.7 / A.16 — generate the regenerated fixtures FROM keripy, not from ourselves.** A.7 already
  forces a fixture regen (A.16); make those the committed **keripy golden vectors**. If keripy's
  `n[]` commitment digest matches ours, A.7 is proven empirically in the same step — don't
  hand-regenerate and then redo it for interop later. (Oracle = keripy, the most authoritative
  impl; subprocess generation is already wired in `crates/auths-keri/tests/cases/keripy_interop.rs`
  under `KERIPY_INTEROP=1`.)
- **B (dual-index) — write a keripy-generated key-removal `rot` as the target fixture FIRST**, then
  implement B.1–B.4 to parse/accept it. Do **not** implement the dual-index index semantics from
  this doc's prose and discover divergence later — build against the reference's bytes.

**Run early (informs a decision, doesn't block the build):** a ~30-min probe of whether
keripy/keriox even emit a P-256 (`1AAJ`) verkey. KERI reference impls are Ed25519-first; if they
don't do secp256r1, P-256 is validated only against the CESR code table + our own vectors (not
cross-impl), which may revisit **P-256-as-default**. Know this before investing in P-256 interop
fixtures.

**Layer after the build (any order):**
1. **proptest invariant suite** in `auths-keri` — threshold soundness (random index subsets vs
   `Threshold::is_satisfied`), SAID tamper-evidence (any field mutation changes `d`), first-seen
   monotonicity, **ECDSA low-s non-malleability** (sign, flip `s→n−s`, assert the verifier rejects
   high-s), parse∘serialize round-trip stability.
2. **Full H.3 cross-impl gate** (`fn-142.5`) — commit keripy/keriox golden vectors for
   icp/rot-with-removal/ixn/dip/drt; CI asserts round-trip with **no toolchain installed** (vectors
   are committed; `interop_vectors.rs` is the loader). The A.7 vectors above seed this.
3. **Optional TLA+/Alloy model** of KEL-replay + first-seen + threshold + duplicity, checking the
   safety property *"no two honest validators accept divergent KELs without `detect_duplicity`
   flagging it."* This is the rigorous answer to the kt=1-without-witnesses question — do it only if
   duplicity is a launch concern.

This collapses most spec/expert questions into checked artifacts (low-s → proptest; dual-index →
B's keripy fixture; qb64 commitment → A.16 keripy vectors). The residual genuine expert questions
are just **RB/NRB `bt` accounting** and **"is P-256 sane as the default given reference-impl
support."**

---

## 1.6 Wave 0 — CESR encoding alignment (Option A; DO FIRST, blocks everything)

**Discovered + decided 2026-06: our wire encoding is NOT byte-interoperable with keripy, and the
user chose Option A — align to keripy.** This is a prerequisite re-foundation: until it lands,
every keripy interop check fails and A.7/B/C cannot validate against the reference. **A.7 collapses
into this wave** (the commitment fix is just one of the encodings being corrected).

**Root cause (proven):** `auths-keri` has TWO encoders. The default path uses **naive
`format!("D{}", base64url(raw))`** for verkeys, `"E{}"+base64` for digests/SAIDs — self-consistent
but NOT CESR's qb64 alignment. The correct cesride-backed `CesrV1Codec` (`src/codec.rs`:
`encode_pubkey`/`encode_digest`/`decode_qualified`) exists but is gated behind the **optional `cesr`
feature** (`default = []`) and used only for "CESR export". keripy rejects our events; our SAID
`EEpOF…` ≠ keripy's `EBKTh…`; our verkey `DAAEC…` ≠ keripy's `DAAB…`.

**Proven fix (committed `9354fba`):** the test `codec::tests::cesr_primitives_match_keripy_reference`
shows **cesride 0.6 == keripy 1.3.4** byte-for-byte (`encode_pubkey(bytes(0..32),Ed25519)` →
`DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f`; `encode_digest(blake3(verkey.qb64b))` →
`EF_M_u7ASVHXfI8QzdWLq3V9ocSKqxkbujXGbi9QMtP9`). So the alignment is: **route everything through
`CesrV1Codec`.**

### STATUS (resume point) — Wave 0 is ~⅔ done; **SAID/event byte-interop with keripy ACHIEVED + committed**

**DONE (committed on `dev-keriCompliantDevices`):**
- `74dcf5b` — always-on `src/cesr_encode.rs` (`encode_verkey`/`decode_verkey`/`encode_blake3_digest`/
  `verkey_code`, wrapping cesride) + `KeriPublicKey::to_qb64()`. cesride is non-optional and
  **WASM-safe** (verifier wasm build verified green), so these are default-build, not feature-gated.
- `6efef5b` — **Part 1 (typing):** `compute_next_commitment` / `verify_commitment` now take
  `&KeriPublicKey` so the curve travels in the type. 40 call sites migrated, value-preserving, 892
  tests pass. New bridges to reuse: `KeriPublicKey::ed25519(&[u8])`, `::from_verkey_bytes(bytes,curve)`,
  `::to_qb64()`, and `GeneratedKeypair::verkey()` (parses its `cesr_encoded`). The sdk rotation path
  now USES its previously-ignored `new_next_curve`; the verify path uses `ParsedKey.seed.curve()`.
- `2ad5cd0` — **Part 2a (digests):** `compute_said` + `compute_next_commitment` use the cesride
  digest. **keripy SAID byte-interop is PROVEN** — `KERIPY_INTEROP=1 cargo nextest run -p auths-keri
  -E 'test(subprocess_mode_when_keripy_available)'` goes FAIL→PASS. 1458 tests pass: the suite
  *computes* SAIDs rather than hardcoding them, so the value change was non-breaking (the feared
  atomic fixture-regen mostly evaporated).

**REMAINING — Part 2b (verkey `k[]` encoding).** Make our verkeys valid CESR too (today keripy
accepts our SAID/structure, but our `k[]` is naive base64 — keripy would mis-decode it for
signature checks). This part **is atomic** (parse + all encode flip together — cesride silently
mis-decodes naive strings, so there is NO safe fallback):
1. **`src/keys.rs` `KeriPublicKey::parse`** → `crate::cesr_encode::decode_verkey` (cesride). Map the
   matter codes: `Ed25519`→`Ed25519`, `ECDSA_256r1`→`P256{transferable:true}`, `ECDSA_256r1N`→
   `P256{transferable:false}`; keep `B`/`Ed25519N` → `UnsupportedKeyType` (the enum has no
   non-transferable Ed25519 variant). `decode_verkey` already exists — drop its `#[allow(dead_code)]`.
2. **The 30 naive `format!("D{}"/"1AAJ{}",…)` encode sites** (`grep -rEn 'format!\("(D|B|1AAJ|1AAI)\{\}"' crates | grep '\.rs:' | grep -v mobile-ffi`)
   → cesride. **Production:** `auths-crypto/src/key_ops.rs:265-266` (add `cesride` to auths-crypto's
   Cargo.toml — WASM-safe; used by `TypedSignerKey::cesr_encoded()` in the rotation `k[]` path),
   `auths-id` inception.rs:121/141 + rotate.rs + resolve.rs. **Tests:** auths-keri validate.rs/keys.rs/
   multi_key_threshold, auths-storage, auths-sdk multi_sig. Replace with
   `KeriPublicKey::from_verkey_bytes(bytes, curve)?.to_qb64()?` (cross-crate) or `cesr_encode::encode_verkey`
   (within auths-keri). Per-site curve + `Result` handling, exactly like Part 1 (`?`/INVARIANT-`expect`
   in prod, `.unwrap()` in tests). `mobile-ffi` is a SEPARATE workspace with its OWN duplicate — skip.
3. **Regenerate verkey fixtures** that hardcode exact `D…`/`1AAJ…` values (`grep -rEno '"D[A-Za-z0-9_-]{43}"' crates | grep '\.rs:'`)
   + the golden `crates/auths-keri/tests/fixtures/keripy/icp.bin`. Most tests COMPUTE/round-trip
   verkeys (robust, like the SAIDs were) — measure real breakage with a full `nextest` run after the
   flip and regenerate only the broken exact-value asserts from cesride/keripy.
4. **Gate:** `cargo nextest run --workspace --all-features` green; the keripy subprocess test still
   PASSES; verifier wasm still green (`cd crates/auths-verifier && cargo check --target
   wasm32-unknown-unknown --no-default-features --features wasm`); commit with
   `git -c commit.gpgsign=false commit --no-verify` (signing hangs on TouchID).
5. Update `SPEC.md` §3 (verkeys are CESR-aligned qb64, not naive base64); mark A.7 (`fn-135.7`) +
   A.16 (`fn-135.16`) done. Then Wave 0 is complete and B/C validate against keripy cleanly.

---

## 2. Build sequence (dependency DAG)

Do waves in order; within a wave, tasks are independent. All are auths-keri-local or cleanly
committable now (tree is clean).

```
WAVE 1  (auths-keri interop fixes — highest value, lowest risk)
  A.7  (commitment qb64)  ──►  A.16 (regen fixtures)
  A.3  (require d on wire)
  A.13 (remove DID, mark done)

WAVE 2  (B — dual-index CESR; consensus-critical wire format)
  B.1 (prior_index field) ──► B.3 (code-directed parser) ──► B.2 (emit) + B.4 (validate)
                                                              └─► B.5 (true-remove, auths-id) ──► B.6 (CLI)

WAVE 3  (C — multisig; C.4 default = majority, decided in §1)
  C.1 (partial-sig collection) ──► C.2 (threshold signing/recovery) ──► C.4 (recovery semantics) ──► C.3 (CLI)
  C.6 (un-hardcode kt + upgrade rot)        C.5 (pair-URI >1024B medium)   [both can run in parallel]

WAVE 4  (D — receipt verification; CONSENSUS-CRITICAL, see §3 gotcha)
  D.1 (verify receipt sigs) ──► D.2 (wire receipts+KAWA into verifier)

WAVE 5  (independent, any order)
  E.1 (keygen via provider)   F.1 (backup)  F.3 (sync)  F.4 (escrow)
  G.2 (authorize CLI) ──► G.3 (revoke) ──► G.4 (demo + SPEC delegation section)
  A.5 (mobile dedup, after A.7)   A.14 (KeyState accessors)
```

---

## 3. Per-task build detail (the non-obvious bits)

- **A.16** (`fn-135.16`): after A.7, regenerate any committed digest fixtures and the
  `interop_vectors.rs`/`keripy_interop.rs` expectations in `crates/auths-keri/tests/`. Run the
  full `auths-keri` suite; fix golden values.
- **D.1** (`fn-138.1`) — *consensus-critical, get the signing domain right.*
  `collect_and_store_receipts` in `crates/auths-id/src/keri/witness_integration.rs` stores
  receipts whose signatures are **never checked** (see the `// SECURITY: ... not verified`
  comment there). Before writing verification, **read what the witness server signs**:
  `crates/auths-core/src/witness/server.rs` issue path — confirm the witness signs over the
  *receipted event SAID* (the receipt's `d`) vs the receipt body, and with which key encoding.
  Then resolve the witness verkey from the controller's `b[]` (a basic witness AID *is* its
  qualified verkey — parse via `KeriPublicKey::parse`), verify each `SignedReceipt.signature`
  over that exact domain, drop failures, delete the comment. Test `receipt_signature_rejected_when_forged`.
  Mismatching the domain silently rejects all valid receipts or accepts forgeries — verify against
  the server's actual signing bytes, don't assume.
- **D.2** (`fn-138.2`): wire verified receipts + KAWA quorum (`WitnessAgreement`, already typed in
  D.3) into the verifier path so receipt quorum gates acceptance.
- **E.1** (`fn-139.1`): the keygen site `crates/auths-id/src/keri/inception.rs` (P-256 arm builds
  `SigningKey::random(&mut OsRng)` + PKCS8 DER) must route through `CryptoProvider`. **Snag:** the
  provider trait is async and yields seed+pubkey, but this site is sync and needs PKCS8 DER. Use a
  sync bridge (see `crate::crypto::provider_bridge` used by the witness server) or add a sync P-256
  keygen helper in `auths-crypto`; convert seed→PKCS8 as needed. Then add a `disallowed-types` ban
  on `p256::ecdsa::SigningKey` to `crates/auths-id/clippy.toml` — **but** the `check-clippy-sync`
  gate requires all crate `clippy.toml` to match the root, so add the ban to the **root**
  `clippy.toml` (and re-run `xtask check-clippy-sync`) rather than only the crate file.
- **F.1/F.4** (`fn-140.1`,`fn-140.4`) — *security-sensitive (raw key material).* Reuse
  `crates/auths-core/src/storage/encrypted_file.rs` (Argon2id + AEAD). Key material must cross
  boundaries as `SecureSeed`/`Zeroizing<Vec<u8>>` (never `Zeroizing<String>` for the passphrase);
  crypto via `CryptoProvider`; orchestration in the SDK (`auths-sdk/src/domains/backup/` new).
  Get these reviewed.
- **G.2/G.3/G.4** (`fn-141.2..4`): build on G.1 (`Verifier::verify_delegated_with_capability`,
  shipped `5b44f0e`). G.2 = `auths agent authorize` CLI verb (presentation only — domain logic in
  SDK, per CLAUDE.md boundary rule). G.4 also writes the SPEC.md delegation section.
- **A.14** (`fn-135.14`): make `KeyState` fields `pub(crate)` + add accessor methods; update the
  ~96 external read sites across ~33 files to use accessors. Mechanical but compiler-enforced —
  the build won't pass until every site is migrated. High churn; do it in one focused pass.

---

## 4. Still blocked — NOT buildable by an agent (need you / infra)

- **D.5** (`fn-138.5`): stand up a real Auths-operated witness server + minimal OOBI endpoint.
- **H.3** (`fn-142.5`): KERIox cross-impl CI gate — needs a `keriox` toolchain to generate `.cesr`
  vectors. `SPEC.md` + `crates/auths-keri/tests/cases/interop_vectors.rs` are the oracle/seed.
- **H.6** (`fn-142.8`): live Rekor demo — the code is done (`auths-infra-rekor` is implemented;
  `build_dsse` + `parse_entry_response` real, see `docs/architecture/dormant-crate-audit.md`); this
  is an end-to-end run against a real Rekor instance via `auths artifact sign --log sigstore-rekor`.
- **H.5** (`fn-142.7`): file deferred GitHub issues — needs `gh` auth; filing public issues is an
  outward action to do with you. Bodies: the §1 decisions + full RB/NRB `bt` accounting +
  scim/radicle keep-vs-archive.
- **H.1a/b/c** (`fn-142.1..3`): **optional** crate relocations — skip pre-launch (churn, no
  functional gain). **H.4** (`fn-142.6`) is a no-op until/unless H.1 is chosen.

---

## 5. Done log (already committed on `dev-keriCompliantDevices`)

Epic A: A.1 A.2 A.4 A.6 A.8 A.9 A.10 A.11 A.12 A.15 A.17 (+ A.13 role-flip half, `0f9c011`).
Epic D: D.3 (`5ac8a43`) D.4 (in `54a1bc2`) D.6 (`ad4ae53`).
Epic E: E.2 E.3 E.4.  Epic F: F.2.  Epic G: G.1 (`5b44f0e`).  Epic H: H.2 (`6857684`).
Refactor: `54a1bc2` DeviceDID→CanonicalDid (176 files, carried D.4 + 45 clippy fixes).
Docs: `SPEC.md`, `docs/architecture/{identity-model,cryptography,dormant-crate-audit}.md`, this file.

Remaining: 35 tasks — §1 decides 6 of them, §2/§3 build ~15, §4 lists ~14 that need you/infra.
