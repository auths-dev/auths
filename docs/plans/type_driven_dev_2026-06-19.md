# Type-Driven Design Review — 2026-06-19

## Resolution — hardening loop, 2026-06-19 (branch `dev-agentMoney`)

A focused loop landed the tractable fail-open / type-driven fixes and parked the rest with
precise reasons. Every commit is workspace-green and keeps the gateway's `./run.sh --check`
(13 ✓) green; each carries a test that fails if the fix is reverted.

**Landed:**

| Finding | Fix | Commit |
|---|---|---|
| Budget parse fail-open (→ silent `u64::MAX` cap) | `Budget::parse -> Result` | `552d35f3` |
| KeyRole reload → most-privileged `Primary` (5 backends) | one `KeyRole::from_persisted -> Result` | `f02f492a` |
| Delegator with no anchored seal → unrestricted | `DelegatorAuthority` (no-seal refused) + extracted `validate_capability_subset` | `920b71d9` |
| Approval git-ref-path injection (`/`, `..`) | `Sha256Hex` / `NonceId` validated ref segments | `578b0f9e` |
| JWS alg open-string (`none` / confusion representable) | `JwsAlg` enum (no `none`, no `HS*`) | `e9e4cdde` |
| Signature classified by substring sniff | classify from `Auths-Id`/`Auths-Device` trailers; verification a separate verdict | `e8dfc2e7` |
| Bare `+` on treasury cap/credit math | `saturating_add` + checked scale/narrow on settlement | `a00dfe14` |
| No relay request body-size limit | explicit `DefaultBodyLimit` | `06ff196f` |

(Earlier on the branch: the gateway money-path cap-bypass + cost-attestation hardening; deeper
residuals in advisory `GHSA-2929-6rr5-gx39`.)

**Parked — advisory `GHSA-f389-2xwc-8q4p` (draft):**

- **IdentityDID single-door + recurrence lint** — the unchecked constructor has ~114 call sites
  across 9 crates; the security subset (untrusted reads where a tampered tree name / corrupt
  keystore becomes a "verified" DID) needs a dedicated cross-crate refactor, too large to land
  green unattended. The lint (ban `new_unchecked` outside its crate) depends on that routing and
  parks with it.
- **Treasury / relay auth-model + deploy items** — forgeable credit, unauthorized reclaim,
  unenforced revocation ledger, cap TOCTOU, unauthenticated drain/deposit, Redis global memory
  cap. Authentication / signed-capability + deploy-config decisions, not unattended code fixes.
- **OIDC residual (informational)** — one dead-code `PlatformOidcConfig` still uses
  `Vec<String>`; off the live path, which uses the typed allowlist.

## Range reviewed

**Full from-scratch audit of `crates/` — every crate, full current source, not a commit range.**
38 crates / ~250K LOC of Rust. No prior `type_driven_dev_*.md` checkpoint existed, so this
establishes the baseline. Branch `dev-agentMoney` @ `821b22d8`.

Reviewed via 13 parallel scoped passes:
money (`auths-mcp-core`+`auths-mcp-gateway`), `auths-keri`, crypto/jwt/oidc-port,
`auths-id`, `auths-core`, `auths-sdk`, verifier+rp, policy+transparency, pairing,
storage/index/telemetry/infra, scim/mcp-server/api, cli+mobile-ffi, murmur+witness.

**Type boundaries touched (where untrusted input becomes domain values):** the MCP payment
gate (agent-declared amount, x402/Stripe rail responses → `Cents`/`AtomicUsdc`); KEL/event
wire parse (`auths-keri`); OIDC/JWT claims (attacker-controlled token); the
`Auths-Presentation` wire (`auths-rp`); FFI/WASM key ingress (`auths-verifier`,
`auths-mobile-ffi`); pairing handshake; SCIM/MCP/control-plane HTTP request bodies; Git/disk
deserialization (`auths-storage`); the murmur binary frame. The newest domain values —
`Cents`/`AtomicUsdc` and the spend-log/audit chain on the active branch — got read hardest.

## Verdict

**Grade: Drifting.**

The core is built to a genuinely high bar and largely holds it: curve tags are carried
in-band and never derived from byte length in `auths-crypto`/`auths-keri`/`auths-core`
(an xtask lint, `check_curve_agnostic.rs`, enforces it); clock injection is honored with no
ambient `Utc::now()` in domain code; the SDK error surface is pure `thiserror`; `auths-rp`'s
verdict→principal→HTTP-status mapping is exhaustive with no fail-open `_ =>`; and several
typestates (`Envelope<Sealed|Open>`, `RootedBundle`, `AuthedPrincipal`, KERI `Threshold`/
`Capability`) are exemplary. But the *boundaries* drift looser than the core they protect.
The dominant signal is structural and tree-wide: **a validated value is unwrapped to a
`String`, threaded one or more layers, then re-asserted with `new_unchecked` under an
`INVARIANT:` comment** — the burndown loop's smallest-diff bias made visible, repeated across
**8 crates and 40+ sites**. Net runtime checks: the range *adds* re-validation (repeated
`strip_prefix("did:keri:")`, per-request `Capability::parse`, per-accessor base64 decode,
`is_zero()` re-checks) far more than it deletes. Three boundaries fail *open*, not closed —
`KeyRole` round-trips through a string and defaults to the most-privileged role on a parse
miss; a delegator with an unloadable scope seal is granted unrestricted via `u64::MAX`
sentinels; a malformed `--budget` becomes an effectively-infinite cap. And the
freshest code — the money types on the branch this review is named for — ships the proof
types (`NonZeroCents`) dead while the gate re-checks at runtime. The invariants are *checked
somewhere*; they are not yet *impossible to violate*.

## Themes (the cross-cutting type weaknesses — the deliverable)

### Theme A — The `new_unchecked` round-trip: a validated value is stringified, threaded, then re-wrapped unchecked. (8 crates, 40+ sites)
The signature smell. `IdentityDID::initialize_registry_identity(...)` returns a validated
`IdentityDID`; the caller `.into_inner()`s it to `String`, threads the bare string, then
re-wraps `IdentityDID::new_unchecked(format!("did:keri:{prefix}"))`
(`auths-sdk/.../identity/service.rs:108,153`). The same pattern, with its own hand-written
`#[allow(clippy::disallowed_methods)] // INVARIANT:` waiver each time, recurs in
`auths-id` (7 sites: `keri/types.rs:22`, `keri/delegation.rs:195,283,1030`,
`identity/initialize.rs:206,371,481`), `auths-core` storage read paths (5: `storage/
macos_keychain.rs:326`, `encrypted_file.rs:329`, `windows_credential.rs:232`,
`ios_keychain.rs:231`, `linux_secret_service.rs:215`), `auths-policy/verify.rs:499,531,544,
568`, `auths-storage/rebuild.rs:151` + `adapter.rs:1740,1743,1787,1790,1799` + `oobi.rs:196`,
`auths-scim`/`control_plane.rs:219`, and **`auths-cli` 25×** in `commands/org.rs` alone
(`Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string())`).
**Why it costs:** every waiver is a comment standing where a type should. The `did:keri:`
invariant is never actually enforced — it is hand-stripped and discarded. At the
storage/OOBI sites (`rebuild.rs:151`, `oobi.rs:196`) the value is *untrusted on read*: a
tampered tree name or hostile OOBI map-key becomes a "verified" SAID/DID the whole system
then trusts. The fix is nearly free — `IdentityDID::from_prefix` and `IdentityDID::parse`
**already exist** in `auths-verifier/types.rs:195,214`; the sites just don't call them.

### Theme B — Curve-from-byte-length dispatch at every embedding boundary — a documented OWN-BAR regression. (verifier, murmur, mobile-ffi)
`CLAUDE.md` bans dispatching on pubkey byte length ("33 bytes is ambiguous between P-256 and
secp256k1 … a silent-correctness hazard the moment a new curve lands"). The core obeys it
perfectly — and the FFI/WASM/mobile edges break it. `pk_from_bytes_ffi`
(`auths-verifier/ffi.rs:18-25`) and `pk_from_hex_wasm` (`wasm.rs:21-29`) both do
`match bytes.len() { 32 => Ed25519, 33|65 => P256, _ => err }`. `murmur-core/identity.rs:40,88`
hardcodes Ed25519 while `address.rs:46` builds an `Aid` with *no* in-band curve tag yet
doc-claims "the AID encodes the curve" — and `murmur` pairing actually mints P-256
(`pairing.rs:171`), so the two halves are silently non-interoperable. **Why it costs:** the
`crypto-secp256k1` feature flag already exists in `auths-core`; the day it reaches these
boundaries, a secp256k1 key is silently routed to P-256 and fails as `InvalidSignature`
(a crypto error masking a routing error) — exactly the documented failure mode. The
contract/presentation path next door (`KeriPublicKey::parse` on the in-band CESR tag) proves
the fix is one helper away.

### Theme C — Verification verdicts modeled as `valid: bool` beside `Option` data, not as sum types. (verifier, cli, policy, monitor, id, sdk)
`DeviceLinkVerification { valid: bool, error: Option<String>, key_state: Option<KeyState>,
… }` (`auths-verifier/verify.rs:156`), `ChainLink { valid: bool, error: Option<String> }`
(`types.rs:116`), CLI's `VerifyResult`/`VerifyCommitResult` (`verify_attestation.rs:80`,
`verify_commit.rs:72`), `BundleVerificationReport::is_valid()` (`auths-policy/bundle.rs:116`),
`monitor`'s `VerificationReport.consistency_ok` (`auths-monitor/lib.rs:92`),
`AnchorVerification { status, Option, Option, Option }` (`auths-id/keri/anchor.rs:85`).
**Why it costs:** `valid:true`+`error:Some` and `valid:false`+`error:None` are both
representable, and the bug is *live* — `auths-cli/verify_commit.rs:537` contains
`if result.error.is_none()` for the sole purpose of papering over the second illegal state.
These are externally-serialized verdicts (JS/FFI consumers branch on `valid`), so the
inconsistency escapes the crate. A verdict is a sum type; this is a sum type drawn as a
struct of flags.

### Theme D — Authority/role/capability enums flattened to `String` at the persistence/wire boundary and re-parsed permissively — including three fail-opens. (core, sdk, mcp-server, money, crypto)
The typed enum exists in memory but is serialized as text and reloaded with a permissive
default. The worst: `KeyRole` → `role.to_string()` → `parse::<KeyRole>().unwrap_or(
KeyRole::Primary)` at **5 storage backends** (`auths-core/storage/macos_keychain.rs:319`,
`ios_keychain.rs:225`, `windows_credential.rs:54`, `linux_secret_service.rs:211`,
`encrypted_file.rs:325`) — a corrupt/unknown role token silently becomes the
*most-privileged* role. `auths-mcp-server` keeps `tool_capabilities: HashMap<String,String>`
(`config.rs:29`) and re-runs `Capability::parse(required)` **per request**
(`keri_auth.rs:181`), turning a config typo into a per-request 500. JWT `idp_protocol:
String` and `allowed_algorithms: Vec<String>` (`auths-jwt/claims.rs:72,261`) leave the
`alg=none` downgrade representable. **Why it costs:** the round-trip re-validates what the
writer already had typed, and the permissive `unwrap_or`/default makes the failure path
*widen authority* instead of refusing.

### Theme E — Money: the unit newtypes landed, but the role-distinctions, the proof types, and the lifecycle did not. (auths-mcp-core, auths-mcp-gateway — the active branch)
`AtomicUsdc` passes the bar (cross-unit mixing is a compile error; the only atomic→cents path
is two total functions through one constant; sub-cent residue is refused). `Cents` does not:
(1) `Cents::new(u64)` (`money.rs:37`) is a transparent unchecked door every untrusted amount
enters through; (2) ceiling-vs-actual and reserved-vs-settled are all the same `Cents` and
silently swappable — `budget.reserve(Cents)` and `budget.settle(hold, Cents)` take the same
type (`money.rs`, `budget.rs:553`), exactly the "two u64s meaning different things" the brief
ranks highest; (3) `NonZeroCents` (`money.rs:73`) — the type whose entire docstring is "a
metered call with zero amount cannot be constructed" — is **built nowhere**, while the gate
re-checks `reserve_ceiling_cents.is_zero()` at runtime (`gate.rs:297`); (4) `SpendLogRecord`
(`audit.rs:33`) carries `rail`/`rail_response`/`settlement_commit` as three independent
`Option`s (2³ states, ~3 legal) and the audit re-derives the legal grouping at read
(`audit.rs:281,300`); (5) `Budget::parse` fails *open* to `u64::MAX` on malformed input
(`session.rs:42`). **Why it costs:** this is the code the branch is named for, the prompt
flags money as the sharpest case, and the invariants live in field comments and runtime
branches instead of the types.

### Theme F — Parse-once violated: the same `(curve,bytes)→key` / claims / DID parsed at 3+ layers. (keri, pairing, crypto/storage, scim, cli)
`CesrKey(String)` (`auths-keri/types.rs:590`) defers parsing past deserialization, so
`KeriPublicKey::parse` re-runs at 4+ validation sites, two of which swallow the error into
`false`/`continue`. The `(curve, base64) → KeriPublicKey` length-ladder is **triplicated** in
pairing (`response.rs:196`, `token.rs:302`, daemon `handlers.rs:451`). OIDC claims are decoded
into a typed `OidcTokenClaims`, thrown back to a `serde_json::Value` via `json!()`
(`auths-storage/oidc_validator.rs:199`), then re-extracted field-by-field
(`machine_identity.rs:96`). SCIM parses a DID, stringifies it, and re-parses it one layer up
with `.ok()` (`auths-scim-server/mapping.rs:138`). **Why it costs:** the proof is recomputed
instead of carried; each re-parse is an error path a caller must handle, and several
downgrade silently.

### Theme G — Typestate present but unenforced on the live path. (pairing)
`PairingFlow<Init→Responded→Confirmed→Paired>` with a `SasMatch` zero-sized proof
(`auths-pairing-protocol/protocol.rs:254-398`) is a textbook consuming-self typestate — with
**zero production callers**. The only shipping consumer (`murmur-ffi/pairing.rs:105`) calls
`PairingProtocol::complete()`, which derives the SAS and returns `CompletedPairing` *without
ever requiring a `SasMatch`*. So the advertised "Paired ⇒ SAS-confirmed" guarantee protects
nothing that ships, and the typestate itself still `.ok_or_else(…"impossible"…)`-unwraps an
`Option` the phantom param made unreachable (`protocol.rs:349,375`). **Why it costs:** a
typestate beside a wide bypass is worse than none — it reads as "handled."

## Findings

> Verdicts as given by the prompt: `leave it` / `tighten now` / `file as debt`. Locations
> are `crate/.../file.rs:line`. Multi-site findings list the representative sites.

### Money (active branch — read hardest)

**TD-001 · primitive-obsession (units: ceiling vs actual, reserved vs settled) · tighten now**
- Loc: `auths-mcp-core/budget.rs` (`reserve(Cents)`/`settle(Hold, Cents)`), ceiling at
  `auths-mcp-gateway/proxy.rs:314`, actual at `rail.rs:223`/`gate.rs:355`.
- Wide type: both the reserve ceiling and the settled actual are `Cents`;
  `Decision{reserved_cents, cumulative_cents}` are swappable.
- Introduce: `Ceiling(Cents)` / `Actual(Cents)` (or `ReservedCents`/`SettledCents`);
  `to_cents_ceiling -> Ceiling`, `to_cents_exact -> Actual`; `reserve(Ceiling)`,
  `settle(Hold, Actual)`.
- Deletes: no runtime `if` (the invariant is untyped today) — makes a silent ceiling/actual
  swap a compile error. Highest-value money newtype despite deleting no branch.

**TD-002 · re-validation (dead proof type) · tighten now**
- Loc: `auths-mcp-core/money.rs:73` (`NonZeroCents`, unused) vs the check at `gate.rs:297-309`.
- Wide type: metered ceiling carried as plain `Cents`; `if rail && reserve_ceiling.is_zero()
  → MeteredAmountRequired` re-checked in the gate.
- Introduce: thread the already-written `NonZeroCents`; a metered call's `judge` takes
  `rail: Option<(RailName, NonZeroCents)>` so "rail present ⟹ amount present" is structural;
  parse + emit `MeteredAmountRequired` at the boundary.
- Deletes: the `is_zero()` branch and the `MeteredAmountRequired` return at `gate.rs:297-309`.
  The cleanest "use the type you already wrote" win in the tree.

**TD-003 · illegal-state (lifecycle as flag-struct) · tighten now**
- Loc: `auths-mcp-core/audit.rs:33-58` (`SpendLogRecord`); legality re-derived at
  `audit.rs:281,300`.
- Wide type: `rail/rail_response/settlement_commit` as three free `Option`s; `rail:None` +
  `settlement_commit:Some` representable and meaningless.
- Introduce: `settlement: Settlement` enum — `None | Forwarded{rail, response} |
  Settled{rail, response, commit}`.
- Deletes: the paired-Option destructure at `audit.rs:281` and the `else { TamperedProof }`
  at `audit.rs:301`; the writer can no longer emit a commit without its rail+response.

**TD-004 · partial-function (audit downgrade keyed on unsigned data) · tighten now**
- Loc: `auths-mcp-core/audit.rs:300` (`if !recomputed.is_zero()`).
- Wide type: the "must carry an agent-signed settlement" requirement is gated on a cost
  re-extracted from the operator-held *unsigned* `rail_response`; a response extracting to
  zero skips the signed-settlement leg.
- Introduce: drive the requirement off TD-003's `Settlement::Settled` variant, not
  `is_zero()`.
- Deletes: the `if !recomputed.is_zero()` security predicate at `audit.rs:300` (keep the
  cross-check at `:347`). Couple with TD-003.

**TD-005 · unchecked-construction (budget fail-open) · tighten now**
- Loc: `auths-mcp-core/session.rs:42` + duplicated `auths-mcp-gateway/proxy.rs:677`,
  `replay.rs:148`.
- Wide type: `Budget::parse` returns `Budget::Cents(u64::MAX)` on unparseable input;
  `require_budget` only checks non-empty, never that it *parses* — a malformed `--budget` on a
  payment wrap becomes an infinite cap.
- Introduce: `Budget::parse(&str) -> Result<Budget, BudgetParseError>`; non-payment path
  chooses `unwrap_or(Budget::unbounded())` explicitly; payment path refuses fail-closed.
- Deletes: the silent `u64::MAX` default and the two duplicated fallbacks. **Fail-open on
  the real-money path.**

**TD-006 · boolean-blindness · tighten now**
- Loc: `auths-mcp-gateway/replay.rs:38` (`CallCost.extracted: bool`), paired with
  `charge_ref: Option` at `replay.rs:393`.
- Wide type: `extracted:true`+`charge_ref:None` representable; two fields encode one fact.
- Introduce: `enum CostSource { Declared{cents} | Extracted{cents, charge_ref, response} }`.
- Deletes: the `(Some(ref), true)` tuple-match at `replay.rs:393`. (Leave the disclosure-only
  `livemode`/`testnet` bools.)

### Curve-from-length (OWN-BAR regression)

**TD-007 · partial-function (curve from length) · tighten now**
- Loc: `auths-verifier/ffi.rs:18-25` (`pk_from_bytes_ffi`).
- Wide type: `&[u8] → DevicePublicKey` recovering curve from `bytes.len()`; 33 bytes assumed
  P-256 with no way to mean secp256k1.
- Introduce: require the curve tag in-band — accept a CESR-tagged verkey (route through
  `KeriPublicKey::parse(...).curve()`, as the presentation path already does) or add an
  explicit `curve: CurveType` C-ABI arg → `DevicePublicKey::try_new(curve, bytes)`.
- Deletes: the `match bytes.len()` curve-inference block and the
  `InvalidSignature`-masks-wrong-curve ambiguity. One feature flag (`crypto-secp256k1`) from
  live.

**TD-008 · re-validation (curve from length) · tighten now**
- Loc: `auths-verifier/wasm.rs:21-29` (`pk_from_hex_wasm`), feeding `verifyAttestationJson`/
  `verifyChainJson`.
- Same defect as TD-007 on the WASM entrypoints; fix with the same in-band-curve helper.

**TD-009 · partial-function / unchecked-construction (murmur curve) · tighten now**
- Loc: `murmur-core/identity.rs:40,88`, `address.rs:46`; mobile twin at
  `auths-mobile-ffi/device_kel_rotation.rs:152` (stamps `1AAI`/P-256 regardless of prior KEL
  curve).
- Wide type: `Aid(String)` with no curve tag; `from_seed`/`verify_sender` hardcode Ed25519
  while `IDENTITY_CURVE` and doc-comments claim agnosticism; P-256 AIDs (minted by
  `pairing.rs:171`) silently fail verification.
- Introduce: either be honest (delete `IDENTITY_CURVE`, document Ed25519-only, make the curve
  explicit) or tag the curve in-band via a parsing `Aid` constructor reusing
  `KeriPublicKey::parse`.
- Deletes: the latent mis-routing; "wrong curve" becomes a parse error, not a deep
  `InvalidSignature`.

### Verdicts as flag-structs

**TD-010 · illegal-state · tighten now**
- Loc: `auths-verifier/verify.rs:156` (`DeviceLinkVerification`), the WASM `verifyDeviceLink`
  result.
- Introduce: `enum DeviceLinkVerification { Linked{key_state, seal_sequence} | Failed{reason} }`
  (serde-tagged for the JS contract). Deletes every consumer's need to trust `valid`
  independently of which `Option`s are populated.

**TD-011 · illegal-state · tighten now**
- Loc: `auths-cli` `verify_attestation.rs:80`, `artifact/verify.rs:26`, `verify_commit.rs:72`.
- Wide type: `VerifyResult{valid:bool, error:Option<String>}`; the reconciliation
  `if result.error.is_none()` at `verify_commit.rs:537` exists only to patch the illegal
  state — proof the bug is live.
- Introduce: have the SDK return `enum Verdict { Valid{issuer, subject, witness_quorum} |
  Invalid{reason} }`; CLI only serializes it. Deletes the `:537` reconciliation.

**TD-012 · boolean-blindness / illegal-state · tighten now**
- Loc: `auths-policy/bundle.rs:116-134` (`is_valid()`).
- Wide type: six independent status enums collapsed to one `bool` via a hand-written
  `matches!` allow-list that silently green-lights `CheckpointStatus::NotProvided`
  (`bundle.rs:121`).
- Introduce: a `BundleVerdict { Trusted | TrustedWeak{reasons} | Rejected{failures} }` from a
  total fold over the six dimensions. Deletes the `matches!` allow-list + `&&` chain.

**TD-013 · illegal-state (status + parallel Options) · tighten now**
- Loc: `auths-id/keri/anchor.rs:85` (`AnchorVerification`).
- Wide type: `status: AnchorStatus` next to `Option<Said>`/`Option<u128>`/`Option<String>`;
  `Anchored`+`said:None` representable.
- Introduce: fold payload into the enum — `Anchored{said, sequence, signing_key: CesrKey} |
  NotAnchored`. Deletes every `if matches!(status, Anchored)` + `.unwrap()` pairing.

**TD-014 · illegal-state (monitor) · tighten now**
- Loc: `auths-monitor/lib.rs:92,263-302` (`VerificationReport.consistency_ok` via `&mut bool`
  out-param).
- Introduce: return `ConsistencyOutcome { Ok | Regressed{old,new} | Equivocation{size} |
  ProofFailed | ProofUnavailable }` (the typed `evidence::checkpoint_transition` already
  models the first three). Deletes the `&mut bool`/`&mut Vec` out-params and the
  duplicated inline size/root comparison.

### The `new_unchecked` DID epidemic (Theme A)

**TD-015 · unchecked-construction (×7+, one logical fix) · tighten now**
- Loc: `auths-id` `keri/types.rs:22`, `delegation.rs:195,283,1030`,
  `initialize.rs:206,371,481`.
- Wide type: `IdentityDID::new_unchecked(format!("did:keri:{prefix}"))`, each with its own
  `// INVARIANT:` waiver, all holding a validated `Prefix`.
- Introduce: `impl From<&Prefix> for IdentityDID` (or reuse the existing
  `IdentityDID::from_prefix`, `auths-verifier/types.rs:214`). All sites become
  `IdentityDID::from(prefix)`.
- Deletes: 7 `#[allow(clippy::disallowed_methods)]` + 7 hand-built `format!` strings;
  centralizes the `did:keri:` scheme.

**TD-016 · unchecked-construction (SDK string round-trip) · tighten now**
- Loc: `auths-sdk/domains/identity/service.rs:108,153,171`; `rotation.rs:355`;
  `credentials/authenticate.rs:154`.
- Wide type: validated `IdentityDID` → `.into_inner()` → threaded `String` → re-wrapped
  `new_unchecked`; `with_parent_did(impl Into<String>)` reaches `new_unchecked` at `:171`
  while the *same field* is parsed with `IdentityDID::parse` at `:544`.
- Introduce: have `resolve_or_create_identity`/`initialize_ci_keys` return the
  `IdentityDID` they already hold; type `parent_identity_did: Option<IdentityDID>`; call
  `parse_did_keri`/`identity.controller_did.prefix()` in rotation instead of hand-stripping.
- Deletes: the `new_unchecked` sites + the `authenticate.rs:154`
  `unwrap_or(issuer.as_str())` lossy fallback that passes a non-`did:keri:` issuer through
  unstripped.

**TD-017 · unchecked-construction (untrusted disk/OOBI read) · tighten now**
- Loc: `auths-storage/rebuild.rs:151`, `adapter.rs:1740-1799`, `oobi.rs:196`;
  `auths-core` storage read paths (5 backends, `macos_keychain.rs:326` et al.).
- Wide type: `serde_json::Value::as_str()` / on-disk tree filenames / OOBI map-keys →
  `IdentityDID`/`Said`/`Prefix::new_unchecked` on the **read** path; the "validated on insert"
  invariant is circular (insert trusts the type, the type was built unchecked at rebuild).
- Introduce: call the existing `CanonicalDid::parse`/`Said::parse`/`IdentityDID::parse` at
  the read point (mirror the already-correct `visit_devices` at `adapter.rs:1297` and the
  `commit_oid` treatment at `index.rs:293`), mapping to the existing `InvalidData`/
  `StorageError`.
- Deletes: ~7 false `INVARIANT` waivers; converts a tampered tree / corrupt keystore from
  silent trust into a typed error.

**TD-018 · primitive-obsession (CLI DID-as-String, 25+ sites) · tighten now**
- Loc: `auths-cli/commands/org.rs` (23×), `compliance.rs:48,299,376`, `namespace.rs:170`,
  `artifact/verify.rs:565,677` (`resolve_pk_from_did(did: &str)` with `else => bail`).
- Wide type: DID is `String` from clap; each handler does
  `Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org)…)`; method resolution
  is a `starts_with` ladder with a fallthrough.
- Introduce: a clap `value_parser = IdentityDID::parse` (a `TypedValueParser`) so the arg is
  parsed once at the boundary; `resolve_pk_from_did(&CanonicalDid)` matches the parsed method
  exhaustively.
- Deletes: 25 `strip_prefix(...).unwrap_or` + `new_unchecked` sites, ~28 `starts_with`/
  `strip_prefix` checks, and the `else => "Unsupported DID method"` arm. Collapses TD-018 +
  the CLI re-validation/leak findings together.

**TD-019 · unchecked-construction (untyped Git ref path → injection) · tighten now**
- Loc: `auths-storage`/`infra-git/approval.rs:17,40,44` (`request_hash: String`,
  `jti: &str` → `format!("refs/auths/approvals/pending/{}", request_hash)`).
- Wide type: a doc-says-hex-SHA256 `String` enforced by nothing flows unchecked into a git
  ref path; a value containing `/` or `..` forges the ref — **no sanitization anywhere**.
- Introduce: `RequestHash([u8;32])` / `Sha256Hex` with `parse` enforcing 64 lowercase hex;
  `pending_ref`/`consumed_ref` take it so the segment is unforgeable; `allowed_approvers:
  Vec<CanonicalDid>`.
- Deletes: the absent-but-required path-segment sanitization at all six ref-builder sites.
  **Security-relevant beyond pure type-driven — flag prominently.**

### Authority/role flattened to String + fail-opens (Theme D)

**TD-020 · illegal-state / partial-function (fail-open to most-privileged) · tighten now**
- Loc: `auths-core` 5 backends: `macos_keychain.rs:319`, `ios_keychain.rs:225`,
  `windows_credential.rs:54`, `linux_secret_service.rs:211`, `encrypted_file.rs:325`.
- Wide type: `KeyRole` persisted as `role.to_string()`, reloaded
  `parse::<KeyRole>().unwrap_or(KeyRole::Primary)` — corrupt/unknown token → **Primary**.
- Introduce: a stable `u8` tag with `from_tag(...) -> Result` (the pattern
  `EncryptionAlgorithm::tag`/`from_tag` at `crypto/mod.rs:29` already uses), or
  `KeyRole::from_persisted(&str) -> Result<_, AgentError>` — no `unwrap_or`.
- Deletes: 5 duplicated `unwrap_or(Primary)` fall-throughs; the round-trip becomes total.
  **The single scariest fail-open in the tree.**

**TD-021 · partial-function (fail-open grant via sentinel) · tighten now**
- Loc: `auths-sdk/domains/agents/delegation.rs:317-330`.
- Wide type: "no scope seal" and "unrestricted root" both `Ok(())`; authority disabled via
  `remaining_ttl_secs: u64::MAX` / `max_depth: u32::MAX` magic values — a delegator whose seal
  *fails to load* is silently granted.
- Introduce: `enum DelegatorAuthority { Root | Scoped(AgentScope) }` from the resolver; the
  `else` grant becomes a named `Root` arm, fail-closed unless proven; capability-only checks
  use a dedicated request type, not `MAX`.
- Deletes: the `u64::MAX`/`u32::MAX` sentinels and the implicit permissive early-return.

**TD-022 · primitive-obsession / re-validation (per-request capability parse) · tighten now**
- Loc: `auths-mcp-server` `config.rs:29`, `state.rs:35`, `keri_auth.rs:181`.
- Wide type: `tool_capabilities: HashMap<String, String>`; KERI path runs
  `Capability::parse(required)` per request, JWT path raw-string-compares — two equality
  notions; a config typo is a per-request `Internal` 500.
- Introduce: `HashMap<String, Capability>` parsed once at config build (`with_tool_capabilities
  -> Result`).
- Deletes: the hot-path `Capability::parse` at `keri_auth.rs:181` and the reachability of its
  `Internal` arm; unifies equality.

**TD-023 · primitive-obsession / illegal-state (JWS alg, alg-confusion) · tighten now**
- Loc: `auths-oidc-port/ports.rs:28`, `auths-jwt/claims.rs:261` (`allowed_algorithms:
  Vec<String>`), error at `auths-jwt/error.rs:38`.
- Wide type: JWS alg names as open strings; `"none"`, `"HS256"`, case variants representable
  and indistinguishable from valid entries.
- Introduce: `enum JwsAlg { Rs256, Es256, … }` (explicitly no `None`), `Vec<JwsAlg>`; parse
  the header alg once. Deletes the string-membership test and makes `alg=none` unrepresentable.

**TD-024 · primitive-obsession (idp_protocol) · tighten now**
- Loc: `auths-jwt/claims.rs:72` (`idp_protocol: String`).
- Introduce: `enum IdpProtocol { Oidc, Saml }` with `#[serde(rename_all="lowercase")]`
  (mirror `CurveType` at `provider.rs:632`). Cheap; it's an auth-routing discriminant.

### Parse-once violations (Theme F)

**TD-025 · re-validation / illegal-state (OIDC port returns Value) · tighten now**
- Loc: `auths-oidc-port/ports.rs:168` (`validate -> Result<serde_json::Value>`); the actual
  MCP consumer sidesteps the port and re-validates by hand at `auths-mcp-server/auth.rs:175`;
  `auths-storage/oidc_validator.rs:199` decodes to typed claims then `json!()`s them back,
  re-extracted at `machine_identity.rs:96`.
- Introduce: the trait returns parsed `VerifiedClaims` (`OidcClaims` with `iss`/`aud`/`exp`
  proven by serde); push the registered-claim presence check into deserialization.
- Deletes: the per-consumer `value.get("iss")?.as_str()?…` triple, the `json!()` round-trip,
  and ~45 lines of re-extraction. The single highest-cost wide type at the attacker-controlled
  boundary.

**TD-026 · re-validation (curve→key triplicated) · tighten now**
- Loc: `auths-pairing-protocol/response.rs:196`, `token.rs:302`, `auths-pairing-daemon/
  handlers.rs:451`.
- Introduce: one `KeriPublicKey::from_curve_and_bytes(CurveType, &[u8]) -> Result` in
  `auths-keri`; the three sites call it. Deletes the two duplicate `match curve {…try_into…}`
  ladders (and `verify_response` in `token.rs` appears dead — candidate for deletion).

**TD-027 · re-validation (Rekor hex decode ×4) · tighten now**
- Loc: `auths-infra-rekor/client.rs:121-145,459-483`.
- Wide type: `root_hash: String`/`hashes: Vec<String>` open-coding `hex::decode → try_into::
  <[u8;32]>` four times.
- Introduce: nothing new — `MerkleHash::from_hex` (`tlog/types.rs:34`) already is the
  operation; map its error once. Deletes ~40 lines → ~4.

**TD-028 · re-validation (provision DID parse→stringify→re-parse) · tighten now**
- Loc: `auths-scim-server/users.rs:51` + `mapping.rs:138`; provisioner returns typed
  `IdentityDID` at `provisioner.rs:186`.
- Introduce: `ProvisionAgentResult.identity_did: IdentityDID` (both sides in-crate, no wire
  constraint). Deletes the `.as_str().to_string()` hop and the `IdentityDID::parse(...).ok()`
  re-parse (which currently can silently null a proven-valid DID).

### Typestate (Theme G)

**TD-029 · typestate (bypassed on the live path) · tighten now**
- Loc: `auths-pairing-protocol/protocol.rs:115` (`complete()`), the `PairingFlow` block
  `254-398`; sole caller `murmur-ffi/pairing.rs:105`.
- Introduce: make the typestate the only in-crate path — either delete `complete()` and route
  murmur-ffi through `initiate → accept_response → confirm(SasMatch) → finalize`, or have
  `complete()` return `PairingFlow<Responded>` so a `SasMatch` is required to extract
  `CompletedPairing`. Converts the SAS-confirmation invariant into a compile error at the one
  real call site.

**TD-030 · typestate (runtime-unwrap inside the typestate) · tighten now**
- Loc: `auths-pairing-protocol/protocol.rs:256,349,375`.
- Wide type: `PairingFlow<S>{ accepted: Option<…>, _state: PhantomData<S> }` — state in both
  `S` and the `Option`; `sas()`/`finalize()` `.ok_or_else(…"impossible"…)`.
- Introduce: move the payload into the states that own it (`Responded{session, accepted: …}`,
  no `Option`). Deletes the two `ok_or_else` unwraps and the `accepted: None` placeholder
  threading. Do with TD-029 (same edit).

### Other tighten-now (concise)

**TD-031 · partial-function (weighted-threshold collapse) · tighten now** —
`auths-keri/ksn.rs:448` `state.backer_threshold.simple_value().unwrap_or(0)` collapses a
`Threshold::Weighted` to a no-quorum-required `0` (regression of the F-15 fix
`validate.rs` already applied for `nt`). Route through the typed `Threshold::is_satisfied`.

**TD-032 · unchecked-construction (Seal wire deserialize) · tighten now** —
`auths-keri/events.rs:269-290` `Seal::deserialize` builds every `Said`/`Prefix` via
`new_unchecked`, skipping even the empty-check the direct `Deserialize` impls enforce. Call
the checked `Said::new`/`Prefix::new` inside `want_str`, mapping to `serde::de::Error`.

**TD-033 · illegal-state / re-validation (PinnedKey decode-once) · tighten now** —
`auths-core/trust/pinned.rs:27,56`, `roots_file.rs:48,100`: `PublicKeyHex` (string) beside a
separate `CurveType`, re-decoded on every `key_matches`. The pair can disagree (66-char P-256
hex tagged Ed25519). Introduce `PinnedKey::parse(hex, curve) -> Result` storing decoded
bytes + curve validated together; deletes the per-call `hex::decode` and the `Result` at every
comparison site.

**TD-034 · illegal-state (signature classified by substring sniff) · tighten now** —
`auths-infra-git/audit.rs:97-122` classifies a signature by `from_utf8_lossy().contains(
"auths")`, producing `AuthsSigned{signer_did: String::new()}` (empty proof) and
`GpgSigned{verified:false}` (never set true). Introduce `parse_signature(&[u8]) ->
Result<ParsedSignature>` carrying a non-empty `SignerDid`; verification becomes a separate
verdict. Violates the `CLAUDE.md` ban on in-band content guessing for security routing.

**TD-035 · re-validation / illegal-state (platform gate via Value) · tighten now** —
`auths-storage/platform_context.rs:59-103` decides a registration/authorization gate via
`.get("status").and_then(as_str).unwrap_or("unknown")` ladders + a `match platform { … _ =>
{} }` that silently drops a *verified* claim for any server-added platform. Introduce a typed
`IdentityResponse{status: RegistrationStatus, platform_claims: Vec<PlatformClaim>}` with
`Platform` using `#[serde(other)] Unknown` (the sibling `claim_client::ServerClaimResponse`
already proves the pattern).

**TD-036 · illegal-state (SCIM PATCH as flag-struct) · tighten now** —
`auths-scim/patch.rs:21` `PatchOperation{op:String, value:Option<Value>}` re-parsed in the
apply loop (`patch.rs:72`); partial mutation precedes the error. Introduce
`#[serde(tag="op")] enum PatchOperation { Add{path,value} | Remove{path} |
Replace{path,value} }`.

**TD-037 · boolean-blindness / illegal-state (allow_all beside allowlist) · tighten now** —
`auths-scim-server/state.rs:39`, `auth.rs:37`: `allow_all: bool` beside
`allowed_capabilities: Vec<Capability>`; every gate must check `allow_all` first
(`mapping.rs:91`, `lifecycle.rs:46`). Introduce `enum CapabilityPolicy { AllowAll |
Restrict(Vec<Capability>) }` with a `validate` method; deletes the repeated `if !allow_all`
guard.

**TD-038 · re-validation (gate with three owners) · tighten now** —
`auths-mcp-server/routes.rs:88-98` re-runs the per-tool capability check that `auth.rs:104`
and `keri_auth.rs:178` already performed. Introduce `AuthorizedCall{agent, tool}` produced
only by a gate fn (mirror `auths-api`'s `AuthedPrincipal`), taken by extractor; the handler
can't run without the gate.

**TD-039 · illegal-state (KeyBacking) + magic-None status · tighten now** —
`auths-sdk/signing/service.rs:355` `ResolvedKey{seed:Option<SecureSeed>, is_hardware:bool}`
(`(Some,true)`/`(None,false)` illegal) → `enum KeyBacking{Software(SecureSeed) | Hardware}`;
and `identity/types.rs:574` `AgentIdentityResult{agent_did:Option, parent_did:Option}` whose
sole producer always sets `agent_did:None` → `enum AgentOutcome{Proposed{parent} |
Created{agent, parent}}`.

**TD-040 · illegal-state (wire confirmation) · tighten now** —
`auths-sdk/pairing/delegation.rs:219` `GetConfirmationResponse{aborted:bool,
encrypted_attestation:Option<String>}` with live error-handling for the `(false,None)`
illegal state → `enum ConfirmationOutcome { Anchored(String) | Aborted }`.

**TD-041 · re-validation (read_tip/cached_state dedup + silent-corrupt inconsistency) ·
tighten now** — `auths-storage/adapter.rs:747,806,1008,2284` re-deserialize `TipInfo`/
`CachedStateJson` inline with `.ok()` (swallows a corrupt tip to "no tip" in one path while
`update_metadata` treats corruption as a hard error). Two private typed readers
`read_tip`/`read_cached_state -> Result`.

**TD-042 · partial-function (EntryKind) · tighten now** —
`auths-infra-git/tree_ops.rs:344,366` use foreign `git2::ObjectType` where only `{Blob,Tree}`
are legal, with `_ => 0o100644` / `unwrap_or(Blob)` (a submodule/symlink silently re-encoded
as a blob) and an O(blob-size) read used as a type test. Introduce `enum EntryKind{Blob,Tree}`
with `TryFrom<git2::ObjectType>`.

**TD-043 · primitive-obsession (telemetry status) · tighten now** —
`auths-telemetry/event.rs:23` `status: &str` with `pub` fields; a typo'd `"denied"` misses
every SIEM rule (the consumer's query becomes the validator). `enum Outcome{Success, Denied,
Error}` via `#[serde(rename_all)]`; type the fields so a public literal can't express an
illegal state.

**TD-044 · re-validation (DID resolver) · tighten now (in-method) / debt (trait)** —
`auths-id/identity/resolve.rs:114-123` re-does `starts_with`/`strip_prefix`/`is_empty` with an
`unreachable!()` confessing the `&str` is too wide. In-method: `match IdentityDID::parse(did)`.
The `&str` trait contract (`auths-core/signing.rs:168`) is debt.

**TD-045 · illegal-state (PresignedRevocation typed fields) · tighten now** —
`auths-id/attestation/revoke.rs:161` stores `device_did/issuer: String, signature: Vec<u8>`
and is `Deserialize`d from storage with the `not_before < not_after` window **never
re-checked**. Type the fields (`CanonicalDid`/`IdentityDID`/`Ed25519Signature` already exist)
and enforce the window in a custom `Deserialize` (or `Verified`/`Unverified` split).

**TD-046 · illegal-state / partial-function (dead Outcome variant past strict collapse) ·
tighten now** — `auths-policy/decision.rs:39` `Outcome::MissingCredential` has no constructor
but is `Deserialize`able and carried unchanged through the strict-mode collapse at
`eval.rs:32` (where `Indeterminate` correctly becomes Deny). Drop the variant or give it a
ctor + an explicit strict arm. Reachable via untrusted input.

**TD-047 · illegal-state (relay DepositResponse string) · tighten now** —
`murmur-relay/http.rs:41-45` `outcome: &'static str` hand-mapped from the clean
`DepositOutcome` enum; a typo or a future variant silently drops. `DepositOutcome::as_wire`/
`http_status` beside the enum; handler becomes `(o.http_status(), Json(o))`.

**TD-048 · partial-function (monitor `_ =>` over live variants) · tighten now** —
`auths-monitor/lib.rs:218` folds `CheckpointStatus::MissingEcdsaSignature` and
`MissingEcdsaKey` (both live, operator-actionable) into one opaque `{other:?}` line.
Enumerate the known variants; keep a `#[non_exhaustive]`-mandated "unknown verdict — monitor
older than verifier" arm.

## The one type worth introducing now

**Make `IdentityDID`'s validated constructor the *only* door — add `impl From<&Prefix> for
IdentityDID` and route every storage/SDK/CLI boundary through `IdentityDID::parse`.**

This is the single change with the largest blast radius of *deleted code and re-checks* in the
tree, and it is nearly free because the validated constructors already exist
(`IdentityDID::parse`, `IdentityDID::from_prefix` in `auths-verifier/types.rs:195,214`) — the
40+ sites simply don't call them.

- **The type / smart constructor:** `impl From<&Prefix> for IdentityDID` (infallible — a
  `Prefix` already carries the proof) for the internal "I hold a validated prefix" sites;
  `IdentityDID::parse(&str) -> Result<IdentityDID, _>` for the untrusted boundaries
  (storage read, clap args, OOBI). Make raw `IdentityDID::new_unchecked` / `Prefix::
  new_unchecked` `pub(crate)` so a wire/disk/CLI site *cannot* reach for them.
- **What it compiles away:** the 7 `format!("did:keri:{}")` + `new_unchecked` waivers in
  `auths-id` (TD-015), the 5-backend `new_unchecked` storage reads in `auths-core` (TD-017),
  the SDK `.into_inner()`→thread→re-wrap round-trips (TD-016), the `rebuild.rs`/`oobi.rs`
  untrusted-read unchecked sites (TD-017), and — the big one — the **25 `strip_prefix(
  "did:keri:").unwrap_or(...)` + `new_unchecked` sites in `auths-cli/commands/org.rs`** plus
  ~28 `starts_with`/`strip_prefix` method checks across the CLI (TD-018), and the
  `resolve_pk_from_did` `else => bail` fallthrough (becomes an exhaustive `match` on a parsed
  `CanonicalDid`). It closes the two genuinely *reachable* illegal states — a tampered Git
  tree name and a corrupt keystore entry — that currently become "verified" DIDs.

Net: one trait impl + one `pub(crate)` visibility change, deleting ~40 unchecked
constructions and ~50 re-validation checks, and turning "the `did:keri:` invariant is asserted
by comment" into "the invariant is the type."

**Runner-up, and the one to land *first on this branch*:** the money pair **TD-001**
(`Ceiling`/`Actual` role-newtypes so a reserve/settle swap is a compile error) **+ TD-003**
(`Settlement` enum replacing the three-`Option` spend-log record). `dev-agentMoney` is the
active branch, the prompt ranks money confusion highest, and these two close the
swappable-units and mid-lifecycle illegal states on the code that is changing right now —
before they compound.

## Type-debt ledger (file-and-forget)

- **TD-D01** `auths-keri/types.rs:590` `CesrKey(String)` defers parse past deserialize; 4+
  re-parses, two error-swallowing (`validate.rs:967,1411,1440`). Debt, not a quick fix —
  the `String` repr is load-bearing for keripy byte-exact round-trip; currently fails closed.
- **TD-D02** `auths-crypto/key_ops.rs:217` `TypedSignerKey.public_key: Vec<u8>` forces the
  `cesr_encoded_pubkey` `expect()` (`:278`); a `VerKey{Ed25519([u8;32])|P256([u8;33])}` enum
  makes length-vs-curve structural. Unreachable today.
- **TD-D03** `auths-verifier` `ChainLink` (`types.rs:116`) and the bare-`bool`
  `wasm_verify_artifact_signature` (`wasm.rs:145`) — report DTOs downstream of the real
  verdict; sum-type-ify when next touched.
- **TD-D04** `auths-id` `org: &str` on registry backend traits (`registry/backend.rs:700+`)
  re-`format!`s `did:keri:{org}` per call; `org: &Prefix` when the trait surface is next
  opened. Receipt ref string-surgery (`storage/receipts.rs:185`) → `ReceiptRef{prefix, said}`.
- **TD-D05** `auths-sdk` `validate_commit_sha -> String` (`signing/service.rs:462`) discards
  the 40/64-hex proof into `AttestationInput.commit_sha: Option<String>`; `CommitSha(String)`
  newtype (return-type now; threading it through `auths-id` is cross-crate debt).
- **TD-D06** `auths-policy` repo/env/role scope predicates stay raw `String` in `CompiledExpr`
  (`compiled.rs:54`) — `CanonicalRepo/Env/Role` only if case/whitespace canonicalization is
  actually wanted; otherwise ceremony. `InclusionProof`/`ConsistencyProof` `pub` fields
  (`proof.rs:26`) → private + `new` smart ctor; the real win is binding `proof.root` to the
  checkpoint (deletes the duplicated `proof.root != checkpoint.root` at `verify.rs:149,435`).
- **TD-D07** Transparency position integers — `Entry.sequence: u128` vs `InclusionProof.index:
  u64` vs `Checkpoint.size: u64` (`entry.rs:173`, `proof.rs:27`) — `LeafIndex`/`TreeSize`/
  `Sequence` newtypes only when a transposition bug appears; no reachable bug today.
- **TD-D08** `auths-pairing-protocol` `Base64UrlEncoded::from_raw` (`types.rs:11`) stores
  unvalidated; `PairingResponse` raw-`String` pubkeys re-decoded per accessor (`response.rs:22`
  ) while the sibling `SubmitResponseRequest` uses the typed newtype — apply it consistently.
  Daemon `DaemonState` four-mutex session lifecycle (`state.rs:36`) → one
  `SessionState` enum (real refactor, locking-granularity implications — not now).
- **TD-D09** `auths-mobile-ffi` `PairingResponsePayload` curve-beside-pubkey + `did`/`prefix`
  duplication (`lib.rs:137`); URI parse→stringify→re-parse (`lib.rs:436`, `pairing_context.rs:
  206`). Out-edge Records; lower severity.
- **TD-D10** `auths-checkpoint-cosigner` `CosignRequest.old_size` (`lib.rs:140`) is accepted
  and silently ignored; `murmur-ffi` `message_id: Vec<u8>` doc-claims 16 bytes while minting 8
  (`messaging.rs:54,87`) — fix the doc/length contradiction. Rekor zero-key / zero-`old_root`
  sentinels (`infra-rekor/client.rs:183,488`) — the fix lives upstream in
  `auths-transparency`/`auths-verifier` shared types.

## Explicitly leave it (verified clean — don't "fix" into a wildcard)

- **Curve tagging in `auths-crypto`/`auths-keri`/`auths-core`** — in-band everywhere, never
  length-derived; `from_public_key_len_fallback` is unused and CI-banned. The model the
  embedding edges (TD-007/008/009) should regress *to*, not from.
- **Clock injection** — no ambient `Utc::now()` in any domain code; all time-sensitive fns
  take `now: DateTime<Utc>`. Bar met tree-wide.
- **`auths-rp` verdict→principal→HTTP-status** — exhaustive, no fail-open `_ =>`, 401-vs-403
  unconfusable, principals proof-carrying, wire parsed once into `PresentationEnvelope`.
- **`auths-api` `AuthedPrincipal` / SCIM `AuthenticatedTenant`** — private-field
  extractor-only typestate; "handler reads an unset principal" is unrepresentable. The
  reference standard the MCP server (TD-038) should match.
- **`AtomicUsdc`** (`money.rs:108`) — cross-unit mixing is a compile error, single-sourced
  conversion, sub-cent residue refused. Money done right.
- **`Envelope<Sealed|Open>` / `RootedBundle` / `JoinerPending`** typestates, KERI
  `Threshold`/`Capability`/`Fraction`, `WitnessParams{Enabled|Disabled}`,
  `policy::context_from_credential` (fail-closed by type), `auths-id` exhaustive `Event`
  matches, `auths-core` `TrustDecision`/`TrustLevel`, murmur `DepositOutcome`/`TrustState`/
  `Session` zeroization — all already make their illegal states unrepresentable.
- **`KeriPublicKey::transferable: bool`** (`keys.rs:86`), pairing daemon `ParsedAuth` raw
  bytes, `auths-index` statelessness, `AgentHandle` `AtomicBool` locking — newtyping these
  would be ceremony with no proof gained (per the zero-cost rule).

## Active-branch gateway security hardening — cross-reference (added 2026-06-19)

A separate, in-flight track on `dev-agentMoney` is hardening the MCP payment gateway to this
review's bar, driven by the gateway findings in `red_team_2026-06-18.md` (RT-A-01/02/03) via
`red_team_gateway_remediation_2026-06-19.md`. It is scoped to **`auths-mcp-core` +
`auths-mcp-gateway` only** (treasury + murmur out of scope). This note maps that track's four
items onto this review's findings so the report is complete w.r.t. the code changing right now.
The two passes are complementary: this review is a *type* audit (illegal-states / re-validation /
parse-once); the hardening track also carries security-shaped items a pure type audit does not
surface (counter location, audit cross-check, independent attestation).

**Item 0 — the ceiling enum (implemented on branch, pending gate + commit; realizes TD-002).**
Models the proxy's cost as `enum CallCost { Free | Metered { rail, ceiling: NonZeroCents, settle:
SettleSource } | AmountRequired { rail } }` and feeds the gate a `Meter { Unmetered | Metered {
rail, ceiling: NonZeroCents } }` (the named form of TD-002's suggested `rail: Option<(RailName,
NonZeroCents)>`). `call_cost` parses the agent's declared amount into the enum at the wire
boundary; `call_tool` emits `metered-amount-required` there, before the gate. **Closes TD-002 in
full** — `NonZeroCents` is now load-bearing and the `gate.rs` `is_zero()` / `MeteredAmountRequired`
runtime branch is deleted (the type makes a zero metered ceiling unconstructible). Also resolves
the *proxy* half of the two-`CallCost` debt (D1 in `architectural_review_2026-06-18.md`) by giving
the settle source its own variant axis (`SettleSource::{RailResponse, Declared}`), no fallthrough.
- *Not covered by Item 0:* **TD-006** — replay's `CallCost.extracted: bool` + `charge_ref: Option`
  is left as-is (only projected to a `Meter` for the gate). The `enum CostSource { Declared |
  Extracted{…} }` cleanup remains an optional follow-on.

**Item A — one durable counter the audit can locate (NEW; not surfaced by this review).**
Introduces a `CounterKey` newtype + `CounterKey::for_agent(&Did)` smart constructor (no `Default`,
no `"wrap-session"` String sentinel) and a `CounterRef` the audit, the `verify-spend` CLI, the
replay gate, and the live wire all derive *identically* from `(registry, Did)`; re-keys the live
counter to the real agent `did:keri:` under the chain's `org_repo` (reordering `serve()` to build
the chain before opening the budget). Type-driven in spirit — it deletes the `"wrap-session"`
sentinel and makes the counter location single-derivable — but its driver is a security gap (the
standalone CLI cannot locate the live counter, so Item B's cross-check has nothing to open) that a
type audit would not flag. Foundation for Item B.

**Item B — the audit is a parser returning a proof, cross-checked against the counter (extends
TD-003/TD-004; the proof + cross-check are NEW).** `audit_spend_log` returns a proof-carrying
`Consistent` (private fields / smart constructor, carrying `SettledCents`) constructible only after
the back-link continuity check **and** a `DurableSettled` cross-check (opened via Item A's
`CounterRef`) both pass — closing the tail-truncation gap (RT-A-03) the back-link alone misses, plus
the strongest tamper-evidence tractable when operator==verifier (a signed `{count, cumulative}`
checkpoint anchor; the residual honestly parked where the operator also holds the counter).
- *Overlap to land together:* **TD-003** (`SpendLogRecord`'s three free `Option`s → a `Settlement`
  enum) and **TD-004** (the `if !recomputed.is_zero()` predicate keyed on unsigned data) rewrite the
  same `audit.rs` / `SpendLogRecord` surface Item B touches — do them in the same pass.

**Item C — independent rail attestation as `Attested<Cents>` (NEW; not surfaced by this review).**
A proof-carrying `Attested<Cents>` whose only constructor verifies an *independent* attestation (a
facilitator-signed receipt over `{payment-id/tx, amount}`, or a decoded on-chain tx value); the
audited total can only sum `Attested<Cents>`, removing the trust-the-operator-bytes path at the type
level (RT-A-02 part b). This review's money themes stop at units/roles/lifecycle (TD-001/003/005/006)
and do not reach independent attestation, so this is additive.

**This review's gateway-money findings the four items do NOT close (still open on the branch):**
- **TD-001** — `Ceiling`/`Actual` (reserved-vs-settled) role-newtypes. Item 0 makes the metered
  *ceiling* `NonZeroCents` but does not split the reserve-ceiling and settled-actual *roles*; a
  `reserve`/`settle` swap is still only a `Cents`. Highest-value remaining money newtype.
- **TD-005** — `Budget::parse` fail-open to `u64::MAX` on a malformed `--budget` (an infinite cap on
  the real-money path). Squarely in the gateway track's scope and a fail-open; recommend pulling it
  into the hardening pass.
- **TD-006** — replay `CallCost` boolean-blindness (above).

**Recommended sequencing (decided 2026-06-19).** Keep the active gateway loop (Items 0/A/B/C)
focused — do NOT fold the tree-wide findings into it (TD-005 is the one in-scope exception, held for
a separate decision). Do NOT treat this report as a 48-item campaign; its value is front-loaded.
The cut line:
- **Now-ish, separate short pass (after the gateway hardening):** the ~7 reachable *fail-opens* —
  TD-005, TD-017, TD-019, TD-020, TD-021, TD-023, TD-034 — where "leave as is" means a live
  authority-widening / money bug, plus the `IdentityDID` single-door pass (TD-015/016/017/018, the
  biggest deletion payoff in the tree).
- **Recurrence gate (highest leverage):** make `*::new_unchecked` / `Prefix::new_unchecked`
  `pub(crate)` and ban them outside the defining crate via an xtask/clippy lint, so the drift this
  report documents stops re-accreting (it is caused by the burndown loop's smallest-diff bias, which
  a one-time sweep does not fix).
- **Boy-scout rule, NOT a sprint:** the remaining ~30 cleanliness findings (verdict-as-`bool`→sum
  type, enum-flattened-to-`String`, parse-once, the FFI curve-from-length edges) — fix when already
  editing that file. Their failure mode is "confusing error," not "breach."
- **Leave it:** the report's own "Explicitly leave it" list + the entire `TD-D*` debt ledger.

---

Reviewed through: 821b22d83ebf44ae78768531447a88d3c517d6df
