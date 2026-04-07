# KERI Spec Compliance Audit: `auths-keri`

**Spec reference:** [Trust over IP KSWG KERI Specification v1.1](https://trustoverip.github.io/kswg-keri-specification/)
**Crate audited:** `crates/auths-keri/` (commit on branch `dev-keriStandardize`)
**Date:** 2026-04-07

This document maps every normative deviation between our implementation and the KERI spec. Each epic is a logically grouped body of work. Each task includes the spec requirement, what our code does, and a concrete fix with code snippets.

---

## CRITICAL: Typing Discipline for All Changes

**Every change in this document MUST follow "parse, don't validate" — use Rust's type system to make invalid states unrepresentable.**

When implementing any task below, never introduce a new `String` or `Vec<String>` field for structured KERI data. The crate already has good newtypes (`Said`, `Prefix`, `KeriSequence`, `KeriPublicKey`) but many fields bypass them. This is the root cause of bugs like thresholds parsed as decimal instead of hex — the raw string propagates unchecked until some deep validation function tries to interpret it.

**Rules for every new or modified field:**

1. **Thresholds** (`kt`, `nt`, `bt`): Use a `Threshold` enum — `Simple(u64)` for hex integers, `Weighted(Vec<Vec<String>>)` for fractional clause lists. Deserialize with hex parsing. Never store as `String`.

2. **Keys** (`k`, `current_keys`): Use `Vec<CesrKey>` — a newtype over `String` that validates the CESR derivation code prefix on construction. `KeriPublicKey` should be derivable from `CesrKey` without re-parsing.

3. **Commitments** (`n`, `next_commitment`): Use `Vec<Said>` — these are `E`-prefixed Blake3-256 digests, structurally identical to SAIDs. `compute_next_commitment` should return `Said`, not `String`.

4. **Backer/Witness AIDs** (`b`, `br`, `ba`): Use `Vec<Prefix>` — witnesses are fully qualified AIDs per the spec.

5. **Configuration traits** (`c`): Use `Vec<ConfigTrait>` where `ConfigTrait` is an enum with variants `EstablishmentOnly`, `DoNotDelegate`, etc. — not `Vec<String>`.

6. **Version string** (`v`): Use a `VersionString` newtype that validates the `KERI10JSON{hhhhhh}_` format on deserialization.

7. **Signatures**: If a signature field exists temporarily during migration, use a `Signature` newtype — never bare `String`. The end state is signatures externalized into CESR attachments (see Task 1.4).

8. **Seals** (`a`): Use an untagged `Seal` enum whose variants are distinguished by field shape (`Digest { d }`, `KeyEvent { i, s, d }`, etc.) — not a struct with a non-spec `"type"` string field.

**The test:** if you can assign a SAID to a key field, a threshold to a version string field, or a backer AID to a commitment field and it compiles — the types are wrong.

---

## Complete Spec Field Label Inventory

The spec defines **26 unique field labels** across all message types and seal formats. Our implementation only uses a subset. This table is the authoritative reference for the audit.

### Table 1: Key Event Fields (17 labels)

Source: [KERI field labels for data structures](https://trustoverip.github.io/kswg-keri-specification/#keri-field-labels-for-data-structures)

| Label | Title | In `auths-keri`? | Notes |
|-------|-------|-------------------|-------|
| `v` | Version String | YES | Incomplete format (missing size + terminator) |
| `t` | Message Type | YES | Correct |
| `d` | Digest (SAID) | YES | Correct |
| `i` | Identifier Prefix (AID) | YES | Correct |
| `s` | Sequence Number | YES | u64 instead of u128 |
| `p` | Prior SAID | YES | Correct |
| `kt` | Keys Signing Threshold | YES | Parsed as decimal, not hex |
| `k` | List of Signing Keys | YES | Correct |
| `nt` | Next Keys Signing Threshold | YES | Parsed as decimal, not hex |
| `n` | List of Next Key Digests | YES | Correct |
| `bt` | Backer Threshold | YES | Parsed as decimal, not hex |
| `b` | List of Backers | YES | Used on ROT (should be ICP-only; ROT uses `br`/`ba`) |
| `br` | List of Backers to Remove | **NO** | Missing from `RotEvent` |
| `ba` | List of Backers to Add | **NO** | Missing from `RotEvent` |
| `c` | List of Configuration Traits | **NO** | Missing from `IcpEvent` and `RotEvent` |
| `a` | List of Anchors (seals) | YES | Non-spec seal format (has `"type"` field) |
| `di` | Delegator Identifier Prefix | **NO** | Delegated events not implemented |

### Table 2: Routed Message Fields (7 additional labels)

These appear in `qry`, `rpy`, `pro`, `bar`, `xip`, `exn` messages — none of which are implemented in `auths-keri`.

| Label | Title | In `auths-keri`? |
|-------|-------|-------------------|
| `u` | UUID Salty Nonce | NO |
| `ri` | Receiver Identifier Prefix | NO |
| `x` | Exchange SAID | NO (see warning below) |
| `dt` | Datetime (ISO-8601) | NO |
| `r` | Route | NO |
| `rr` | Return Route | NO |
| `q` | Query Map | NO |

> **WARNING — The `x` field in our code is NOT the spec's `x`.**
> The spec defines `x` as "Exchange SAID — fully qualified unique digest for an exchange transaction" used in `exn` messages. Our implementation uses `x` as an inline signature field on all event types. The spec's `x` is a digest; our `x` is a base64url Ed25519 signature. These are completely different things. Our `x` field is non-spec and must be removed (see Task 1.4).

### Table 3: Seal Fields (2 additional labels)

| Label | Title | In `auths-keri`? |
|-------|-------|-------------------|
| `rd` | Merkle Tree Root Digest | NO |
| `bi` | Backer Identifier | NO |

### Message Body Field Orders (spec-normative)

| Message | Type | Required Fields (in order) |
|---------|------|----------------------------|
| Inception | `icp` | `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]` |
| Rotation | `rot` | `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]` |
| Interaction | `ixn` | `[v, t, d, i, s, p, a]` |
| Delegated Inception | `dip` | `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di]` |
| Delegated Rotation | `drt` | `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]` |
| Receipt | `rct` | `[v, t, d, i, s]` |
| Query | `qry` | `[v, t, d, dt, r, rr, q]` |
| Reply | `rpy` | `[v, t, d, dt, r, a]` |
| Prod | `pro` | `[v, t, d, dt, r, rr, q]` |
| Bare | `bar` | `[v, t, d, dt, r, a]` |
| Exchange Inception | `xip` | `[v, t, d, u, i, ri, dt, r, q, a]` |
| Exchange | `exn` | `[v, t, d, i, ri, x, p, dt, r, q, a]` |

"No other top-level fields are allowed (MUST NOT appear)" applies to every message type.

---

## Epic 1: Event Field Schema (Missing & Extra Fields)

The spec defines strict, required field sets for each event type. No other top-level fields are allowed. Our structs deviate in three ways: missing the `c` (configuration traits) field, using an `x` field for inline signatures (which the spec forbids), and using a full `b` list on ROT instead of `br`/`ba` deltas.

### Task 1.1: Add `c` (Configuration Traits) Field to ICP

**Spec (ICP field order):** `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]` — ALL required.

Configuration traits control identity behavior (establishment-only, do-not-delegate, etc.). The spec defines:
- `EO` — Establishment-Only: only establishment events in KEL
- `DND` — Do-Not-Delegate: cannot act as delegator
- `DID` — Delegate-Is-Delegator
- `RB` / `NRB` — Registrar backer control

**Current code** (`events.rs:168-196`):
```rust
pub struct IcpEvent {
    pub v: String,
    pub d: Said,
    pub i: Prefix,
    pub s: KeriSequence,
    pub kt: String,
    pub k: Vec<String>,
    pub nt: String,
    pub n: Vec<String>,
    pub bt: String,
    pub b: Vec<String>,
    // MISSING: pub c: Vec<String>,
    pub a: Vec<Seal>,
    pub x: String,       // NON-SPEC: should not exist (see Task 1.4)
}
```

**Fix:** Add `c: Vec<String>` field between `b` and `a`. Update the custom `Serialize` impl to always include it (the spec says all fields are required, even if the list is empty). Update `Deserialize` with `#[serde(default)]` for backwards compat during migration.

```rust
// events.rs — IcpEvent struct
/// Configuration traits/modes (e.g., "EO", "DND", "DID")
#[serde(default)]
pub c: Vec<String>,

// events.rs — IcpEvent Serialize impl, after "b" entry:
map.serialize_entry("c", &self.c)?;
```

Also add `c` to `RotEvent` (same position, between `b` and `a`). The IXN event does NOT have `c`.

**Validation impact:** `validate.rs` must enforce:
- `EO` trait: reject any IXN events in a KEL whose inception has `"EO"` in `c`
- `DND` trait: prevent delegation (not yet implemented, but the field must exist for future enforcement)
- `c` is inception-only for `EO`/`DND`/`DID`; `RB`/`NRB` can appear in rotation

### Task 1.2: Add `br` / `ba` Fields to ROT (Replace `b`)

**Spec (ROT field order):** `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]` — ALL required.

Rotation uses **delta-based** witness list changes: `br` (remove) and `ba` (add), processed in that order.

**Current code** (`events.rs:237-267`):
```rust
pub struct RotEvent {
    // ...
    pub bt: String,
    pub b: Vec<String>,   // NON-SPEC: full replacement list
    // MISSING: pub br: Vec<String>,
    // MISSING: pub ba: Vec<String>,
    pub a: Vec<Seal>,
    pub x: String,
}
```

**Fix:** Replace `b` with `br` and `ba`:
```rust
// events.rs — RotEvent struct
/// Backer/witness threshold
pub bt: String,
/// List of backers to remove (processed first)
#[serde(default)]
pub br: Vec<String>,
/// List of backers to add (processed after removals)
#[serde(default)]
pub ba: Vec<String>,
/// Configuration traits
#[serde(default)]
pub c: Vec<String>,
```

Update the custom `Serialize` impl field order:
```rust
// events.rs — RotEvent Serialize impl
map.serialize_entry("bt", &self.bt)?;
map.serialize_entry("br", &self.br)?;
map.serialize_entry("ba", &self.ba)?;
map.serialize_entry("c", &self.c)?;
// ...then "a" (conditionally)
```

**Blast radius:** Every call site that constructs `RotEvent` currently sets `b: vec![]` or `b: witnesses`. These must all be migrated to `br: vec![], ba: vec![]`. Search for `RotEvent {` across the workspace.

`KeyState` must track the full backer list and compute the new list as: `state.backers.remove_all(br).extend(ba)`.

### Task 1.3: Always Serialize `a` Field (Remove Conditional Omission)

**Spec:** All fields listed in the event schema are REQUIRED. The `a` field MUST be present even when empty.

**Current code** (`events.rs:219-221`):
```rust
// IcpEvent Serialize impl
if !self.a.is_empty() {
    map.serialize_entry("a", &self.a)?;
}
```

Same pattern in `RotEvent` (line 291) and `IxnEvent` (already always serializes `a`).

**Fix:** Remove the conditional. Always serialize `a`:
```rust
map.serialize_entry("a", &self.a)?;
```

Apply to all three event types. This also fixes the field count calculation (remove `!self.a.is_empty() as usize` from the dynamic count).

### Task 1.4: Externalize Signatures (Remove `x` Field)

**Spec:** "Signatures MUST be attached using CESR attachment codes" — they are NOT part of the event body. The spec's event field lists do not include `x` or any signature field.

**Current code** (`events.rs:194-195`, `events.rs:265-266`, `events.rs:324-325`):
```rust
/// Event signature (Ed25519, base64url-no-pad)
#[serde(default)]
pub x: String,
```

The `x` field is serialized conditionally in every event type. `serialize_for_signing` zeros it, and `compute_said` removes it. This is a workaround for storing signatures inline.

**Fix (phased):**

**Phase A (struct change):** Remove `x` from all event structs. Store signatures alongside events rather than inside them. Create a wrapper:
```rust
/// An event paired with its detached signature(s).
pub struct SignedEvent {
    pub event: Event,
    /// Controller-indexed signatures (base64url-no-pad Ed25519)
    pub signatures: Vec<String>,
}
```

**Phase B (serialization):** `serialize_for_signing` becomes trivial — serialize the event as-is (no field clearing needed). `compute_said` no longer needs to remove `x`.

**Phase C (storage migration):** All KEL storage must be updated to store `(event_json, signatures)` separately instead of `event_json_with_x`.

This is the largest single change in this audit. It touches every crate that creates, stores, or verifies events. Consider doing this as a separate epic after the field schema changes are stable.

---

## Epic 2: Version String Compliance

### Task 2.1: Use Full v1.x Version String with Size Field

**Spec (v1.x format):** `KERIvvSSSShhhhhh_` — 17 characters total.
- `KERI` — 4-char protocol ID
- `vv` — hex major.minor (e.g., `10` = v1.0)
- `SSSS` — serialization type (`JSON`, `CBOR`, `MGPK`, `CESR`)
- `hhhhhh` — 6 hex chars = total serialized byte count
- `_` — terminator

**Current code** (`events.rs:13`):
```rust
pub const KERI_VERSION: &str = "KERI10JSON";  // 10 chars — WRONG
```

This is only the first 10 characters of the v1.x version string. Missing: the 6-hex-char byte count and `_` terminator.

The `compute_version_string()` function in `version.rs` does compute the full 17-char string correctly, but it's behind the `cesr` feature flag and unused in the default event path.

**Fix:** Move `compute_version_string()` out from behind the `cesr` feature flag. Use it in `finalize_icp_event` and all event creation paths:
```rust
// said.rs or version.rs (no feature gate)
pub const KERI_VERSION_PREFIX: &str = "KERI10JSON";

/// Compute the full version string with byte count for a serialized event.
pub fn compute_version_string(event_bytes: &[u8]) -> String {
    format!("KERI10JSON{:06x}_", event_bytes.len())
}
```

Event finalization must do a two-pass serialize:
1. Serialize with placeholder version → measure size → compute version string
2. Re-serialize with correct version string

The `cesr`-gated `version.rs` already implements this two-pass pattern (lines 19-63). Promote it to the default path.

### Task 2.2: Receipt Version String

**Current code** (`witness/receipt.rs:28`):
```rust
pub const KERI_VERSION: &str = "KERI10JSON000000_";  // hardcoded zeros
```

The `000000` byte count is always wrong for actual receipts. The receipt version string should reflect the actual serialized size.

**Fix:** Compute the receipt version string dynamically during construction, same two-pass approach as events.

---

## Epic 3: Sequence Number Type

### Task 3.1: Widen KeriSequence to u128

**Spec:** "Maximum value MUST be `ffffffffffffffffffffffffffffffff`" — that is `2^128 - 1` (128-bit).

**Current code** (`events.rs:28`):
```rust
pub struct KeriSequence(u64);  // max = 2^64 - 1
```

**Fix:** Change inner type to `u128`:
```rust
pub struct KeriSequence(u128);
```

Update `value()` return type to `u128`. Update `KeyState.sequence` to `u128`. Update all comparison sites.

**Practical note:** No real KEL will exceed u64. This is a spec-correctness change, not a practical one. Low priority.

---

## Epic 4: Threshold Parsing

### Task 4.1: Parse Thresholds as Hex (Not Decimal)

**Spec:** Key signing threshold (`kt`, `nt`) and backer threshold (`bt`) are "hex-encoded non-negative integer[s]."

**Current code** (`validate.rs:135-140`):
```rust
fn parse_threshold(raw: &str) -> Result<u64, ValidationError> {
    raw.parse::<u64>()  // DECIMAL parse — WRONG for values >= 10
        .map_err(|_| ValidationError::MalformedSequence {
            raw: raw.to_string(),
        })
}
```

For thresholds 1-9, hex and decimal produce the same result. At threshold 10+: `"a"` (hex) = 10, but `"a".parse::<u64>()` fails. Spec example: `"kt":"2"` — same in both bases.

**Fix:**
```rust
fn parse_threshold(raw: &str) -> Result<u64, ValidationError> {
    u64::from_str_radix(raw, 16)
        .map_err(|_| ValidationError::MalformedSequence {
            raw: raw.to_string(),
        })
}
```

### Task 4.2: Support Fractionally Weighted Thresholds

**Spec:** Thresholds can also be a list of clause lists with rational fractions for complex multi-sig policies:
```json
"kt": [["1/2", "1/2", "1/2"], ["1/2", "1/2"]]
```
Clauses are ANDed. Each clause is satisfied when the sum of weights for verified signatures >= 1.

**Current code:** Only supports simple integer thresholds.

**Fix:** Define a threshold enum:
```rust
pub enum Threshold {
    /// Simple M-of-N threshold (hex-encoded integer)
    Simple(u64),
    /// Fractionally weighted threshold (list of clause lists)
    Weighted(Vec<Vec<String>>),
}
```

Parse the `kt`/`nt`/`bt` fields into this enum. Update signature verification to check threshold satisfaction accordingly.

**Priority:** Medium. Current auths usage is single-sig (`kt: "1"`). Multi-sig support requires this.

---

## Epic 5: Seal Format Compliance

### Task 5.1: Support Multiple Seal Types

**Spec defines these seal formats:**

| Seal Type | Fields | Field Order |
|-----------|--------|-------------|
| Digest Seal | `d` | `[d]` |
| Merkle Root Seal | `rd` | `[rd]` |
| Source Event Seal | `s`, `d` | `[s, d]` |
| Key Event Seal | `i`, `s`, `d` | `[i, s, d]` |
| Latest Est. Event Seal | `i` | `[i]` |
| Registrar Backer Seal | `bi`, `d` | `[bi, d]` |

**Current code** (`events.rs:113-119`):
```rust
pub struct Seal {
    /// Digest of anchored data
    pub d: Said,
    /// Type indicator (renamed to "type" in JSON)
    #[serde(rename = "type")]
    pub seal_type: SealType,
}
```

Problems:
1. Only supports digest seals (just `d` field)
2. Adds a non-spec `"type"` field to the JSON
3. No support for key event seals, source event seals, etc.

**Fix:** Replace with a seal enum:
```rust
/// KERI seal — typed by field shape, not a "type" discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Seal {
    /// Digest seal: {"d": "<SAID>"}
    Digest { d: Said },
    /// Source event seal: {"s": "<hex-sn>", "d": "<SAID>"}
    SourceEvent { s: KeriSequence, d: Said },
    /// Key event seal: {"i": "<AID>", "s": "<hex-sn>", "d": "<SAID>"}
    KeyEvent { i: Prefix, s: KeriSequence, d: Said },
    /// Latest establishment event seal: {"i": "<AID>"}
    LatestEstablishment { i: Prefix },
    /// Merkle tree root digest seal: {"rd": "<digest>"}
    MerkleRoot { rd: String },
}
```

**Note:** The current `SealType` enum (`DeviceAttestation`, `Revocation`, `Delegation`, `IdpBinding`) is an auths-specific extension. It should be modeled as data INSIDE a digest seal's referenced document, not as a field on the seal itself. The seal is just `{"d": "..."}` — the "type" meaning lives in the anchored data.

### Task 5.2: Enforce Seal Field Order

**Spec:** "Field order MUST be `[i, s, d]`" for key event seals, `[s, d]` for source event seals, etc.

The `Seal` enum variants should have custom `Serialize` impls that enforce field order, or rely on `preserve_order` + field declaration order in the struct.

---

## Epic 6: Signature Verification (Multi-Key Threshold)

### Task 6.1: Verify Threshold-Satisficing Signatures, Not Just First Key

**Spec:** "Signed by a threshold-satisficing subset of the current set of private keys."

**Current code** (`validate.rs:142-148`, `validate.rs:189-191`):
```rust
// validate_inception — only checks first key
verify_event_signature(
    &Event::Icp(icp.clone()),
    icp.k.first().ok_or(ValidationError::SignatureFailed { sequence: 0 })?,
)?;

// validate_rotation — only checks first new key
if !rot.k.is_empty() {
    verify_event_signature(event, &rot.k[0])?;
}
```

Only verifies ONE signature against the first key. For multi-sig (kt > 1), this is insufficient.

**Fix:** `verify_event_signature` must accept a list of signatures and a list of keys, then check that at least `kt` of them verify:
```rust
fn verify_threshold_signatures(
    event: &Event,
    keys: &[String],
    signatures: &[String],  // or extracted from SignedEvent
    threshold: u64,
) -> Result<(), ValidationError> {
    let canonical = serialize_for_signing(event)?;
    let mut verified_count = 0u64;
    for (key, sig) in keys.iter().zip(signatures.iter()) {
        if verify_single_signature(&canonical, key, sig).is_ok() {
            verified_count += 1;
        }
    }
    if verified_count < threshold {
        return Err(ValidationError::SignatureFailed { ... });
    }
    Ok(())
}
```

### Task 6.2: Rotation Dual-Threshold Requirement

**Spec:** "A set of controller-indexed signatures MUST satisfy BOTH the current signing threshold AND the prior next rotation threshold."

**Current code:** Only checks one threshold (implicit single-sig).

**Fix:** During rotation validation, verify that the provided signatures satisfy:
1. The current signing threshold (`state.threshold`)
2. The prior next rotation threshold (`state.next_threshold`)

This requires tracking which keys from the new key list correspond to the pre-committed next keys, then checking that enough of them verify.

### Task 6.3: Verify All Pre-Rotation Commitments (Not Just First)

**Spec:** "The current public key list MUST include a satisfiable subset of exposed (unblinded) pre-rotated next keys from the most recent prior establishment event."

**Current code** (`validate.rs:193-201`):
```rust
if !state.next_commitment.is_empty() && !rot.k.is_empty() {
    let key_bytes = KeriPublicKey::parse(&rot.k[0])  // ONLY first key
        .map(|k| k.as_bytes().to_vec())
        .map_err(|_| ValidationError::CommitmentMismatch { sequence })?;
    if !verify_commitment(&key_bytes, &state.next_commitment[0]) {  // ONLY first commitment
        return Err(ValidationError::CommitmentMismatch { sequence });
    }
}
```

Only checks `rot.k[0]` against `state.next_commitment[0]`. For multi-key identities, ALL exposed next keys must match their pre-committed digests.

**Fix:**
```rust
// For each commitment in state.next_commitment, at least next_threshold
// of the new keys must match (by finding their digest in the commitment list).
for (i, commitment) in state.next_commitment.iter().enumerate() {
    // Find the corresponding key in rot.k that matches this commitment
    let matched = rot.k.iter().any(|key| {
        KeriPublicKey::parse(key)
            .map(|k| verify_commitment(k.as_bytes(), commitment))
            .unwrap_or(false)
    });
    if !matched {
        return Err(ValidationError::CommitmentMismatch { sequence });
    }
}
```

---

## Epic 7: KEL Validation Gaps

### Task 7.1: Reject Events After Abandonment

**Spec:** "When the `n` field value in a Rotation is an empty list, the AID MUST be deemed abandoned and no more key events MUST be allowed."

**Current code:** `KeyState.is_abandoned` is tracked but never enforced during `validate_kel`:
```rust
// validate.rs:183-216 — validate_rotation
// No check for state.is_abandoned before processing
```

`verify_event_crypto` does check this (line 272), but `validate_kel` calls `validate_rotation` directly, not `verify_event_crypto`.

**Fix:** Add to `validate_kel` loop, before processing any event:
```rust
if state.is_abandoned {
    return Err(ValidationError::AbandonedIdentity { sequence: expected_seq });
}
```

Same for non-transferable identities (inception with empty `n`).

### Task 7.2: Reject IXN in Establishment-Only KELs

**Spec:** When `"EO"` is in the inception's `c` traits, only establishment events (ICP, ROT) may appear in the KEL.

**Current code:** No `c` field exists (see Task 1.1), so this validation is impossible.

**Fix:** After adding `c` field, check in `validate_kel`:
```rust
let establishment_only = if let Event::Icp(icp) = &events[0] {
    icp.c.contains(&"EO".to_string())
} else { false };

// In the event loop:
if establishment_only && matches!(event, Event::Ixn(_)) {
    return Err(ValidationError::EstablishmentOnly { sequence: expected_seq });
}
```

### Task 7.3: Enforce Non-Transferable Identity Rules

**Spec:** "When the `n` field value in an Inception is an empty list, the AID MUST be deemed non-transferable and no more key events MUST be allowed."

**Current code:** Not enforced. A KEL with inception `n: []` followed by rotation/interaction events would be accepted.

**Fix:** After creating initial state from inception:
```rust
if icp.n.is_empty() && events.len() > 1 {
    return Err(ValidationError::NonTransferable);
}
```

### Task 7.4: Track and Expose Witness/Backer State in KeyState

**Spec:** Key state includes backer list and threshold.

**Current code** (`state.rs:18-42`):
```rust
pub struct KeyState {
    pub prefix: Prefix,
    pub current_keys: Vec<String>,
    pub next_commitment: Vec<String>,
    pub sequence: u64,
    pub last_event_said: Said,
    pub is_abandoned: bool,
    pub threshold: u64,
    pub next_threshold: u64,
    // MISSING: backers, backer_threshold, config_traits
}
```

**Fix:** Add:
```rust
pub struct KeyState {
    // ... existing fields ...
    /// Current backer/witness list
    pub backers: Vec<String>,
    /// Current backer threshold
    pub backer_threshold: u64,
    /// Configuration traits from inception (and rotation for RB/NRB)
    pub config_traits: Vec<String>,
    /// Whether this identity is non-transferable (inception n was empty)
    pub is_non_transferable: bool,
}
```

Update `from_inception` and `apply_rotation` to maintain these fields. `apply_rotation` must apply `br`/`ba` deltas to the backer list.

---

## Epic 8: Receipt Message Compliance

### Task 8.1: Fix Receipt `d` Field Semantics

**Spec (receipt field order):** `[v, t, d, i, s]` — ALL required. No other fields.
- `d` is the SAID of the **referenced key event** (not the receipt itself)
- Signatures are on the referenced key event body, attached via CESR

**Current code** (`witness/receipt.rs:63-86`):
```rust
pub struct Receipt {
    pub v: String,
    pub t: String,
    pub d: Said,            // receipt's own SAID — WRONG per spec
    pub i: String,
    pub s: u64,
    pub a: Said,            // NON-SPEC: event SAID being receipted
    #[serde(with = "hex")]
    pub sig: Vec<u8>,       // NON-SPEC: should be CESR attachment
}
```

Problems:
1. `d` should be the referenced event's SAID, not the receipt's own SAID
2. `a` field does not exist in the spec receipt format
3. `sig` should be a CESR attachment, not a body field
4. `s` is `u64` but spec uses hex-encoded string (should be `KeriSequence`)

**Fix:**
```rust
pub struct Receipt {
    pub v: String,
    pub t: String,          // "rct"
    pub d: Said,            // SAID of the referenced event (NOT the receipt)
    pub i: String,          // Witness AID
    pub s: KeriSequence,    // Event sequence number (hex-encoded)
}

pub struct SignedReceipt {
    pub receipt: Receipt,
    /// Witness signature (CESR-attached, not in body)
    pub signature: Vec<u8>,
}
```

---

## Epic 9: SAID Algorithm Refinements

### Task 9.1: Integrate Version String Size into SAID Computation

**Spec:** The `v` field includes the serialized byte count. SAID computation must use the correct `v` value.

**Current SAID algorithm** (`said.rs:22-71`):
1. Replace `d` with placeholder
2. For ICP: replace `i` with placeholder
3. Remove `x`
4. `serde_json::to_vec` (insertion-order)
5. Blake3 hash
6. `E` + base64url-no-pad

**Missing step:** The `v` field in the serialized event must have the correct byte count. Currently the SAID is computed with whatever `v` value the event already has (typically `"KERI10JSON"` — the truncated version). The spec requires `v` to reflect the total serialized byte count.

**Fix:** In `compute_said`, after injecting placeholders:
1. Serialize once to measure byte count
2. Compute version string: `format!("KERI10JSON{:06x}_", byte_count)`
3. Set `v` to the computed version string
4. Re-serialize with correct `v`
5. Hash the final serialization

This mirrors the two-pass approach in `version.rs:19-63` (currently cesr-gated).

### Task 9.2: Validate SAID Placeholder Length Matches Derivation Code

**Spec:** The placeholder is `#` characters of the length of the **digest to be used**. For Blake3-256 with CESR `E` code: `E` + 43 base64url chars = 44 chars.

**Current code** (`said.rs:8`):
```rust
pub const SAID_PLACEHOLDER: &str = "############################################";  // 44 chars
```

This is correct for Blake3-256. However, if other digest algorithms are supported in the future, the placeholder length must match. Consider deriving from the derivation code:
```rust
/// Placeholder length for a given derivation code.
pub fn placeholder_length(derivation_code: &str) -> usize {
    match derivation_code {
        "E" => 44,  // Blake3-256: 1 code char + 43 base64url chars
        _ => 44,    // Default, extend as needed
    }
}
```

Low priority — currently only Blake3-256 is used.

---

## Epic 10: Key and Prefix Type Flexibility

### Task 10.1: Support Non-Self-Addressing AIDs (Prefix Validation)

**Spec:** AIDs can be:
- **Self-addressing:** derived from inception event SAID (starts with `E` for Blake3-256)
- **Non-self-addressing:** derived from public key (starts with `D` for Ed25519, `1` for secp256k1, etc.)

**Current code** (`types.rs:21-37`):
```rust
fn validate_keri_derivation_code(s: &str, type_label: &'static str) -> Result<(), KeriTypeError> {
    // ...
    if !s.starts_with('E') {
        return Err(KeriTypeError { /* ... */ });
    }
    Ok(())
}
```

Only accepts `E` prefix. Non-self-addressing AIDs (e.g., `D`-prefixed Ed25519 keys used as non-transferable prefixes) are rejected.

**Fix:** Accept any valid CESR derivation code:
```rust
fn validate_keri_derivation_code(s: &str, type_label: &'static str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError { type_name: type_label, reason: "must not be empty".into() });
    }
    // CESR derivation codes: D (Ed25519), E (Blake3-256), 1 (secp256k1), etc.
    // For now, allow any non-empty string starting with an uppercase letter or digit.
    let first = s.chars().next().unwrap_or('\0');
    if !first.is_ascii_alphanumeric() {
        return Err(KeriTypeError {
            type_name: type_label,
            reason: format!("must start with a CESR derivation code, got '{}'", first),
        });
    }
    Ok(())
}
```

**Note:** `Said` should remain `E`-only (SAIDs are always digests). Split validation:
- `Prefix`: any CESR derivation code
- `Said`: `E` only (or other digest codes)

### Task 10.2: ICP Self-Addressing Rule — `i == d` Only When Self-Addressing

**Spec:** "When the AID is self-addressing, `d` and `i` MUST have the same value." But non-self-addressing AIDs have `i` derived from the public key, not from `d`.

**Current code** (`validate.rs:259-264`):
```rust
if icp.i.as_str() != icp.d.as_str() {
    return Err(ValidationError::InvalidSaid { ... });
}
```

Always enforces `i == d`. This is correct for self-addressing AIDs only.

**Fix:** Check the derivation code of `i` to determine if it's self-addressing:
```rust
let is_self_addressing = icp.i.as_str().starts_with('E');
if is_self_addressing && icp.i.as_str() != icp.d.as_str() {
    return Err(ValidationError::InvalidSaid { ... });
}
```

---

## Epic 11: Witness Validation

### Task 11.1: Validate Witness AID Uniqueness

**Spec:** "A given AID MUST NOT appear more than once in any Backer list."

**Current code:** No uniqueness check anywhere.

**Fix:** In inception and rotation validation:
```rust
fn validate_backer_uniqueness(backers: &[String]) -> Result<(), ValidationError> {
    let mut seen = std::collections::HashSet::new();
    for b in backers {
        if !seen.insert(b) {
            return Err(ValidationError::DuplicateBacker { aid: b.clone() });
        }
    }
    Ok(())
}
```

### Task 11.2: Validate `bt` Consistency with Backer List

**Spec:** "When `b` is empty, `bt` MUST be `"0"`."

**Fix:** In inception validation:
```rust
let bt = parse_threshold(&icp.bt)?;
if icp.b.is_empty() && bt != 0 {
    return Err(ValidationError::InvalidBackerThreshold { bt, backer_count: 0 });
}
```

### Task 11.3: Validate `br` Before `ba` Processing Order

**Spec:** "AIDs in `br` MUST be removed before any AIDs in `ba` are appended."

After Task 1.2 adds `br`/`ba`, validate that:
1. All AIDs in `br` exist in the current backer list
2. No AID appears in both `br` and `ba`
3. No duplicate AIDs in `br` or `ba`

---

## Epic 12: Delegated Events (Not Yet Implemented)

### Task 12.1: Add `dip` (Delegated Inception) Event Type

**Spec field order:** `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di]`

Same as ICP plus `di` (delegator identifier prefix).

### Task 12.2: Add `drt` (Delegated Rotation) Event Type

**Spec field order:** `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]`

Same fields as ROT but `t = "drt"`. Validation requires checking the delegator's KEL for an anchoring seal.

### Task 12.3: Implement Delegated Event Validation

**Spec:** "A Validator MUST be given or find the delegating seal in the delegator's KEL before the delegated event may be accepted as valid."

This requires cross-KEL validation (delegatee's event references delegator's KEL).

**Priority:** Low. Delegation is not used in the current auths identity model.

---

## Epic 13: Eliminate Stringly-Typed Fields ("Parse, Don't Validate")

The crate has strong newtypes for `Said`, `Prefix`, `KeriSequence`, and `KeriPublicKey`, but most event struct fields bypass them and store raw `String`s. The result: parsing happens deep in validation functions rather than at the deserialization boundary, invalid data can propagate silently, and callers must remember which strings are keys vs commitments vs thresholds.

### Task 13.1: Type the Threshold Fields (`kt`, `nt`, `bt`)

**Current:** `kt: String`, `nt: String`, `bt: String` on all event types. Parsed ad-hoc in `validate.rs:135-140` as decimal (should be hex), and discarded after use.

```rust
// validate.rs:135 — ad-hoc parse, wrong base, result thrown away
fn parse_threshold(raw: &str) -> Result<u64, ValidationError> {
    raw.parse::<u64>()  // decimal, not hex
}
```

**Fix:** Define a `Threshold` enum and use it on the structs:
```rust
/// KERI signing/backer threshold.
///
/// Simple thresholds are hex-encoded integers ("1", "2", "a").
/// Weighted thresholds are clause lists ([["1/2","1/2"],["1/3","1/3","1/3"]]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Threshold {
    Simple(u64),
    Weighted(Vec<Vec<String>>),  // future: Vec<Vec<Fraction>>
}
```

With a custom `Deserialize` that parses hex for simple values and accepts arrays for weighted. Then on the structs:
```rust
pub struct IcpEvent {
    pub kt: Threshold,
    pub nt: Threshold,
    pub bt: Threshold,
    // ...
}
```

Invalid thresholds are rejected at deserialization, not during validation.

### Task 13.2: Type the Key Fields (`k`, `current_keys`)

**Current:** `k: Vec<String>` on events and `current_keys: Vec<String>` on `KeyState`. `KeriPublicKey` exists as a validated type but is only used transiently in `validate_rotation` and `verify_event_signature`, then discarded.

```rust
// events.rs:181 — raw strings
pub k: Vec<String>,

// validate.rs:194 — parsed on the fly, thrown away
let key_bytes = KeriPublicKey::parse(&rot.k[0])
    .map(|k| k.as_bytes().to_vec())
```

**Fix:** Use a CESR-qualified key newtype on the struct:
```rust
/// A CESR-encoded public key (e.g., 'D' + base64url Ed25519).
/// Validated at deserialization time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CesrKey(String);

impl CesrKey {
    pub fn parse_ed25519(&self) -> Result<KeriPublicKey, KeriDecodeError> {
        KeriPublicKey::parse(&self.0)
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

// On the struct:
pub k: Vec<CesrKey>,
```

Then `KeriPublicKey::parse` is called once per key during deserialization or on first access, not scattered across validation sites.

Also update `KeyState.current_keys: Vec<CesrKey>`.

### Task 13.3: Type the Commitment Fields (`n`, `next_commitment`)

**Current:** `n: Vec<String>` on events, `next_commitment: Vec<String>` on `KeyState`. These are always `E`-prefixed Blake3-256 digests, identical in format to `Said`, but stored as bare strings.

`compute_next_commitment` returns `String`:
```rust
// crypto.rs:29 — returns untyped string
pub fn compute_next_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes()))
}
```

**Fix:** Return `Said` (or a new `KeyCommitment` newtype if semantic distinction matters):
```rust
pub fn compute_next_commitment(public_key: &[u8]) -> Said {
    let hash = blake3::hash(public_key);
    Said::new_unchecked(format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}

// On the structs:
pub n: Vec<Said>,
```

Update `KeyState.next_commitment: Vec<Said>`.

### Task 13.4: Type the Backer Fields (`b`, `br`, `ba`)

**Current:** `b: Vec<String>`.

Witness AIDs are fully qualified CESR primitives per the spec. For non-transferable witnesses (which the spec requires), these are public-key-derived AIDs (e.g., `D`-prefixed).

**Fix:** After Task 10.1 relaxes `Prefix` to accept non-`E` derivation codes:
```rust
pub b: Vec<Prefix>,
// and after Task 1.2:
pub br: Vec<Prefix>,
pub ba: Vec<Prefix>,
```

### Task 13.5: Type the Version String (`v`)

**Current:** `v: String` on all events. No validation of the `KERI10JSON{size}_` format.

```rust
// events.rs:170 — raw string, no format enforcement
pub v: String,
```

**Fix:** Define a `VersionString` newtype:
```rust
/// KERI v1.x version string: "KERI10JSON{hhhhhh}_" (17 chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionString {
    pub protocol: String,      // "KERI"
    pub version: (u8, u8),     // (major, minor)
    pub serialization: String, // "JSON"
    pub size: u32,             // serialized byte count
}

impl VersionString {
    pub fn as_str(&self) -> String {
        format!("KERI{}{}{}{:06x}_",
            self.version.0, self.version.1,
            self.serialization, self.size)
    }
}
```

With serde that validates on deserialization.

### Task 13.6: Type the Receipt Fields

**Current:** `Receipt.i: String`, `Receipt.s: u64`.

**Fix:**
```rust
pub struct Receipt {
    pub v: VersionString,
    pub t: String,         // or MessageType enum
    pub d: Said,
    pub i: Prefix,         // was String
    pub s: KeriSequence,   // was u64
}
```

### Task 13.7: Type the Configuration Traits (`c`)

After Task 1.1 adds the `c` field, don't use `Vec<String>` — use an enum:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigTrait {
    #[serde(rename = "EO")]
    EstablishmentOnly,
    #[serde(rename = "DND")]
    DoNotDelegate,
    #[serde(rename = "DID")]
    DelegateIsDelegator,
    #[serde(rename = "RB")]
    RegistrarBackers,
    #[serde(rename = "NRB")]
    NoRegistrarBackers,
}

// On the struct:
pub c: Vec<ConfigTrait>,
```

This makes `icp.c.contains(&ConfigTrait::EstablishmentOnly)` type-safe instead of `icp.c.contains(&"EO".to_string())`.

---

## Priority Matrix

| Epic | Priority | Reason |
|------|----------|--------|
| 1 (Event Fields) | **HIGH** | Field schema is the foundation; all downstream work depends on it |
| 2 (Version String) | **HIGH** | Affects SAID computation, interop, and all serialized events |
| 5 (Seal Format) | **HIGH** | Current seal format is non-interoperable |
| 4 (Threshold Parsing) | **MEDIUM** | Only affects multi-key identities (kt >= 10 hex = 16 decimal) |
| 6 (Multi-Sig Verification) | **MEDIUM** | Single-sig works today; needed for multi-device |
| 7 (Validation Gaps) | **MEDIUM** | Partial gaps in edge cases; core happy path works |
| 8 (Receipt Format) | **MEDIUM** | Receipts work for internal use; interop requires fix |
| 9 (SAID Refinements) | **MEDIUM** | Current SAID works; version string integration is correctness |
| 10 (Prefix Types) | **LOW** | Only self-addressing AIDs are used currently |
| 11 (Witness Validation) | **LOW** | No witnesses in production yet |
| 3 (Sequence u128) | **LOW** | u64 is practically sufficient |
| 12 (Delegation) | **LOW** | Not in current identity model |
| 13 (Strong Typing) | **HIGH** | Parse-at-boundary prevents entire classes of bugs; do alongside Epic 1 |

---

## Recommended Execution Order

1. **Epic 1** (event fields) + **Epic 13** (strong typing) — do together; when adding `c`/`br`/`ba`, type them correctly from the start rather than adding more `String` fields
2. **Epic 2** (version string) + **Epic 9** (SAID) — together, since SAID depends on version string
3. **Epic 5** (seals) — can proceed in parallel with Epic 2
4. **Epic 4** (thresholds) — subsumed by Epic 13 Task 13.1 if done together
5. **Epic 7** (validation gaps) — requires Epic 1 for `c` field enforcement
6. **Epic 6** (multi-sig) — requires typed thresholds from Epic 13
7. **Epic 8** (receipts) — depends on signature externalization from Epic 1 Task 1.4
8. **Epics 10, 11, 3, 12** — in any order, as capacity allows
