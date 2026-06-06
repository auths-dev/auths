# Auths KERI Substrate — Conformance Specification

This document is the **normative wire-format and validation specification** for the
KERI substrate implemented in `crates/auths-keri`. It exists so that the findings
closed during launch hardening cannot silently regress: every emitted field set,
derivation code, and validation rule below is either enforced by code today or
explicitly marked **PENDING** with the task that will land it.

The companion conformance test is
`crates/auths-keri/tests/cases/interop_vectors.rs`. The cross-implementation CI gate
(KERIox round-trip) is Epic H.3; this document and that test seed it.

Status legend:

- **ENFORCED** — implemented and covered by tests in `auths-keri`.
- **PENDING(<id>)** — resolved by design, not yet implemented; tracked by the named task.
- **DEVIATION** — a deliberate, documented departure from stock KERI v1.1.

---

## 1. Event model

Auths uses KERI v1.1 JSON events. Five establishment/interaction event types are
emitted: `icp`, `rot`, `ixn`, `dip`, `drt`. Events are serialized as an **ordered
JSON map**; field order is normative because the version string `v` encodes the exact
serialized byte count and the SAID `d` is computed over the canonical serialization.

### 1.1 Emitted field sets (ENFORCED)

The deserializer rejects any event whose field set differs from the one below for its
`t` (strict field-set validation — no unknown fields, no missing required fields).

| `t`   | Ordered fields |
|-------|----------------|
| `icp` | `v, t, d, i, s, kt, k, nt, n, bt, b, c, a` |
| `rot` | `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a` |
| `ixn` | `v, t, d, i, s, p, a` |
| `dip` | `v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di` |
| `drt` | `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a, di` |

The event type tag `t` is injected immediately after `v` and is a constant per type;
it is **not** a free-form field. A parsed event whose `t` does not match the structural
field set is rejected.

### 1.2 No in-body timestamp (DEVIATION / ENFORCED — A.1)

KEL **events** (`icp`/`rot`/`ixn`/`dip`/`drt`) carry **no `dt` field**. Wall-clock
time is not part of an establishment event's signed body; it is neither hashed into the
SAID nor signed. Timestamps that legitimately travel on the wire (e.g. receipt and
witness *messages*) are out of scope for the event body and are unaffected.

Rationale: an in-body `dt` is an unauthenticated, non-deterministic input that two honest
controllers cannot agree on, and it widens the signed surface for no security benefit.

### 1.3 Signing domain (ENFORCED — A.2)

The bytes signed for an event are the **finalized canonical serialization** of that
event — i.e. the event after its `v` size and `d` SAID have been computed and written
back. The signer never signs a placeholder/default-SAID form. This closes the forge path
where a signature computed over a `d: ""` skeleton could be replayed against a finalized
event.

---

## 2. Field encodings

| Field | Type | Encoding |
|-------|------|----------|
| `v` | version string | `KERI10JSON{size:06x}_` (17 chars); `size` = total serialized byte count. Legacy/short version strings are **rejected** (A.11). |
| `t` | event type | constant string: `icp`/`rot`/`ixn`/`dip`/`drt`. |
| `d` | SAID | `E` + base64url(Blake3-256(canonical event)). |
| `i` | prefix (AID) | CESR-qualified controller identifier. |
| `s` | sequence | lowercase hex string, no `0x` (e.g. `"0"`, `"a"`). Legacy decimal/short forms rejected (A.11). |
| `p` | prior SAID | SAID of the immediately preceding event. |
| `kt`,`nt`,`bt` | threshold | hex integer **or** fractional-weight list (see §4). |
| `k` | current keys | list of CESR-qualified verkeys (§3). |
| `n` | next commitments | list of pre-rotation digests (§3.2). |
| `b` | backers | ordered list of backer AIDs (icp/dip). |
| `br`,`ba` | backer cuts / adds | rotation backer deltas (rot/drt). |
| `c` | config traits | list of `EO`/`DND`/`RB`/`NRB` (§5). |
| `a` | anchors | list of seals (§6). |
| `di` | delegator AID | present only on `dip`/`drt`. |

---

## 3. Cryptographic keys and signatures

### 3.1 Verkey derivation codes (ENFORCED — A.6)

Every public key on the wire carries its curve and transferability **in-band** via its
CESR derivation code. Length-based curve dispatch is forbidden.

| Curve | Transferable | Non-transferable |
|-------|--------------|------------------|
| Ed25519 | `D…` (qb64, 44 chars / 32 key bytes) | `B…` (qb64, 44 chars) |
| P-256 (secp256r1) | `1AAJ…` (qb64, 48 chars / 33-byte compressed SEC1) | `1AAI…` (qb64, 48 chars) |

`1AAJ` = `ECDSA_256r1` (transferable), `1AAI` = `ECDSA_256r1N` (non-transferable), per the
CESR master code table as implemented by `cesride` and `keripy` `MatterCodex`.

Verkeys are encoded as full CESR **`qb64`** via `cesride` — **byte-identical to `keripy`'s
`Verfer.qb64`** — not a naive `code + base64url(raw)` concatenation. CESR's lead-byte
alignment shifts the payload, so e.g. `Verfer(bytes(0..32), Ed25519).qb64` is
`DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f`, which differs from a naive `"D" +
base64url(bytes)`. Encoding and decoding route exclusively through
`KeriPublicKey::{to_qb64, parse}` (both cesride-backed).

The transferability recorded from the code is load-bearing: it determines whether the
identifier may rotate (§7) and feeds the basic-derivation check (§3.3).

### 3.2 Pre-rotation commitments

A next-key commitment in `n[]` is the CESR-qualified Blake3-256 digest (`E…` qb64) of the
**CESR-qualified `qb64` form** of the next verkey — i.e. `Diger(ser=Verfer.qb64b)`,
**byte-identical to `keripy`** (ENFORCED — A.7). The commitment binds the curve and
transferability, not just the raw key bytes. `compute_next_commitment` takes a typed
`KeriPublicKey`, so the curve required to produce the qualified form always travels with
the key and length-based dispatch is impossible.

### 3.3 Basic-derivation binding (ENFORCED — A.9)

For a single-key inception, the controller prefix `i` must equal the qualified form of the
sole current key `k[0]` (the basic/self-certifying derivation). An inception whose `i`
does not match `k[0]` is rejected.

### 3.4 Indexed signatures (PENDING — Epic B)

Signatures attach as CESR indexed signatures. Dual-index emission (current-list index +
prior-list index, required to verify a rotation that *removes* a key) and the
code-directed attachment parser are **PENDING(B.1–B.4)**. Until then, asymmetric
key-count rotations (prior next-count ≠ new key-count) are rejected rather than verified
with an ambiguous single index.

---

## 4. Thresholds (ENFORCED — A.4)

`kt`/`nt`/`bt` are either a hex integer (`m`-of-`n`) or a fractional-weight list.

- A threshold is validated for **satisfiability** against its list length at ingest: a
  weighted `nt` can no longer be silently collapsed to `1`-of-`n` (closes F-15).
- Empty backer set requires `bt == 0`.
- Pre-rotation satisfaction is evaluated over the **typed** prior `nt`: each revealed
  next-key index counts toward the threshold, and the typed predicate decides — not a
  `simple_value().unwrap_or(1)` collapse.

---

## 5. Configuration traits (`c[]`)

| Code | Meaning | Status |
|------|---------|--------|
| `EO`  | Establishment-Only — KEL may contain only establishment events; `ixn` prohibited. | ENFORCED |
| `DND` | Do-Not-Delegate — identifier may not act as a delegator. | ENFORCED (rejected in `validate_delegation`). |
| `RB`  | Registrar Backers — `b[]` names registrar-backer AIDs. | role-flip ENFORCED (A.13) |
| `NRB` | No Registrar Backers — backers are witnesses. | role-flip ENFORCED (A.13) |

### 5.1 Registrar-backer role flips (ENFORCED — A.13)

`RB` and `NRB` carry different backer-list semantics. A rotation whose `c[]` flips the
role (`RB`↔`NRB`) while any prior backer survives is **rejected** — a role flip MUST
rebuild `b[]` (cut every prior backer via `br`). An empty `c[]` inherits the role and
cannot flip.

The non-standard `Delegate-Is-Delegator` (`DID`) trait was **removed** (A.13): a config trait
that waives the delegation seal is a delegation-authorization bypass, and it was never consumed
by `validate_delegation` (which fail-closes on the anchoring seal regardless). Full
registrar-backer `bt` accounting is deferred to a tracked issue (Epic H.5).

---

## 6. Seals (`a[]`) (ENFORCED — A.8)

The canonical anchor seal is an **event-location seal** with fields `{i, s, p, t, d}`
(`SealEvent`). Delegated-event validation searches the delegator's KEL for a
location/digest seal matching the delegated event's `i`/`s`/`d`.

Extended seal shapes (`MerkleRoot`, `RegistrarBacker`) are gated behind the
`seal-extensions` Cargo feature and are **not** part of the default wire surface. The
default deserializer rejects unknown seal shapes.

---

## 7. Transferability and abandonment (ENFORCED — A.12)

- A non-transferable inception (empty `n[]`, non-transferable verkey code) is
  **non-transferable**, *not* abandoned. It simply cannot rotate or emit `ixn`.
- **Abandonment** is a post-inception state reached only by a rotation to an empty next
  commitment. `is_abandoned` is `false` at inception regardless of transferability.

This distinction matters: a verifier must treat "this identity was born non-rotating" and
"this identity rotated itself into the ground" differently.

---

## 8. Witness receipts (`rct`) (ENFORCED — D.4)

A receipt body is `{v, t, d, i, s}` where:

- `t` is the constant `"rct"` (a typed tag — a receipt can never carry a forged `t` such
  as `"icp"`; non-`rct` values fail to parse).
- `d` is the SAID of the **referenced key event**, not the receipt's own SAID.
- Signatures are **externalized** (not in the body); a `SignedReceipt` pairs the body with
  its detached witness signature.

---

## 9. Closed-finding summary

| Finding | Rule | Status |
|---------|------|--------|
| A.1 | No in-body `dt` on KEL events | ENFORCED |
| A.2 | Sign finalized canonical bytes | ENFORCED |
| A.4 / F-15 | Threshold satisfiability; no weighted→1-of-N collapse | ENFORCED |
| A.6 | P-256 `1AAJ`/`1AAI`, Ed25519 `D`/`B`; no length dispatch | ENFORCED |
| A.7 / C-05 | Commitment over CESR-qualified `qb64` | ENFORCED |
| A.8 | Event-location seal `{i,s,p,t,d}`; extensions feature-gated | ENFORCED |
| A.9 | Basic-derivation `i == k[0]` for single-key inception | ENFORCED |
| A.10 / F-05 | Rotation backer-delta validation (`br`⊆prior, `ba`∩survivors=∅) | ENFORCED |
| A.11 | Reject legacy/short version & sequence strings | ENFORCED |
| A.12 | Non-transferable ≠ abandoned | ENFORCED |
| A.13 / F-23 | Reject silent `RB`↔`NRB` role flips | ENFORCED |
| A.13 | Remove non-standard `DID` (delegate-is-delegator) trait | ENFORCED |
| B.1–B.4 | Dual-index CESR signatures | **PENDING(Epic B)** |
| D.4 / F-27 | Typed receipt `t = "rct"` | ENFORCED |

---

## 10. Conformance vectors

`crates/auths-keri/tests/cases/interop_vectors.rs` asserts **round-trip stability**: for a
representative event of each type, `parse(serialize(e))` reproduces the event and the
emitted field set matches §1.1. These are Auths-authored golden vectors; the
cross-implementation KERIox `.cesr` vectors that pin byte-level agreement with a second
implementation are added by Epic **H.3**, which consumes this specification as its
oracle.

Any change to §1 (field sets/order), §3 (codes/commitment domain), §6 (seal shape), or §8
(receipt shape) is a wire-format change and MUST update this document, the round-trip
vectors, and — once it exists — the H.3 KERIox gate in the same change.
