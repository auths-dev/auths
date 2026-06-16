# Outcome: verified-continuation-rotation (MSG-2)

> One cycle, finished and proven. MSG-2 RED → GREEN → closed; federated gate green.

## What changed

The headline win is now real: a contact's pre-committed key rotation verifies as a
*continuation of the same identity*, with the §2 binding mechanism wired — not a
prose claim (PRD §2, §10, the verified-continuation claim).

- **`crates/murmur-core/src/rotation.rs`** (new) — the engine half of verified
  key continuity.
  - `KeyState` carries the **stable AID** (the inception SAID, which outlives the
    signing key across a rotation), the current key the AID resolves to in that
    state, and the **pre-rotation commitment** to the next key.
  - `compute_next_commitment(next_key)` is the one-way SHA-256 commitment the prior
    state records (domain-separated), the same binding KERI's `n` field gives.
  - `verify_continuation(prior, current)` runs the commitment check: the freshly
    revealed current key must hash to the prior state's `next_commitment` and the
    AID must be preserved → `VerifiedContinuation`; a key the prior state never
    pre-committed to → `NonContinuationWarning`, **never** a soft re-pin.
  - `verified_rotation_rekey(...)` drives the whole beat and the binding mechanism:
    on a verified continuation it (a) **re-keys** the Signal session by re-running
    X3DH against the freshly-replayed key-state and asserts the re-keyed root
    **differs** from the prior session's — the old ratchet is never continued
    across the change; (b) **re-verifies** the republished prekey bundle against
    the new current key, and proves a **stale-signer** bundle (signed by the
    superseded key) is rejected; (c) proves the **substituted-key twin** is warned,
    not re-pinned. Any failure returns an error — never a silent pass.
- **`crates/murmur-core/src/trust.rs`** — `evaluate()` no longer fails closed
  `NotBuilt`. It decodes two `KeyState` snapshots (the shape a KEL replay yields)
  and returns the `verify_continuation` verdict, so the three `TrustState`s are
  produced by a real commitment check rather than modelled-but-never-produced.
- **`crates/murmur-relay/src/main.rs`** — an eighth `serve` self-test leg
  (`run_continuation`) drives the beat and prints the markers the probe greps for:
  `verified-continuation` + `session-rekeyed` + `prekey-reverified`. It fails the
  serve closed if the substituted twin is re-pinned, the session is not re-keyed,
  or a stale-signer prekey is accepted.

No loop vocabulary in product code — the claim is referenced by name
("the verified-continuation claim"), never by gap id; `leakcheck` clean over both
trees (an initial draft referenced `MSG-2` in doc comments and was caught by the
gate, then rewritten to the claim name).

## What the gate said

- `recurve --config .recurve/murmur.toml probe --gap MSG-2` — **GREEN**
  ("a pre-committed rotation verified as a continuation of the same identity; the
  Signal session was re-keyed … and the republished prekey was re-verified against
  the fresh current key; a substituted key was warned, not re-pinned").
- Trap discriminates: `TRAP_FIXTURE=probes/msg-2.trap/substituted-key` turns the
  probe **RED** (exit 1) — a not-pre-committed key verifying as a continuation, the
  ratchet continued across an identity change, or a stale-signer prekey accepted is
  caught.
- `cargo test -p murmur-core -p murmur-relay` — 68 passed, 0 failed.
- `cargo clippy --release -p murmur-core -p murmur-relay` — clean.
- `recurve --config .recurve/murmur.toml matrix --gate` — **GATE OK**:
  holding 16 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0;
  traps 9/9 still RED; `sculpt murmur: gate OK (exit 0)`; `leakcheck: clean`.
- `recurve --config .recurve/murmur.toml coverage --gate` — clean (no prose drift;
  the murmur suite carries no GAPS.md, the ledger is canonical).

## Ledger delta

MSG-2: `open → closed`. `observed` rewritten to the GREEN reality; `evidence`
rewritten to the feature note (rotation.rs / trust.rs / relay self-test). Trap count
8/8 → 9/9 (the MSG-2 substituted-key counterexample is now an active guard).
