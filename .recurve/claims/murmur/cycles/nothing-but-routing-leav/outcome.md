# Outcome — nothing-but-routing-leav (ENC-4)

## Gap closed

**ENC-4 — Nothing but routing leaves the device in the clear: no plaintext, key,
ratchet state, or sender AID in the relay-visible bytes.** RED → GREEN, promoted
`open → closed`.

## What changed (the real feature, not a probe hack)

Built a **metadata-hygiene leakcheck** in `murmur-core` and drove it through the
real `murmur-relay` binary. The two-layer envelope was already *modelled* to carry
routing only (the relay touches just the `OuterEnvelope` — a mailbox id + opaque
ciphertext); this cycle makes that a *proven, runtime-asserted* property over the
actual bytes the relay forwards, rather than a fact you trust from reading the
struct.

- **`leakcheck.rs` (new)** — the relay-capture + scan:
  - `relay_visible_bytes(&OuterEnvelope)` returns the **raw** wire form the relay
    holds — the mailbox-id bytes it routes on, concatenated with the opaque
    ciphertext bytes. Deliberately *not* a JSON/length-prefixed re-encoding: a
    re-encoding would hide a leaked byte run behind its own escaping, so the scan
    would lie. (This was the bug the first pass had — `serde_json` renders a
    `Vec<u8>` as a number array, so raw AID/key byte runs never appeared; the fix
    scans the literal bytes an attacker captures.)
  - `prove_routing_only(...)` runs a leakcheck-style scan over those bytes for
    four sensitive values — the message body, the sender address, the session
    content key, and the forward-secret chain state — and returns a
    `RoutingOnlyReport` only if **every** one is absent as a contiguous run; any
    hit returns `CoreError::Rejected` naming what leaked, so a caller fails closed.
    The mailbox id is expected to be present (it is the routing handle) and is
    never treated as a leak.
- **`lib.rs`** — `deliver_routing_only` + `RoutingHygieneReceipt`: seal a real
  message on **both** of the engine's send paths (`Endpoint::seal_to` and a
  `Ratchet` sending chain) → store-and-forward each → **capture the outer envelope
  off the `MailboxStore` after it was forwarded** (so what is scanned is literally
  what the relay held) → prove routing-only over each, the fixed-session capture
  scanned against the session secret and the ratchet capture against the *live*
  chain state. Either path leaking fails the whole call closed.
- **`ratchet.rs`** — `chain_state()` (crate-internal) so the in-crate leakcheck
  can scan for the live chain key to prove its *absence*; the chain key never
  crosses the public API or the FFI.
- **`murmur-relay` `serve`** — now drives a fourth leg (`run_routing_only`) and
  prints `routing-only-envelope` (a captured envelope held only `mbx:phone`; the
  body, the sender address, the session key, and the chain state were each scanned
  for and found absent). A leak in either path fails the leg — and the whole
  self-test — closed.

The crypto is **not** touched: the scan is plain byte-window matching over the
real sealed output; the seal/ratchet primitives are the same audited
ChaCha20-Poly1305 / HMAC-SHA256 constructions. No new dependency.

## A soundness note worth carrying forward

A leakcheck over ciphertext is only meaningful for **distinctive** secrets: a
2-byte plaintext (`"hi"`) can false-positive against random AEAD output (~1/65536
per window), which surfaced as a flaky test. The relay self-test uses a long,
distinctive body, so its verdict is deterministic; the test bodies were lengthened
to match. High-entropy secrets (the 53-char AID, 32-byte keys, 32-byte chain
state) never collide. The probe was run 6× with no flake.

## Deliberately deferred (named seams, not stubs that pretend)

- The **logs / receipts / telemetry / crash-report** half of the claim's scan
  surface — today there *is* no logging or telemetry path on the seal leg, so
  there is nothing to leak through one; when a relay log or push receipt lands,
  the same `prove_routing_only` scan extends to cover its bytes.
- **ENC-5** (the untrusted relay can't tamper, replay, or link — AEAD-reject +
  replay-dedup + pairwise-mailbox-unlinkability) is the adjacent transport claim,
  still open.

## Gate verdict

```
recurve --config .recurve/murmur.toml matrix --gate   → exit 0
  ENC-4                GREEN  closed
  holding 16 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
  traps: 5/5 counterexamples still RED
  GATE OK
  sculpt murmur: gate OK (exit 0)
  leakcheck: clean
recurve --config .recurve/murmur.toml coverage --gate → 0 orphan prose gaps
```

- `cargo test --release -p murmur-core -p murmur-relay`: 38 passed (was 33; +5
  leakcheck tests: a real sealed envelope carries routing only; a leaked sender
  address / plaintext / session key is each caught; the mailbox id is not treated
  as a leak), deterministic across 6 runs.
- `cargo clippy --release -p murmur-core -p murmur-relay --all-targets`: clean, 0
  warnings, no suppressions.
- The trap (`enc-4.trap/sender-aid-in-envelope`) turns the probe RED — the probe
  discriminates (GREEN on the good path, RED on the captured envelope that carries
  the sender AID).
- ENC-1, ENC-2, DEV-1, APP-1 stayed GREEN; zero regressions. The app sculpt tree
  was not touched.
```
