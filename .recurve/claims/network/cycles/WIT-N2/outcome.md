# Cycle WIT-N2 — receipts verify offline on a stranger's machine

- **Date:** 2026-06-13
- **Gap:** `WIT-N2` (class `missing-surface`, severity `feature`)
- **Result:** **CLOSED — promoted.** Probe authored greenfield, baselined RED,
  driven GREEN; the forged-signature trap stays RED; the BOOT and WIT-N1 probes
  still GREEN; both federated gates green (demos `rictl matrix --gate` → OK,
  interop `ictl matrix --gate` → OK). `open → closed` in `gaps.yaml`; GAPS.md
  §WIT-N2 rewritten to the closed reality.
- **auths rev:** branch `dev-auths-network` (parent `9e0584ae`).

## The claim, and why it was genuinely RED

A witness receipt is only *corroboration* if a third party who does not trust
the node can check it alone — on a clean machine, with no network and no
registry. WIT-N2: a receipt plus the witness's published identity verifies
offline; a tampered receipt is rejected with a distinct reason.

The probe (`probes/wit-n2.sh`, authored this cycle) stands up the 3-witness
fixture, has `wit1` receipt a valid inception event (a real `SignedReceipt`
comes back over `POST /witness/{prefix}/event`), reads the node's published
`did:key` from `/health`, assembles the bundle, and tries to verify it offline
in an isolated empty-home context. At baseline it was honestly RED:

```
$ NO_COLOR=1 bash probes/wit-n2.sh
ours=exit2 expected=verified — a genuine receipt + the witness's published
identity did NOT verify offline (no network, no registry) … error:
unrecognized subcommand 'verify-receipt'                          (exit 1 RED)
```

The receipt half existed; the third-party-checks-it-alone half did not. The
platform shipped the self-contained offline verify primitive only deep in
`auths-core` (`witness::verify::verify_receipt`, which the node crate does NOT
compose), and the public verifier's `verify_witness_receipts` is **not**
self-contained — it requires the caller to *separately* supply a `witness_did →
key` table, so it cannot decide from the bundle alone. No `auths witness` verb
exposed any of it.

## The fix (smallest honest change in `../auths`)

The decision "does this signature verify against the key the published identity
embeds?" is protocol — it must be correct for strangers — so per the repo
boundary it belongs in the platform verifier, not the node crate.

1. **`auths-verifier::verify_receipt_offline`** (new, in `witness.rs`,
   re-exported from the crate root). Recovers the witness's key from its
   published `did:key` via `auths_crypto::did_key::did_key_decode` (the identity
   *embeds* the key — that is what makes the bundle self-contained), builds an
   `auths_keri::KeriPublicKey`, and checks the signature over
   `serde_json::to_vec(&receipt)` — byte-for-byte what the witness server signs.
   Returns a parsed `OfflineReceiptVerdict` (`Verified` / `SignatureFailed` /
   `UnreadableIdentity`); `Verified` is the only success arm, so an unchecked
   receipt cannot masquerade as a checked one (parse-don't-validate). Five unit
   tests: genuine verifies with no key table, bit-flipped signature and tampered
   body and foreign identity all `SignatureFailed`, garbage identity
   `UnreadableIdentity`.

2. **`auths-witness-node::ReceiptBundle`** (new `receipt.rs`). The self-contained
   artifact a node hands a stranger: `{ receipt: SignedReceipt, witness:
   <did:key> }`. `verify_offline()` composes the verifier surface — it
   re-implements no protocol (WIT-B1). Three tests over a real captured bundle.

3. **`auths witness verify-receipt --receipt <file>`** (new CLI verb, `-` reads
   stdin). The clap surface compiles in every build (thin def); the handler is
   feature-split — with `witness-node` it verifies via the node crate, without it
   returns the helpful "install the witness build" line. A genuine receipt prints
   `verified: …` and exits 0; a tampered or foreign one exits non-zero with the
   distinct reason; an unreadable identity is its own message.

No core crate gained a dependency on the node crate; the default `cargo tree -p
auths-cli` still pulls **zero** `auths-witness-node` (WIT-B2 holds, the lean
default stays lean). No loop vocabulary in the tree. Clippy clean (`-D warnings`)
on `auths-verifier`, `auths-witness-node`, and the feature-enabled `auths-cli`.

## Gate (federated)

- **Claim probe GREEN, trap RED.** `bash probes/wit-n2.sh` → "receipts verify
  offline on a stranger's machine … the corroboration claim holds end to end"
  (exit 0). `TRAP_FIXTURE=…/forged-signature` → RED (exit 1: "rejected: this
  receipt does not verify against did:key:z6MktUL… — it was altered or was not
  issued by that node").
- **No regression in the suite.** After `harness/rebuild.sh`, BOOT-1/2/3 and
  WIT-N1 all GREEN; BOOT-3's meta-baseline reports 4 authored probes, every one
  decided, zero BROKEN.
- **Demos:** rebuilt the stale demo artifacts the `auths-verifier` change
  invalidated (AITFC / PWNTS / verify-the-world web WASM, then DOAK /
  lost-the-laptop CLI), then `rictl matrix --gate` → `regressions 0 · broken 0 ·
  stale 0 · missing 0 · GATE OK`.
- **Interop:** `scripts/build.sh` then `ictl matrix --gate` → `regressions 0 ·
  broken 0 · stale 0 · missing 0 · GATE OK`.

## Fixtures (test data, not protocol code)

- `probes/fixtures/icp-event.json` — a valid ed25519 KERI inception event the
  probe submits to the live node to be receipted (generated once from `../auths`;
  the node computes/verifies its own SAID, so this is data).
- `probes/fixtures/receipt-bundle.json` — a real bundle captured from `wit1`, the
  no-Docker fallback so the offline-verify claim still decides on a box without
  an engine.
- `probes/wit-n2.trap/forged-signature/bundle.json` — the genuine bundle with one
  signature byte flipped; the permanent forged-receipt counterexample.

## Teardown

The probe leaves the shared fixture standing (the harness owns up/down); the
fixture was torn down at end of cycle (`harness/down.sh`) — no `auths-witness-net`
containers linger.
