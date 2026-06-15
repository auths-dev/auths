# wit-n2 trap — a forged receipt that must stay RED

A probe that has never been seen RED is not yet evidence. This fixture feeds the
WIT-N2 probe a known-bad receipt bundle (via `TRAP_FIXTURE`) that the offline
verify MUST reject.

- `forged-signature/bundle.json` — a **genuine** witness receipt and the
  witness's real published identity, but with **one byte of the signature
  flipped** (the first hex nibble). Everything else is authentic: the receipt
  body, the `did:key` identity, the rest of the signature. This is a tampered
  receipt — the kind a thief produces by editing a real one.

The probe runs `auths witness verify-receipt` on the bundle in the same isolated
no-network, no-registry context it uses for the genuine path, and asserts a
non-zero exit. A zero exit here means the verifier accepted a forged receipt as
corroboration — exactly the failure WIT-N2 exists to forbid. If this ever goes
GREEN, receipts stop being worth anything: a stranger could be handed an altered
receipt and told it verified.
