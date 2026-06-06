# Native KEL distribution (Epic C)

**Status:** Active (2026-06-03). Companion to `keri-only-roadmap.md` (Epic C) and `cryptography.md`.

A verifier who never saw an identity must be able to fetch its KEL over the network — decentralized,
**no central CA and no central server** — and replay it to a trusted key-state. This document defines
the wire formats and the trust model.

## The one rule

> **Distribution is untrusted. Trust comes only from replay against the self-certifying prefix.**

Every transport below (git remote, static HTTP/OOBI, Key-State Notice) only *delivers* bytes. The
verifier feeds them into `verify_commit_against_kel`, which replays the KEL and checks the root against
the committed `.auths/roots` pin. A malicious or stale source can withhold data (a freshness/DoS
problem) but **cannot forge a key-state**: substituting a different identity's KEL fails the
**prefix-binding guard** (`auths_id::keri::verify_prefix_binding` re-derives the inception SAID and
compares it to the requested `did:keri:` prefix — it never trusts the event's stored `i` field), and
mutating an event breaks the self-addressing SAID / hash chain. Continuing a KEL requires the
pre-committed next key (pre-rotation commitment `n = H(next_key)`), which only the controller holds —
so KEL replay is authentic even without per-event controller signatures.

## C1 — git-remote resolution (done)

`auths verify <commit> --remote <url>` resolves a signer's device + root KELs from a git remote with no
local pre-seeding. Implementation: `auths_storage::git::RemoteKelSource` fetches `refs/auths/registry`
into a throwaway temp repo; `auths_sdk::keri::KelResolverChain` orchestrates **local-first + rollback
floor** (a remote KEL older than the locally-trusted tip is rejected; a strictly-newer one is accepted;
ties prefer local). Local-only by default — no network without `--remote`.

## C2 — OOBI-style static distribution

For verifiers without the git remote, an identity's KEL is published as **flat files any static host
serves** (GitHub Pages, S3, the git host) — the "no central server" form.

### URI scheme

Adopts the KERI/`did:webs` conventions:

```text
<host>/.well-known/keri/oobi/<aid>/keri.cesr
```

- `<aid>` — the `did:keri:` prefix (a base64url CESR string; URL- and filesystem-safe).
- `keri.cesr` — the KEL (see wire format). One directory per AID.

An **OOBI is an untrusted introduction**: it associates a URL with an AID, nothing more. The bytes it
returns are verified by replay + the prefix-binding guard, exactly as for the git path.

### Wire format (`keri.cesr`)

The KEL as a **JSON array of event bodies**, content-type `application/json+cesr`. The CESR-tagged
verkeys (`k[]`/`n[]`) are serialized **verbatim** — curve tags are preserved with zero transformation
(unlike the deprecated Ed25519-flattening `HttpIdentityResolver`). Reader/writer:
`auths_storage::git::{export_identity_oobi, parse_oobi_kel}`.

Per-event controller signatures (CESR `-A##` attachments) are **not** included: key-state derivation
relies on the SAID chain + pre-rotation commitments (above), and the prefix-binding guard re-derives the
inception SAID on ingest. (Witness receipts are Epic D; the KSN reserves a slot for them — see C3.)

### Device vs. root

A delegated device's `dip` carries its delegator (root) AID in `di`. To make a device resolvable
end-to-end, publish **both** the device AID's OOBI and the root AID's OOBI; a client resolving the
device recurses to the root's OOBI to complete `validate_delegation`. (The commit verifier already
resolves device + root independently from the two commit trailers.)

### Transport hardening (C2b — HTTP client)

The HTTP OOBI *client* must treat the URL as hostile: no redirect-following to private/loopback ranges,
HTTPS-only, response-size caps. The same prefix-binding + rollback guards as C1 apply regardless of
transport — they are not reimplemented per transport.

## C3 — Key-State Notice (KSN)

A signed snapshot of current key-state for thin/CI clients that cannot replay the full log.
Types in `auths_keri::ksn`:

- `KeyStateNotice { version, t: "ksn", state, dt }` — the controller-signed body. `state` is the
  `KeyState` (carries CESR-tagged `current_keys`, `sequence`, `delegator`, thresholds, backers). `dt` is
  an injected RFC-3339 timestamp. `canonical_bytes()` is the deterministic struct-order JSON the
  controller signs.
- `SignedKsn { notice, signature, receipts }` — the body + detached controller signature (over
  `canonical_bytes`) + a **reserved** `receipts: Vec<SignedReceipt>` slot. The receipts are **not**
  covered by the controller signature (witnesses receipt the signed notice after the fact), so Epic D
  populates the slot without a wire-format break or invalidating the signature. Empty (and omitted) in v1.

### Serving / consuming

Served as `ksn.json` (a `SignedKsn`) alongside `keri.cesr` under the same OOBI path:
`<host>/.well-known/keri/oobi/<aid>/ksn.json`. A thin client deserializes it, calls
`SignedKsn::verify()` and `SignedKsn::check_not_stale(last_seen_seq)`.

### Verification (the forgery-rejection checklist)

`SignedKsn::verify()` requires ALL of: `t == "ksn"`; a current key is named; that key decodes (curve
from its CESR tag); and the signature verifies over the canonical bytes **by that current key** (the
signer *is* the key the state names as current — self-attested). Rollback is rejected separately by
`check_not_stale(last_seen_seq)` (monotonicity on `sequence`). Tampering, an unsigned/garbage signature,
a signature by a non-current key, or a wrong `t` all fail.

### Trust model — trust-on-first-sight (the `kt=1` caveat)

A verified KSN returns `VerifiedKsn { state, trust: TrustOnFirstSight }`. The verdict is explicit that a
controller-signed KSN is **a latency optimization, never a trust upgrade**:
`is_authoritative_over_kel()` and `satisfies_revocation_check()` both return `false`. Rationale: under
`kt=1` with no witnesses (`multi_device_accepted_risks.md`), a compromised controller can sign a
self-consistent notice naming its own key — so a KSN is only as good as trust-on-first-sight, never
authoritative when the full KEL is resolvable, and never sufficient for a revocation check (revocation is
a root-KEL fact, and a delegated-device KSN is flagged via `names_delegated_device()`). Epic D adds a
`Witnessed` trust level once `bt`-of-`b` receipts fill the reserved slot.

## Non-goal (this epic): external KERI-tooling byte-interop

auths' KEL/CESR diverges from keripy/keria/signify until "Epic 4" (`docs/plans/keri_compliance.md`):
in-body `dt` in the SAID, `1AAI` used as the P-256 transferable code. The C2/C3 wire formats therefore
target **auths verifiers**; cross-tooling byte-interop is tracked separately and is out of scope here.
