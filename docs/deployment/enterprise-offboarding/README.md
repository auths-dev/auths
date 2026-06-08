# Enterprise Off-boarding & Air-gapped Evidence — Deployment Kit

A repeatable install for a single organization. It lands a **cryptographic,
audit-ready off-boarding event**: when you fire a person, rotate a vendor, or kill a
compromised key, any credential that subject later presents is **provably dead** —
even a stale, otherwise-valid attestation — and that fact verifies **air-gapped**.

This kit is composition over already-shipped primitives. Nothing here needs a witness
commons, a blockchain, or a central server — just Git and cryptography.

> **Scope:** first-party / single-org. The trust root is the org's own KERI identity;
> there is no cross-org federation here (that is Epic E2). Read **Limits** below
> before deploying — the `kt=1` single-signature model has real, accepted tradeoffs.

---

## What you get

| Capability | Command | Evidence produced |
|---|---|---|
| Stand up an org identity | `auths org create` | a self-certifying `did:keri` org AID |
| Add a member (their own key) | `auths org add-member` | a delegation anchored in the org KEL |
| Off-board a member | `auths org revoke-member` | a **signed, durable off-boarding record** bound to the revocation's KEL position |
| Prove signed-before-vs-after | `auths org audit` | a typed `AuthorityAtSigning` verdict (by KEL position, never wall-clock) |
| List off-boardings | `auths org offboarding-log` | the audit-ready record set (`--json` for tooling) |
| Package for air-gap | `auths org bundle` | a self-contained, URL-free bundle |
| Verify offline | `auths artifact verify --offline --roots` | a fail-closed verdict, zero network |

---

## 1. Pin the trust roots

The verifier trusts a small, explicit set of root identities. Roots are **DID-only** —
a root says *"this org's KEL may delegate authority to callers"*; the **capabilities**
a member holds come from the org KEL's delegator-anchored scope seals, never from the
roots file.

Copy [`auths-roots.template`](./auths-roots.template) to `.auths/roots` in the repo
your CI verifies, and replace the placeholder with your org's `did:keri`:

```text
# .auths/roots — one did:keri per line; '#' comments allowed.
did:keri:EYourOrgPrefixHere...
```

`auths artifact verify` auto-reads `.auths/roots`; `--roots <path>` overrides it. A
malformed line is a **hard error** (fail-closed), never silently skipped.

## 2. Add the CI verify gate

Drop [`ci-verify-gate.yml`](./ci-verify-gate.yml) into `.github/workflows/`. It rejects
any artifact whose signer's authority was revoked:

```yaml
- name: Verify provenance (offline, pinned roots)
  run: auths artifact verify ./build.out --offline --roots .auths/roots
```

The gate exits non-zero on any non-authorized verdict (untrusted root, KEL duplicity,
signed-at/after-revocation, or an incomplete bundle), so a revoked signer fails the
build.

## 3. Run the off-boarding lifecycle

The end-to-end flow — see [`offboarding-demo.sh`](./offboarding-demo.sh) for a runnable
version:

```bash
# Stand up the org identity (self-certifying — no IdP issues it).
auths org create --name "Acme Security"
ORG=did:keri:EAcme...                       # printed by `create`

# Add a member by their OWN did:keri (delegate-to-existing) or a bare alias (mint).
auths org add-member --org "$ORG" --member did:keri:EAlice... \
  --role engineer --capabilities sign_commit,deploy:staging

auths org list-members --org "$ORG"

# Off-board: anchors a revocation AND emits a durable, signed record.
auths org revoke-member --org "$ORG" --member did:keri:EAlice... --note "left the company"

# Prove an artifact was signed before vs after off-boarding (by KEL position).
auths org audit --org "$ORG" --member did:keri:EAlice... \
  --artifact ./release.tar.gz --signed-at 41 --json
#  -> AuthorizedBeforeRevocation | RejectedAfterRevocation { revoked_at: 42 }

# The audit-ready off-boarding log.
auths org offboarding-log --org "$ORG" --json

# Package everything for a disconnected/classified environment.
auths org bundle --org "$ORG" --out ./acme.auths-offline

# Air-gapped side (no network): verify the bundle, classify a signer.
auths artifact verify ./acme.auths-offline --offline --roots .auths/roots \
  --member did:keri:EAlice... --signed-at 41 --json
```

**Flag names (load-bearing):** `--org`, `--member` (alias `--member-did`),
`--capabilities` (plural, comma-delimited). Earlier drafts used `--did` / `--capability`
— those do not exist.

## 4. Programmatic provisioning (no CLI subprocess)

The kit provisions orgs through the **SDK workflows**, not by shelling out — agents and
servers use the same domain logic the CLI does. See
[`programmatic-provisioning.md`](./programmatic-provisioning.md).

```rust
use auths_sdk::workflows::org::{create_org, revoke_member, build_org_bundle};
// create_org(&ctx, name, &admin_alias, curve, metadata)?  -> OrgCreated
// revoke_member(&ctx, &org, &org_alias, member_did, reason)? -> Option<SignedOffboardingRecord>
// build_org_bundle(&ctx, &org)? -> AirGappedOrgBundle
```

---

## The metric: mean-time-to-provably-dead-credential

The headline number is the **mean time from off-boarding decision to provably-dead
credential** — how long between "we decided to revoke" and "every verifier rejects
that subject."

- **Online verifiers** read the org KEL directly: a credential is provably dead the
  instant `auths org revoke-member` commits the revocation seal. The measurable lag is
  the operator's reaction time, not a propagation delay — there is no CRL/OCSP to push.
- **Air-gapped verifiers** read a bundle: the credential is provably dead in any bundle
  built **at or after** the revocation's KEL position. The measurable lag is the bundle
  refresh cadence (see freshness, below).

**How to measure it:** the off-boarding record carries `recorded_at` (decision time)
and `revoked_at_seq` (the KEL position authority ended). Compare `recorded_at` against
the timestamp of the first verify that rejects the subject (online) or the `built_at`
of the first bundle that includes the revocation (air-gapped). `auths org offboarding-log
--json` is the data source; the verdict ordering is always by KEL position, so a
backdated clock can never inflate the number in your favour.

---

## Limits (read before deploying)

These are accepted tradeoffs of the first-party, single-org model. State them to your
security team up front — they are documented, not hidden.

- **`kt=1` single-signature org.** The org has one controller key. A compromised org
  key can both **add a malicious member** and **revoke legitimate ones**. There is no
  admin quorum yet (multi-sig `kt>=2` revocation is a tracked follow-up). Protect the
  org key accordingly (hardware-backed keychain; restricted operators).
- **First-party / single-org.** The trust root is the org itself; this kit does not do
  cross-org trust, SCIM/OIDC federation, or a witness commons. Each surface says
  "first-party / single-org." Federation is Epic E2.
- **Air-gap freshness is frozen at build.** An air-gapped bundle reflects the org KEL
  **as-of its build position** (`built_at_org_seq`, printed by `auths org bundle` and
  surfaced by offline verify). A revocation anchored *after* a bundle was built is not
  in that bundle — rebuild and redistribute to propagate new off-boardings into
  disconnected environments. Offline verify states the as-of position so a stale bundle
  is visible, never silent.
- **Ordering is by KEL position, never wall-clock.** "Signed before vs after
  off-boarding" is exact and backdating-resistant. There is intentionally **no**
  wall-clock comparison in any authority verdict.

---

## The objection we expect

*"We already have Okta + Sigstore — why add this?"* Okta is the root of trust *and* the
honeypot *and* the single point of de-platforming; Sigstore roots CI trust in the OIDC
provider and its own operated log. This kit's differentiator is the two things neither
can do: **off-boarding/revocation that verifies air-gapped with no issuer**, and
**authority that is attenuable and traceable to a principal**. Position it as the
attestor / continuity layer *over* your existing IdP, not a rip-and-replace.

## Related

- `docs/architecture/multi_device_accepted_risks.md` — the `kt=1` duplicity tradeoff in depth.
- `roadmap/04-ent-provable-offboarding.md` — the epic this kit productizes.
