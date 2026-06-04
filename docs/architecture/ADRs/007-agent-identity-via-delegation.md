# ADR 007 — Agent (and org-member) identity via KERI delegation (Epic E)

**Status:** Accepted
**Context:** Epic E ("agent identity via delegation"). An AI agent — and an
organization member — gets its **own** KERI identity, delegated from a human/org
via `dip`/`drt`, scoped and revocable by the delegator **through the KEL**, not via
an attestation `delegated_by` field or a bearer token.

## Context

The verified reality at the start of Epic E was that the delegation engine already
existed and was **not device-specific**: `incept_delegated_device` / `build_device_dip`
/ `anchor_received_dip` / `author_root_anchor_ixn` / `rotate_delegated_device` /
`revoke_delegated_device` / `list_delegated_devices` in `auths-id/keri/delegation.rs`
operate on a delegator prefix + a fresh delegated key. Epic E was therefore mostly
**wiring an agent/org surface onto that engine**, deleting two legacy "agent" models,
and fixing one shared correctness gap (the reciprocal source seal).

Two legacy models were removed:

- A **bearer-token / in-memory session** agent model (`auths-sdk/domains/agents/`):
  minted a UUID `did:keri`, stamped an attestation, generated a random
  `bearer_token`. This violated the project rule *"bearer tokens are a red flag —
  default to DeviceDID signatures."* Deleted, with its `auths-api /v1/agents` routes.
- A **standalone-`icp` + attestation `delegated_by`** provisioning path
  (`auths-id/agent_identity.rs`). Replaced with a real `dip`-delegated agent.

The decisions below were surfaced during gap analysis and are recorded here as the
load-bearing identity/authority choices.

## Decisions

1. **CLI namespace = `auths id agent <add|rotate|revoke|list>`.** Grouped under the
   existing `id` command. `auths agent` is already the SSH-agent daemon, so the
   delegation verbs cannot live there. *Alternative noted:* a unified
   `auths device add --role agent` surface. (E.3–E.5)

2. **Reciprocal source seal = bilateral binding.** `dip`/`drt` carry the delegate-side
   `-G` `SealSourceCouple` (snu+dig back-reference to the anchoring event), and
   `validate_delegation` enforces **both** directions — the delegator-side
   `Seal::KeyEvent` *and* the delegate-side back-reference. This is required for honest
   keripy 1.3.4 byte-interop (keripy emits `-G`). The seal is an attachment added after
   anchoring (cooperative double-anchor): it never changes the event SAID or the signed
   bytes. (E.1)

3. **Scope/expiry = delegator-anchored scope seal.** Authority comes from the party
   that controls the delegator key: the scope (capabilities + optional expiry) rides a
   `Seal::Digest` marker in the **delegator's** own `ixn`, never in the delegate's KEL
   (a compromised agent must not widen its own scope). Expiry is **verifier-enforced**
   via an injected `now`. The capability-subset rule (a delegate may only narrow) is
   reused from the deleted bearer model. ACDC/TEL credentials are the principled
   upgrade (Epic F). *Interim fallback (unused):* a delegator-signed attestation, never
   agent-self-asserted. (E.7)

4. **Org threshold = `kt=1` now, `kt≥2` deferred.** `author_root_anchor_ixn` is
   single-author, so an org delegator must be single-signature. A `kt≥2` org delegation
   is rejected with a typed `OrgError::OrgThresholdDelegationUnsupported`; multi-sig org
   anchoring is deferred (see Deferrals). `kt=1` is the documented pre-launch baseline. (E.8)

5. **Org membership = `dip` delegated by the org AID, fail-closed.** An org member is a
   delegated identifier of the **org** AID (not an attestation `delegated_by`); the org
   anchors the member's `dip` and a role/capability scope seal. Authority is read
   **KEL-authoritative and fail-closed**: a member revoked on the org KEL is
   unauthorized **even if a stale attestation is present** — readers never OR-fallback
   to an attestation. Admin authority = holding the org signing key (the key that
   anchors the org KEL); the legacy attestation `manage_members` admin lookup is gone
   from add/remove. The member's role rides the scope seal as a `role:{role}` marker. (E.8)

6. **Legacy bearer-token model = deleted.** Pre-launch, zero users — the UUID/bearer
   model and `auths-api /v1/agents` were removed rather than migrated. (E.2)

7. **Revocation ordering = by KEL position, not wall-clock.** KERI events carry no
   timestamps, so revocation is ordered against the signing event by **KEL position**:
   the signer records the root KEL tip at sign time in an `Auths-Anchor-Seq` commit
   trailer; the verifier compares it to the revocation seal's position. A commit signed
   *before* revocation stays valid; one signed *after* fails
   (`CommitVerdict::SignedAfterRevocation`). No-trailer commits keep the flat
   `DeviceRevoked` verdict. (E.6)

8. **Custody = local-add MVP + remote follow-on.** Local `auths id agent add` / org
   `add-member` generate the delegated key on the delegator's host (like devices) and
   satisfy the acceptance. Remote/CI provisioning — the agent (or org member) holds its
   own key, reusing the pairing relay — is the priority follow-on (the autonomous-agent
   headline). Delegation depth cap and sub-agent-as-delegator rules are also deferred. (E.3, E.7)

## Consequences (assurance, stated precisely)

- An agent / org member is a first-class KERI delegated AID: its `did:keri` derives
  from its own `dip` SAID, it rotates its own key via `drt`, and a third party verifies
  its commits purely by KEL replay (delegated-by-the-claimed-root **and** not-revoked
  **and** signing key current), with no bearer token anywhere on the path.
- Authority that used to be an attestation field is now a KEL fact. Stale attestations
  cannot grant authority a revoked-on-KEL identity no longer has (decision 5).
- A `kt≥2` org cannot yet delegate members (decision 4) — it fails fast and typed
  rather than silently producing an unanchorable event.
- Scope/expiry is advisory authorization carried by the delegator, not a credential;
  credential-grade scope is Epic F (decision 3).

## Deferrals (tracked)

Each item below is out of Epic E scope and has a tracking GitHub issue on
`auths-dev/auths` (filed during E.9, each back-referencing this ADR):

1. **Multi-sig org anchoring (`kt≥2` delegators)** —
   [#213](https://github.com/auths-dev/auths/issues/213). `author_root_anchor_ixn` is
   single-author; a `kt≥2` org currently gets `OrgThresholdDelegationUnsupported`.
2. **ACDC/TEL scope credentials (Epic F)** —
   [#214](https://github.com/auths-dev/auths/issues/214). Credential-grade
   capabilities/roles to replace the advisory delegator-anchored scope seal.
3. **Remote / CI headless agent (and org-member) provisioning** —
   [#215](https://github.com/auths-dev/auths/issues/215). The delegate holds its own
   key and the delegator only anchors, reusing the pairing relay. **Priority follow-on
   — the autonomous-agent headline.**
4. **Cascade revocation** —
   [#216](https://github.com/auths-dev/auths/issues/216). Revoking an agent should
   transitively invalidate the sub-agents it delegated.
5. **Signer-type discriminator in the commit trailer** —
   [#217](https://github.com/auths-dev/auths/issues/217). Lets policy enforce e.g. "no
   agent signatures on protected branches."
6. **Delegation depth cap + sub-agent-as-delegator rules** —
   [#218](https://github.com/auths-dev/auths/issues/218). org→human→agent is depth 3; a
   hard cap and the rules for an agent delegating further are unspecified.

## Reconciliation

- The roadmap's Epic E "events built, unwired" status is superseded: the engine was
  already built and generic, and Epic E wired the agent + org-member surface onto it,
  fixed the reciprocal seal, ordered revocation by KEL position, and added
  delegator-anchored scope. The legacy attestation `delegated_by` org model
  (`org/service.rs`) and both legacy agent models are removed.
- The attestation-based org *capability/role update* helpers (`update_*`/`get_*`) were
  left intact (out of Epic E scope) and should be retired when org updates also move to
  the KEL.

## References

- `docs/architecture/keri-only-roadmap.md` §"Epic E"
- `docs/getting-started/delegation.md` (rewritten for the `dip` model)
- `docs/AGENT_PROVISIONING.md` (rewritten for the `dip` model)
- `docs/architecture/device-model.md` (devices/agents are `dip`/`drt` delegated AIDs)
- `docs/architecture/multi_device_accepted_risks.md` (`kt=1`, no-witness baseline)
- `docs/architecture/cryptography.md` → "Wire-format Curve Tagging"
- ADR 006 (witness receipting; same deferral-recording convention)
