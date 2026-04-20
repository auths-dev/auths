# Witness Diversity Policy

This document describes the organizational, operational, and
jurisdictional diversity requirements for the Auths witness set, and
the client-side verification quorum that makes those requirements
enforceable.

## Threat model

The verifier requires the witness set to cosign inclusion proofs for
KERI events. Single-operator witness sets are vulnerable to:

- **A1 (insider compromise)** — an operator employee with commit /
  signing-key access forges a log view.
- **A2 (legal compulsion)** — a jurisdiction compels the operator to
  silently backdate, hide, or forge entries (e.g. NSL, subpoena under
  seal).
- **A3 (supply-chain compromise)** — a shared build pipeline ships a
  malicious binary to every witness.
- **A4 (DDoS / availability)** — a single operator outage takes down
  the entire log.
- **A5 (cost + capture)** — a single operator unilaterally sets fees,
  SLAs, or deprecation schedules.
- **A6 (key-management compromise)** — a shared HSM or KMS tenant
  compromise takes down every witness at once.
- **A7 (TLS / Network infra)** — a shared CDN or TLS certificate
  issuance path is a single point of trust.

Mitigating A1-A7 requires diversity along three axes: organizational,
jurisdictional, and operational (distinct key-management + software
stacks where practical).

## Quorum rules

The verifier MUST require, before accepting any attestation:

1. **At least `K = 3` cosigned inclusion proofs** from witnesses whose
   pubkeys are pinned in the runtime trust store.
2. **The `K` proofs MUST come from witnesses operated by at least 3
   distinct organizations.** Two witnesses under the same
   `organization` metadata key are counted as one from a quorum
   perspective.
3. **The ≥ 3 organizations MUST span at least 2 jurisdictions.** A
   jurisdiction is the nation-state with legal compulsion authority
   over the operator's production infrastructure.

Shortfall on any rule is a hard verification failure. Clients MUST
NOT degrade gracefully to "2 witnesses, same org" — that is the
single-operator threat model this policy exists to eliminate.

## Operational recommendations

- **Distinct key-management products** where feasible: e.g. AWS KMS
  + GCP Cloud KMS + on-prem HSM. A shared KMS tenant compromise is a
  single point of failure even with nominally distinct operators.
- **Distinct software stacks** are a bonus but not required —
  two independent Sigsum implementations running the same binary under
  two different KMS tenants is still better than one tenant, one
  binary.
- **Cross-signed witness fingerprints**: each witness's pubkey is
  also anchored in a separate transparency log (e.g. a shared Sigsum
  log for witness public keys) so silent rotation is detectable.

## Witness onboarding

1. Operator proposes a witness in a PR to `witness_policy.json`.
2. Review: organizational identity, jurisdiction, key-management
   provider, SLA commitments, contact for compromise disclosure.
3. Pinning: the runtime trust store embeds the pubkey as a 32-byte
   Ed25519 verkey or 33-byte P-256 compressed pubkey (curve carried
   in-band per workspace wire-format rule — never inferred from
   length).
4. Key rotation: announced via a `rotation_notice` entry in the
   policy file, signed by the pre-rotation key, referencing the new
   pubkey.
5. Sunset: marked as `"status": "retired"` in the policy file at
   least 30 days before removal; retired witnesses still count for
   historical proof verification but cannot contribute to new
   quorums.

## Current state vs target state

| Axis | Current | Target (pre-GA) |
|---|---|---|
| Witnesses | 1 | ≥ 3 |
| Organizations | 1 (`auths.dev`) | ≥ 3 |
| Jurisdictions | 1 (US) | ≥ 2 |

**Current state fails the policy.** The machine-readable
[`witness_policy.json`](../../crates/auths-transparency/data/witness_policy.json)
embeds the target quorum so clients see it as a hard failure until
the witness set meets the policy. This is intentional — a passing
verification with only one witness would be worse than a loud
failure.

## Residual risks

Collusion remains possible within a single legal regime (e.g. two
US organizations subpoenaed under the same court order). The policy
mitigates this probabilistically — the more diverse the
organizations within a jurisdiction, the higher the collusion cost —
but it does not eliminate it. For highest-assurance deployments,
pair this policy with offline-verifier attestation audits (a
third-party who periodically downloads the log and checks for
consistency).

## References

- Sigsum: <https://www.sigsum.org/> (client-side policy model;
  no server-side trust decisions).
- Chrome CT policy (RFC 6962 §7.1): ≥ 2 logs across ≥ 2 operators.
- RFC 9162 (Certificate Transparency v2): log-list policy framework.
- NIST SP 800-208 §6.2 (post-quantum signature policy) for witness-
  signature algorithm agility.
