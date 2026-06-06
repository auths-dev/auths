# Agent Provisioning

## Overview

Agent provisioning gives an AI agent (or CI/CD runner) its **own KERI identity**,
delegated from a human or organization and revocable through the KEL. An agent is a
KERI **delegated identifier**: it is incepted with a `dip` that names the delegator,
the delegator anchors that `dip` in its own KEL, and the delegator anchors a scope
seal granting capabilities (e.g. `sign_commit`) with an optional expiry. There are no
bearer tokens, and authority is provable by KEL replay — not by a stand-alone
attestation.

## Identity hierarchy

```
Human / Org Identity (did:keri:E…, the delegator KEL)
├── Device   (did:keri:E…)  ← laptop — dip delegated + root-anchored
├── Device   (did:keri:E…)  ← phone
└── Agent    (did:keri:E…)  ← CI bot — dip delegated, scope seal = sign_commit
```

| Level | DID | Key lifecycle | Storage |
|-------|-----|---------------|---------|
| Human / Org | `did:keri:E…` | KERI `icp`/`rot` | HSM or software keychain |
| Device | `did:keri:E…` (delegated AID) | own `dip`/`drt`, root-anchored | platform keychain |
| Agent | `did:keri:E…` (delegated AID) | own `dip`/`drt`, delegator-anchored | platform keychain (local-add MVP) |

Devices and agents share the exact same `dip`/`drt` delegation mechanism; the
distinction is a role marker so `auths id agent list` and `auths device list` don't
intermix.

## Provisioning flow

### 1. Create the delegator (human or org) identity

```bash
# Software-backed (default)
auths init --profile developer

# HSM-backed (PKCS#11)
export AUTHS_KEYCHAIN_BACKEND=pkcs11
export AUTHS_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
export AUTHS_PKCS11_TOKEN_LABEL=auths
export AUTHS_PKCS11_PIN=12345678
auths init --profile developer
```

### 2. Delegate an agent (`dip`, anchored by the delegator)

```bash
auths id agent add \
  --label ci-bot \
  --key my-key \
  --scope sign_commit \
  --expires-in 86400
```

The delegator's host generates the agent key (local-add MVP), the agent's `dip`
names the delegator, and the delegator authors an `ixn` anchoring it plus a scope
seal carrying the capabilities and expiry. The agent's `did:keri` derives from its
`dip` SAID. (Remote/CI provisioning — the agent holds its own key, reusing the
pairing relay — is the priority follow-on; see
[ADR 007](architecture/ADRs/007-agent-identity-via-delegation.md).)

### 3. Agent rotates its own key (`drt`)

```bash
auths id agent rotate did:keri:EAgent… --key my-key
```

The agent reveals its pre-committed next key and authors a `drt`; the delegator
anchors it. The old key stops verifying.

### 4. Agent signs within its scope

Each signing operation verifies by KEL replay:

- the agent KEL is valid and the signing key is current,
- the delegator anchored the agent's `dip` (bilateral seal),
- the agent is not revoked (ordered by KEL position),
- the action is within the delegator-anchored scope and before any expiry.

### 5. Revocation

```bash
auths id agent revoke did:keri:EAgent… --key my-key
auths id agent list --include-revoked
```

Revocation is a KEL fact. Signatures ordered **before** the revocation's KEL
position stay valid; signatures ordered **after** it fail
(`SignedAfterRevocation`).

## Organization members

An org member is a `dip` delegated by the **org AID** (not an attestation
`delegated_by`). The org anchors the member's `dip` and a scope seal carrying the
member's role and capabilities; authority is read fail-closed from the org KEL:

```bash
auths org add-member --org did:keri:EOrg… --member alice --role member --key org-myorg
auths org list-members --org did:keri:EOrg…
auths org revoke-member --org did:keri:EOrg… --member did:keri:EAlice… --key org-myorg
```

A `kt≥2` (multi-signature) org delegator is not yet supported and returns a typed
`OrgThresholdDelegationUnsupported` error (`kt=1` is the documented pre-launch
baseline).

## Scope and expiry

Scope is **delegator-anchored**: capabilities and expiry live in a seal in the
delegator's KEL, never in the agent's own KEL (a compromised agent cannot widen its
scope). A requested scope must be a subset of the delegator's own — the SDK rejects
an over-broad request with `OutsideDelegatorScope`. Expiry is verifier-enforced via
an injected `now`. Credential-grade scope (ACDC/TEL) is the Epic F upgrade.

## HSM-backed delegation

When the delegator uses PKCS#11, its key never leaves hardware:

| Operation | Key location |
|-----------|-------------|
| Key generation | on HSM token |
| Anchoring `ixn` signing | delegated to HSM via `CKM_EDDSA` |
| Key rotation | new key generated on HSM |
| Key export | blocked (`CKA_EXTRACTABLE=false`) |

Compatible HSMs: YubiKey HSM2, Thales Luna, Nitrokey HSM, SoftHSMv2 (testing).

### Environment variables

| Variable | Description |
|----------|-------------|
| `AUTHS_PKCS11_LIBRARY` | Path to PKCS#11 shared library |
| `AUTHS_PKCS11_SLOT` | Numeric slot ID (mutually exclusive with token label) |
| `AUTHS_PKCS11_TOKEN_LABEL` | Token label for slot lookup |
| `AUTHS_PKCS11_PIN` | User PIN for HSM authentication |
| `AUTHS_PKCS11_KEY_LABEL` | Label for the signing key object |

## Policy evaluation

Authority for policy decisions is read from the KEL (delegated-by, not-revoked,
role, capabilities), fail-closed. A revoked-on-KEL identity is denied even if a
stale attestation is present.

```json
{
  "and": [
    {"delegated_by": "did:keri:EOrg…"},
    {"has_capability": "sign_commit"},
    {"not_revoked": true},
    {"not_expired": true}
  ]
}
```

```bash
auths policy lint policy.json
auths policy explain policy.json --context context.json
```

## CLI quick reference

```bash
# Initialize the delegator identity
auths init --profile developer --non-interactive

# Delegate / rotate / revoke / list agents
auths id agent add --label ci-bot --key my-key --scope sign_commit --expires-in 86400
auths id agent rotate did:keri:EAgent… --key my-key
auths id agent revoke did:keri:EAgent… --key my-key
auths id agent list --include-revoked

# Org members
auths org add-member --org did:keri:EOrg… --member alice --role member --key org-myorg
auths org list-members --org did:keri:EOrg…

# Verify a commit (KEL replay)
auths verify HEAD
```

## See also

- [ADR 007 — Agent identity via delegation](architecture/ADRs/007-agent-identity-via-delegation.md)
- [Delegation](getting-started/delegation.md)
- [Device model](architecture/device-model.md)
