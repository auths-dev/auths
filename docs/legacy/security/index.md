# Security

Security analysis, threat modeling, and incident response for Auths.

## Sections

- **[Threat Model](threat-model.md)** -- Comprehensive threat model for `auths-verifier`: assets, threat actors, trust boundaries, attack vectors with mitigations, dependency analysis, and audit checklist.

- **[Revocation Design](revocation-design.md)** -- How attestation revocation works: signed `revoked_at` fields, the revocation flow, verification behavior, and enterprise considerations.

- **[Key Compromise Recovery](key-compromise-recovery.md)** -- End-to-end walkthrough from "key compromised" to "identity recovered and verified," demonstrating KERI pre-rotation protection.

- **[Git Linearity Enforcement](git-linearity.md)** -- Three layers of defense (pre-receive hooks, registry backend, client validation) that enforce append-only semantics on KERI Key Event Logs.
