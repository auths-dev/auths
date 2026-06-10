# Archive (pre-KEL-native)

The documents in this directory predate the June-2026 KEL-native migration and
are retained for historical context only.

They describe an earlier architecture in which commit trust was anchored on an
SSH `allowed_signers` allowlist and device/org membership was established via
standalone attestations. None of that describes the current system: trust is
now resolved by replaying the signer's Key Event Log (KEL) against the
committed `.auths/roots` trusted-root pin, commits carry in-band `did:keri:`
trailers, and devices are KERI delegated identifiers (`dip`/`drt`) anchored by
the root identity.

Statements in these documents about SSH signing, `allowed_signers` files, or
attestation-based org/device membership no longer describe the system. For the
current model, see [`docs/architecture/identity-model.md`](../architecture/identity-model.md)
and [`docs/architecture/keri-only-roadmap.md`](../architecture/keri-only-roadmap.md).
