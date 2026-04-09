# Ephemeral CI Signing: Threat Model

## 1. Trust Chain

```
Maintainer's device-bound Ed25519 key (hardware keychain, Touch ID)
    ↓ signs git commits
Commit signature (SSH, verifiable via allowed_signers)
    ↓ CI verifies before building
CI runner builds artifact from verified commit
    ↓ generates throwaway Ed25519 keypair (lives in memory, dies with the run)
Ephemeral key signs artifact hash + commit SHA + build environment
    ↓ produces .auths.json attestation
Consumer verifies: artifact hash ← ephemeral signature ← commit SHA ← maintainer signature
```

**Root of trust:** The maintainer's KERI-rooted Ed25519 key, stored in the device hardware keychain. Loss or compromise is handled by KERI pre-rotation — the next key is committed before the current key is exposed.

**Transitive trust:** The ephemeral key has no identity of its own. It's a `did:key:` — self-certifying, born and dead in one CI run. Its authority derives entirely from the fact that CI verified the commit was signed by a maintainer before using the ephemeral key to sign the artifact. The commit signature is the bridge between the maintainer's identity and the artifact.

**What the attestation binds (all covered by the ephemeral signature):**
- Artifact SHA256 hash (in `payload.digest.hex`)
- Commit SHA (in `commit_sha`)
- Build environment metadata (in `payload.ci_environment`)
- `signer_type: "workload"` (distinguishes ephemeral from device-signed)

## 2. Attack Surface

### Compromised CI runner

An attacker who owns the runner controls the build. They can:
- Build a different binary than what the source code would produce
- Generate their own ephemeral key and sign the malicious artifact
- Claim any commit SHA in the attestation

**Mitigation:** The commit SHA in the attestation is covered by the ephemeral signature. If the consumer verifies that the commit SHA is signed by a trusted maintainer (via the commit's SSH signature), they confirm the maintainer approved that specific code. The attacker can't forge the maintainer's commit signature without the maintainer's device key.

**Remaining gap:** The attacker can use a real signed commit SHA but build different code from it. This is a CI-level compromise that no signing scheme prevents — including Sigstore. The only defense is reproducible builds (out of scope) or detection after the fact (maintainer notices unexpected attestations).

**Detection:** Ephemeral attestations include `signer_type: "workload"` and build environment metadata. A maintainer monitoring their identity's attestation history would see unexpected artifacts claiming their commits. This is analogous to certificate transparency for TLS.

### Compromised maintainer device

The maintainer's Ed25519 key is extracted from the hardware keychain.

**Mitigation:** KERI pre-rotation. The maintainer's next key is cryptographically committed before the current key is active. On detection of compromise:
1. Rotate to the pre-committed next key
2. All future commit signatures use the new key
3. Past attestations anchored before the rotation event remain valid
4. Attestations signed after the compromised key's rotation are rejected

**Practical note:** Hardware keychain extraction (macOS Secure Enclave, YubiKey) requires physical access to the device and typically biometric authentication. This is significantly harder than stealing a CI secret from runner environment variables.

### Git history rewrite

An attacker rewrites git history to change what a commit SHA points to.

**Irrelevant.** The attestation pins a specific commit SHA, and commit SHAs are content-addressed hashes. You can't change what a SHA points to without changing the SHA itself. Force-pushing to a branch doesn't change existing commit objects — it changes which commit the branch ref points to. The attestation references the object, not the ref.

### Replay of old ephemeral signatures

An attacker re-publishes an old ephemeral attestation, claiming a previous artifact is the current release.

**Current mitigation (partial):** The attestation includes a timestamp and optional `expires_at`. Consumers checking freshness can detect stale attestations. The build environment metadata (run ID, workflow ref) provides additional context for detecting replays.

**Future mitigation (out of scope this epic):** Witness anchoring. Submit each attestation to the auths witness network, producing a timestamped inclusion proof. This cryptographically pins the attestation to a point in time and enables duplicity detection (two different attestations claiming the same commit SHA). The existing witness infrastructure in `auths-core/src/witness/` handles KERI KEL head consistency — extending it to attestation anchoring is a separate effort.

### Forged ephemeral key chain

An attacker generates their own ephemeral key and signs an artifact, claiming it was built from a legitimate commit.

**This is the same attack as "compromised CI runner"** — the ephemeral key is self-certifying (`did:key:`), so "forgery" just means "generate a key and sign." The ephemeral key alone proves nothing. It's only meaningful when:
1. The commit SHA in the attestation is verifiably signed by a trusted maintainer
2. The consumer trusts that the CI runner built from the commit it claims

Without both conditions, the ephemeral signature is cryptographically valid but semantically meaningless.

## 3. What We're NOT Claiming

**No reproducible builds.** A consumer cannot independently rebuild the binary from source and check that it matches. They're trusting that the CI runner built honestly from the verified commit. This is weaker than SLSA Level 4 but equivalent to how every CI-based signing system works in practice (including Sigstore).

**No CI runner honesty guarantee.** If the CI runner is fully compromised, the attacker controls the build output. The ephemeral signing scheme makes the attack detectable (via commit signature verification and attestation monitoring) but does not prevent it. Prevention requires either reproducible builds or hardware-attested build environments, both of which are out of scope.

**No offline verification without the git repo.** Verifying an ephemeral attestation requires access to the git commit object (to check the commit's SSH signature). A consumer who only has the artifact + `.auths.json` and no git clone cannot complete the transitive verification. They can verify the ephemeral signature and check the artifact hash, but they're trusting the commit SHA claim without verification.

## 4. Comparison with Sigstore

| Property | Auths (ephemeral) | Sigstore |
|----------|-------------------|----------|
| **Artifact cryptographically signed** | Yes (ephemeral key) | Yes (ephemeral cert from Fulcio) |
| **Signing secrets in CI** | None — key generated per run | None — OIDC + ephemeral cert |
| **Root of trust** | Maintainer's device-bound key | OIDC provider (GitHub, Google) |
| **Identity survives account compromise** | Yes — KERI rotation | No — identity IS the OIDC account |
| **Central authority required** | No | Yes — Fulcio CA + Rekor log |
| **Offline verification** | Partial — needs git repo | No — needs Rekor |
| **Replay protection** | Timestamps + future witness anchoring | Rekor transparency log |
| **SLSA level** | L1 (provenance exists) | L2 (signed provenance from hosted build) |
| **Adoption** | Pre-launch | De facto standard |

**Where Sigstore wins:** Adoption (it's everywhere), convenience (keyless, one-line integration), OIDC ecosystem (works with GitHub/Google/Microsoft identity), enterprise support via OpenSSF, SLSA L2+ provenance, Rekor transparency log for replay protection.

**Where Auths wins:** Self-sovereign identity (no CA, no OIDC dependency), offline verification (with git repo), identity durability (survives GitHub account compromise), commit-level provenance (Sigstore signs artifacts, Auths chains to commit signatures), no central infrastructure dependency.

**Where equivalent:** Both produce artifact-level cryptographic signatures using ephemeral keys. Both require trust in the CI platform for build honesty. Neither provides reproducible builds out of the box.

**The honest pitch:** If you want the easiest path to signed artifacts and trust the Linux Foundation's infrastructure, use Sigstore. If you want self-sovereign identity that survives account compromise and works without depending on any central authority, use Auths.

## 5. Future: Witness Anchoring

The current ephemeral signing model has a replay gap: there's no cryptographic proof that an attestation existed at a specific point in time. Timestamps in the attestation are self-reported by the CI runner.

**Planned mitigation:** After signing, submit the attestation's content hash to the auths witness network. The witness returns a signed receipt binding the hash to a verified timestamp. This receipt is embedded in the `.auths.json` and checked during verification.

**What this enables:**
- Replay detection: an attacker can't retroactively claim an attestation existed before it did
- Duplicity detection: two attestations claiming the same commit SHA at different times are flagged
- Revocation timeline: attestations anchored after a key rotation are rejected

**Current state:** The witness infrastructure in `auths-core/src/witness/` handles KERI key event log consistency (split-view detection). Extending it to attestation anchoring requires a new witness receipt type and a submission API. This is a separate epic.

## Wire Format: SignerType

`SignerType::Workload` serializes to `"workload"` in JSON. This string is part of `CanonicalAttestationData` and is covered by the ephemeral key's signature. Once shipped, this string cannot change without breaking verification of existing attestations.

```json
{
  "signer_type": "workload"
}
```
