# Auths vs Sigstore: Honest Comparison

## Where Sigstore Wins

**Adoption.** Sigstore is the de facto standard for open-source artifact signing. Kubernetes, npm, PyPI, Homebrew, Maven Central all use it. Auths has zero users.

**Convenience.** Sigstore's "keyless" model means developers authenticate via OIDC (GitHub login), sign with an ephemeral certificate from Fulcio, and the proof goes to the Rekor transparency log. One CLI command, no key management. Auths requires `auths init` to create a KERI identity and device key.

**OIDC ecosystem.** Sigstore works with GitHub, Google, Microsoft identities out of the box. Auths uses its own identity layer.

**SLSA Level 2+.** Sigstore's signed provenance from a hosted build platform meets SLSA L2. Auths ephemeral signing is L1 (provenance exists, but not from a verified builder).

**Enterprise support.** Sigstore is backed by the OpenSSF (Linux Foundation) with enterprise adoption programs. Auths is a solo project.

**Replay protection.** Rekor provides a globally consistent transparency log with timestamped inclusion proofs. Auths currently relies on attestation timestamps (self-reported). Witness anchoring is planned but not shipped.

## Where Auths Wins

**Self-sovereign identity.** Auths identity is anchored to a KERI key event log stored in Git. No certificate authority, no OIDC provider, no central infrastructure. If GitHub goes down or changes their OIDC policy, Sigstore signing breaks. Auths signing works with just Git.

**Identity survives account compromise.** If your GitHub account is compromised, your Sigstore signing identity is compromised — Sigstore identity IS the OIDC account. With Auths, your identity is a device-bound Ed25519 key. Account compromise doesn't give the attacker your signing key. KERI pre-rotation lets you recover.

**Offline verification.** Sigstore verification requires querying the Rekor transparency log (network call). Auths verification works offline with just a Git clone — the commit signatures and allowed_signers are in the repo.

**No central authority.** Sigstore depends on Fulcio (CA) and Rekor (transparency log), both operated by the Linux Foundation. Auths depends on nothing external.

**Commit-level provenance.** Sigstore signs artifacts. Auths chains artifact signatures to signed commits, providing a link from the binary all the way to the specific code change and the developer who approved it.

**Air-gapped environments.** Auths works in environments with no internet access. Sigstore does not.

## Where They're Equivalent

**Artifact-level cryptographic signing.** Both produce Ed25519 signatures on artifacts using ephemeral keys generated per CI run.

**Zero CI secrets.** Neither requires long-lived signing secrets in CI. Sigstore uses OIDC tokens. Auths generates throwaway keys.

**Trust in CI.** Both trust the CI platform to build honestly from the claimed source. Neither provides reproducible builds out of the box.

**Tamper detection.** Both detect post-signing artifact tampering via cryptographic hash verification.

## The Honest Pitch

If you want the easiest path to signed artifacts and trust the Linux Foundation's infrastructure, use Sigstore. It's mature, widely adopted, and works with one command.

If you want self-sovereign identity that survives account compromise, works offline, and doesn't depend on any central authority, use Auths. The tradeoff is more setup and a smaller ecosystem.

Both are better than unsigned artifacts.
