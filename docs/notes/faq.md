# Frequently Asked Questions

## Why not GPG?

**GPG is powerful but complex.** It was designed for email encryption in the 1990s and carries decades of accumulated features, key formats, and trust models.

| Aspect | GPG | Auths |
|--------|-----|--------|
| Key management | Manual (export, import, backup) | Platform keychain |
| Trust model | Web of Trust | Attestation chains |
| Learning curve | Steep | Minimal |
| Modern integration | Bolted on | Native (Git SSH) |

**Auths's approach:**
- Keys live in your OS keychain—no manual file management
- Passphrase prompts only when signing, not constantly
- Git's native SSH signing (2.34+) instead of GPG-specific tooling
- Identity binding through attestations, not key servers

**When GPG still makes sense:**
- Email encryption (S/MIME or PGP/MIME)
- File encryption for archival
- Established GPG infrastructure in your organization

## Why not blockchain?

**Blockchains solve distributed consensus.** Auths solves identity binding.

| Aspect | Blockchain | Auths |
|--------|------------|--------|
| Consensus | Global (expensive) | Local (free) |
| Latency | Minutes to hours | Instant |
| Storage | On-chain (costs gas) | Git (free) |
| Revocation | Append-only | Attestation |
| Privacy | Pseudonymous public ledger | Private by default |

**Git is your "blockchain":**
- Merkle-tree-based (just like Bitcoin)
- Tamper-evident history
- Distributed replication built-in
- Zero transaction fees
- Works offline

**When blockchain makes sense:**
- Trustless global coordination
- Cryptocurrency transactions
- Public timestamping services

## Why Git for attestations?

**Git is already everywhere developers work.**

1. **No new infrastructure**: Your attestations live in the same repos as your code
2. **Built-in replication**: Push to multiple remotes for redundancy
3. **Offline-first**: Sign and attest without network access
4. **Conflict resolution**: Git's merge semantics handle concurrent updates
5. **Audit trail**: `git log` shows attestation history

**Storage model:**
```
refs/auths/identity          → Identity metadata
refs/auths/devices/nodes/X   → Device attestations
```

**Verification doesn't require the signer's repo:**
- Attestations are self-contained JSON with signatures
- Verifiers only need the public key (in `allowed_signers`)

## Is Auths production-ready?

**Current status: Pre-1.0**

| Component | Status | Notes |
|-----------|--------|-------|
| auths-core | Beta | Stable API, used in CLI |
| auths-cli | Beta | Feature-complete for core use cases |
| auths-verifier | Beta | WASM support ready |
| Threshold signatures | Planned | Epic 6 in roadmap |
| Security audit | Not yet | Required before 1.0 |

**Roadmap to v1.0:**
- v0.3: Hardened core (zeroize audit, no seeds in API)
- v0.4: Verify everywhere (npm, PyPI, GitHub Action)
- v0.5: Git native (`git commit -S` integration)
- v0.6: Cross-platform (Linux, Android, Windows)
- v1.0: SDK polish, stable API, security audit

**Safe to use for:**
- Personal projects
- Internal tools
- Non-critical signing

**Wait for 1.0 for:**
- Production security infrastructure
- Compliance-sensitive applications

## How do I migrate from GPG signing?

**Coexistence is possible.** You don't have to switch everything at once.

### Step 1: Set up Auths alongside GPG

```bash
# Create Auths identity
auths id init-did --local-key-alias main --metadata-file meta.json

# Keep GPG as default
git config --global gpg.format openpgp

# Use Auths for specific repos
cd my-new-project
git config --local gpg.format ssh
git config --local gpg.ssh.program auths-sign
git config --local user.signingKey "auths:main"
```

### Step 2: Verify both signature types

```bash
# GPG signatures still verify normally
git log --show-signature

# Auths signatures verify via SSH
git config gpg.ssh.allowedSignersFile .auths/allowed_signers
```

### Step 3: Gradual migration

- New projects: Use Auths from the start
- Existing projects: Switch when convenient
- Team projects: Add Auths keys to `allowed_signers`

### No key conversion

GPG keys and Auths keys are different formats. Generate new Auths keys rather than trying to convert.

## How does Auths relate to DID standards?

**Auths uses did:key for device DIDs.**

```
did:key:z6Mk...  ← Your public key, self-certifying
```

- No resolution required (key is in the DID itself)
- Ed25519-based (same as SSH keys)
- Interoperable with DID ecosystems

**Controller DID uses did:keri-style derivation:**

```
did:keri:ABC...  ← Derived from your root key
```

This provides a stable identifier even if you rotate keys (future feature).

## Can I use Auths with Radicle?

**Yes, with compatible storage layouts.**

```bash
# Initialize with Radicle-compatible refs
auths id init-did --preset radicle ...
```

This stores attestations in `refs/rad/*` instead of `refs/auths/*`.

Radicle integration (Epic 5 in roadmap) will add:
- Radicle node authentication
- Patch signing with Auths keys
- Identity federation between repos

## What happens if I lose my device?

**Revoke from another device, or accept key loss.**

If you have multiple linked devices:
```bash
# From any other device
auths device revoke --device-did did:key:z6MkLostDevice...
```

If you only had one device:
- Your identity is orphaned
- You cannot sign or revoke
- Create a new identity

**Prevention:**
- Link multiple devices
- Future: Threshold signatures (M-of-N recovery)
- Future: Social recovery mechanisms

## Is my private key ever exposed?

**No. Private keys never leave the secure enclave.**

The signing flow:
1. Auths requests a signature from the keychain
2. Keychain decrypts key in protected memory
3. Keychain performs signature operation
4. Only the signature is returned

Even Auths code never sees the raw private key bytes—only the encrypted PKCS#8 blob, which is decrypted inside a `Zeroizing<>` container that clears memory on drop.

## See Also

- [Threat Model](../security/threat-model.md) — Detailed security analysis
- [Quickstart](quickstart.md) — Get started in 5 minutes
- [Integration Guide](integration-guide.md) — Use Auths as a library
