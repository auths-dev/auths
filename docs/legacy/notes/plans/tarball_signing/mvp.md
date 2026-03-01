 Plan: auths artifact sign / auths artifact verify Commands

 Context

 Supply chain attacks (SolarWinds, xz) have made artifact provenance a critical concern. Auths already has all the
 cryptographic primitives for signing and verifying artifacts — Ed25519 signatures, attestation chains with capabilities
 (sign_release), witness quorum verification, and WASM/FFI bindings for embedding. What's missing is a thin CLI surface
 that wires these together for signing arbitrary files (tarballs, binaries). The architecture should be hexagonal so
 Docker/NPM/Cargo adapters can be added later without changing the core logic.

 CLI Surface

 auths artifact sign <FILE> [--output <PATH>] [--identity-key-alias <ALIAS>] [--device-key-alias <ALIAS>]
 [--expires-in-days <N>] [--note <TEXT>]
 auths artifact verify <FILE> [--signature <PATH>] [--identity-bundle <PATH>] [--json] [--witness-receipts <PATH>]
 [--witness-keys <DID:HEX>...] [--witness-threshold <N>]

 Exit codes (matching verify-commit): 0=valid, 1=invalid, 2=error.

 Files to Create

 1. crates/auths-cli/src/commands/artifact/mod.rs

 Top-level command struct + subcommand dispatch (follows git.rs pattern).

 2. crates/auths-cli/src/commands/artifact/core.rs

 Hexagonal trait abstraction:
 pub trait ArtifactSource {
     fn digest(&self) -> Result<ArtifactDigest>;
     fn metadata(&self) -> Result<ArtifactMetadata>;
 }

 pub struct ArtifactDigest {
     pub algorithm: String,  // "sha256"
     pub hex: String,        // hex-encoded hash
 }

 pub struct ArtifactMetadata {
     pub artifact_type: String,  // "file", "docker", "npm", "cargo"
     pub digest: ArtifactDigest,
     pub name: Option<String>,
     pub size: Option<u64>,
 }
 This is the extension point. Future adapters implement ArtifactSource for their format.

 3. crates/auths-cli/src/commands/artifact/file.rs

 V1 implementation of ArtifactSource for generic files. Uses sha2::Sha256 (already a dependency) with streaming 8KB buffer
 reads.

 4. crates/auths-cli/src/commands/artifact/sign.rs

 Signing handler. Flow:

 1. Load identity via RegistryIdentityStorage::new(repo_path).load_identity() (pattern from device.rs:217-222)
 2. Load device key from platform keychain via get_platform_keychain() + load_key() (pattern from device.rs:214-270)
 3. Compute artifact digest via FileArtifact::digest()
 4. Build AttestationMetadata { timestamp, expires_at, note }
 5. Call create_signed_attestation() with artifact metadata as payload (from auths-id/src/attestation/create.rs)
 6. Set attestation.capabilities = vec![Capability::sign_release()]
 7. Call resign_attestation() to re-sign with capabilities in the envelope (from auths-id/src/attestation/core.rs:59) —
 this is critical: create_signed_attestation hardcodes capabilities to None in the signed data, so we must resign after
 setting them
 8. Write attestation JSON to <FILE>.auths.json (or --output path)

 5. crates/auths-cli/src/commands/artifact/verify.rs

 Verification handler. Flow:

 1. Load signature file (<FILE>.auths.json or --signature path)
 2. Parse Attestation from JSON
 3. Extract ArtifactMetadata from attestation.payload
 4. Compute file digest via FileArtifact::digest()
 5. Compare digests — fail fast on mismatch
 6. Resolve identity public key:
   - From --identity-bundle (stateless CI mode, pattern from verify_commit.rs:138-162)
   - Or from ~/.auths repo via RegistryIdentityStorage
 7. Verify attestation chain with capability check via verify_chain_with_capability(&chain, &Capability::sign_release(),
 &pk) (from auths-verifier/src/verify.rs)
 8. Optional witness quorum verification (pattern from verify_commit.rs, using parse_witness_keys from verify_helpers.rs)
 9. Output result (text or JSON)

 Files to Modify

 6. crates/auths-cli/src/commands/mod.rs

 Add pub mod artifact;

 7. crates/auths-cli/src/main.rs

 - Import: use commands::artifact::{ArtifactCommand, handle_artifact};
 - Commands enum: Artifact(ArtifactCommand), with doc comment
 - Match dispatch: Commands::Artifact(cmd) => handle_artifact(cmd, cli.repo, passphrase_provider)?

 Signature File Format

 The .auths.json file is a standard Attestation JSON with:
 - rid: "sha256:<hex_digest>" (content-addressed)
 - payload: ArtifactMetadata JSON (artifact_type, digest, name, size)
 - capabilities: ["sign_release"]
 - Dual-signed (identity + device) with capabilities in signed envelope

 Key Reuse Points
 ┌────────────────────────────────┬──────────────────────────────────────────┬───────────────────────────┐
 │              What              │                  Where                   │         Used For          │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ create_signed_attestation()    │ auths-id/src/attestation/create.rs       │ Create base attestation   │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ resign_attestation()           │ auths-id/src/attestation/core.rs:59      │ Re-sign with capabilities │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ verify_chain_with_capability() │ auths-verifier/src/verify.rs             │ Verify chain + capability │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ Capability::sign_release()     │ auths-verifier/src/core.rs:96            │ Well-known capability     │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ RegistryIdentityStorage        │ auths-id/src/storage/registry/           │ Load identity from repo   │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ get_platform_keychain()        │ auths-core                               │ Access platform keychain  │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ StorageSigner                  │ auths-core/src/signing.rs                │ Sign with keychain keys   │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ parse_witness_keys()           │ auths-cli/src/commands/verify_helpers.rs │ Parse witness CLI args    │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ IdentityBundle                 │ auths-verifier/src/core.rs:260           │ Stateless CI verification │
 ├────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────┤
 │ sha2::Sha256                   │ Already in Cargo.toml                    │ File hashing              │
 └────────────────────────────────┴──────────────────────────────────────────┴───────────────────────────┘
 Verification Plan

 # Build
 cargo build --package auths_cli

 # Unit tests
 cargo test --package auths_cli artifact

 # Manual end-to-end (requires identity setup)
 echo "hello" > /tmp/test-artifact.txt
 auths artifact sign /tmp/test-artifact.txt
 auths artifact verify /tmp/test-artifact.txt
 auths artifact verify /tmp/test-artifact.txt --json

 # Tamper detection
 echo "modified" > /tmp/test-artifact.txt
 auths artifact verify /tmp/test-artifact.txt  # should exit 1

 # Lint and format
 cargo fmt --check --all
 cargo clippy --all-targets --all-features -- -D warnings
