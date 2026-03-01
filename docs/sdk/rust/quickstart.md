# Quickstart

## Installation

Add `auths-sdk` to your project:

```bash
cargo add auths-sdk
```

For verification-only use cases (servers, CI validators), you can use the lighter `auths-verifier` crate instead:

```bash
cargo add auths-verifier
```

## Minimal Example: Developer Identity Setup

This example provisions a new developer identity, links a device, and configures Git commit signing.

```rust
use std::sync::Arc;
use auths_sdk::context::AuthsContext;
use auths_sdk::setup::{setup_developer, quick_setup};
use auths_sdk::types::{DeveloperSetupConfig, GitSigningScope};
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
use auths_core::signing::{StorageSigner, PrefilledPassphraseProvider};
use auths_core::ports::clock::SystemClock;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize platform keychain and infrastructure adapters
    let keychain = get_platform_keychain()?;
    let keychain_arc: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);

    // 2. Build the runtime context with all required adapters
    let ctx = AuthsContext::builder()
        .registry(/* your RegistryBackend */)
        .key_storage(Arc::clone(&keychain_arc))
        .clock(Arc::new(SystemClock))
        .identity_storage(/* your IdentityStorage */)
        .attestation_sink(/* your AttestationSink */)
        .attestation_source(/* your AttestationSource */)
        .build();

    // 3. Create a signer backed by the keychain
    let signer = StorageSigner::new(Arc::clone(&keychain_arc));
    let passphrase_provider = PrefilledPassphraseProvider::new("my-secure-passphrase");

    // 4. Configure and run developer setup
    let alias = KeyAlias::new("work-laptop")?;
    let config = DeveloperSetupConfig::builder(alias.clone())
        .with_git_signing_scope(GitSigningScope::Global)
        .build();

    let result = setup_developer(
        config,
        &ctx,
        keychain_arc.as_ref(),
        &signer,
        &passphrase_provider,
        None, // no git config provider in this example
    )?;

    println!("Identity DID: {}", result.identity_did);
    println!("Device DID:   {}", result.device_did);
    println!("Key alias:    {}", result.key_alias);

    Ok(())
}
```

## Quick Setup (One-Liner)

For the common case of creating a developer identity with sensible defaults (global Git signing, no platform verification, no registry):

```rust
use auths_sdk::setup::quick_setup;
use auths_core::storage::keychain::KeyAlias;

let alias = KeyAlias::new("main")?;
let result = quick_setup(&alias, &ctx, keychain.as_ref(), &signer, &provider)?;
```

## Verification-Only Example

If you only need to verify attestation chains (e.g., in a CI pipeline or server):

```rust
use auths_verifier::{verify_chain, VerificationStatus, VerificationReport};

let report: VerificationReport = verify_chain(&attestations, &root_public_key).await?;

match report.status {
    VerificationStatus::Valid => println!("Chain verified successfully"),
    VerificationStatus::Expired { at } => println!("Chain expired at {}", at),
    VerificationStatus::Revoked { at } => println!("Chain revoked at {:?}", at),
    VerificationStatus::InvalidSignature { step } => {
        println!("Invalid signature at chain step {}", step);
    }
    VerificationStatus::BrokenChain { missing_link } => {
        println!("Broken chain: {}", missing_link);
    }
    VerificationStatus::InsufficientWitnesses { required, verified } => {
        println!("Need {} witnesses, only {} verified", required, verified);
    }
}
```

## CI/Ephemeral Identity Setup

For automated pipelines that need an ephemeral signing identity:

```rust
use auths_sdk::setup::setup_ci;
use auths_sdk::types::{CiSetupConfig, CiEnvironment};
use std::path::PathBuf;

let config = CiSetupConfig {
    ci_environment: CiEnvironment::GitHubActions,
    passphrase: std::env::var("AUTHS_PASSPHRASE").unwrap(),
    registry_path: PathBuf::from("/tmp/.auths"),
    keychain: Box::new(memory_keychain),
};

let result = setup_ci(config, &ctx)?;
println!("CI identity: {}", result.identity_did);
for line in &result.env_block {
    println!("{line}");
}
```

## What's Next

- [Identity Operations](identity-operations.md) -- init, register, attest, rotate
- [Signing and Verification](signing-and-verification.md) -- `SecureSigner`, `verify_chain()`, `verify_with_keys()`
- [Error Handling](error-handling.md) -- domain error types and recovery patterns
- [Storage Backends](storage-backends.md) -- Git backend and custom trait implementations
