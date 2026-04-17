# auths-mobile-ffi

UniFFI bindings for Auths mobile identity creation (iOS/Android). Provides Swift and Kotlin entry points for device pairing, identity creation, signing, and authentication challenges — all backed by the same cryptographic protocol as the CLI and Node/Python SDKs.

> **Note:** This crate is a **standalone workspace** (`[workspace]` declared in its own `Cargo.toml`) and is **not compiled** as part of the main `cargo check --workspace` from the auths repo root. It has its own dependency tree and `Cargo.lock`.
>
> The curve-agnostic sweep (fn-121) did **not** land here. Specifically:
>
> - **Ed25519 hardcoding remains.** Functions like `create_identity`, `sign_with_identity`, `get_public_key_from_pkcs8`, `sign_auth_challenge`, and `create_pairing_response` still use `ring::signature::Ed25519KeyPair` directly and emit a hardcoded `curve: "ed25519"` on the pairing wire format. This is wrong for the target platform — iOS Secure Enclave is P-256 exclusively, and Android StrongBox supports P-256 only for EC.
>
> - **X25519 ECDH remains.** The pairing response still uses `x25519_dalek` for ephemeral key agreement. The main workspace migrated to P-256 ECDH (`p256::ecdh`); this crate has not.
>
> **To migrate**, add `auths-crypto = { path = "../auths-crypto", features = ["native"] }` as a dependency, then:
> 1. Replace `Ed25519KeyPair::from_pkcs8` / `generate_pkcs8` with `TypedSignerKey::from_pkcs8` / `generate_keypair_for_init(CurveType::default())`.
> 2. Replace `ed25519_keypair.sign(&msg)` with `typed_signer.sign(&msg)`.
> 3. Replace the hardcoded `curve: "ed25519"` literal with `typed_signer.curve().to_string()`.
> 4. Replace `x25519_dalek` ECDH with `p256::ecdh::EphemeralSecret::random(&mut OsRng)` (same swap the main pairing-protocol crate did).
> 5. Replace `generate_device_did(hex)` with `DeviceDID::from_typed_pubkey(&signer)`.
> 6. Verify with `cd crates/auths-mobile-ffi && cargo check`.
> 7. Regenerate Swift/Kotlin bindings and coordinate with the `auths-mobile` app repo.
