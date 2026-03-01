# auths-core

Core cryptography and keychain integration for Auths.

## Features

- Ed25519 key generation and signing
- Platform keychain support (macOS, Linux, Windows)
- Secure key storage with encryption

## Platform Support

- macOS/iOS: Security Framework
- Linux: Secret Service (optional)
- Windows: Credential Manager (optional)

## Usage

```rust
use auths_core::{Keychain, KeyPair};

let keychain = Keychain::new()?;
let keypair = KeyPair::generate()?;
keychain.store("my-key", &keypair)?;
```

## License

MIT OR Apache-2.0
