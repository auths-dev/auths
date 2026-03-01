# auths-id

Multi-device identity and attestation management for Auths.

## Features

- DID-based identity (did:keri, did:key)
- Device attestation chains
- Git-native storage under `refs/auths/`

## Usage

```rust
use auths_id::{Identity, AttestationStore};

let identity = Identity::create()?;
let store = AttestationStore::open("~/.auths")?;
store.add_attestation(&attestation)?;
```

## License

MIT OR Apache-2.0
