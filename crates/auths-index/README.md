# auths-index

SQLite-backed index for O(1) attestation lookups.

## Features

- Fast attestation queries by DID
- Persistent storage with SQLite
- Git integration for syncing

## Usage

```rust
use auths_index::AttestationIndex;

let index = AttestationIndex::open("path/to/db")?;
let attestations = index.find_by_subject("did:key:z...")?;
```

## License

MIT OR Apache-2.0
