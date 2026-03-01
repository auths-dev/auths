# auths-policy

Policy expression engine for Auths - composable authorization logic.

## Features

- Declarative policy expressions
- Capability-based access control
- JSON serialization

## Usage

```rust
use auths_policy::{Policy, PolicyBuilder};

let policy = PolicyBuilder::new()
    .require_capability("commit:sign")
    .build();
```

## License

MIT OR Apache-2.0
