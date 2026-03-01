# Installation

## CLI (primary)

### From source (recommended)

```bash
cargo install --git https://github.com/bordumb/auths.git auths_cli
```
Or from local repo:
```bash
cargo install --path crates/auths-cli
```

This installs three binaries:

| Binary | Purpose |
|--------|---------|
| `auths` | Main CLI for identity and key management |
| `auths-sign` | Git SSH signing program (used by `gpg.ssh.program`) |
| `auths-verify` | Signature verification tool |

### From local checkout

```bash
git clone https://github.com/bordumb/auths.git
cd auths
cargo install --path crates/auths-cli --force
```

### Verify installation

```bash
auths --version
```

Ensure `~/.cargo/bin` is in your `PATH`:

```bash
echo $PATH | grep -q ".cargo/bin" || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
```

### Run without installing

```bash
cargo run -p auths-cli -- <arguments>
```

Or set up a cargo alias in `.cargo/config.toml`:

```toml
[alias]
auths = "run -p auths-cli --"
```

Then: `cargo auths key list`

## Platform requirements

| Platform | Keychain backend | Notes |
|----------|-----------------|-------|
| macOS | Security Framework (Keychain) | Default, no extra setup |
| Linux | Secret Service (GNOME Keyring) | Or encrypted file fallback |
| Windows | Credential Manager | Requires `keychain-windows` feature |
| CI/headless | Encrypted file | Set `AUTHS_KEYCHAIN_BACKEND=file` |

## SDK installation

SDKs are for **verification only** -- they embed `auths-verifier` for your language.

=== "Python"

    ```bash
    pip install auths-verifier
    ```

=== "JavaScript"

    ```bash
    npm install @auths/verifier
    ```

=== "Go"

    ```bash
    go get github.com/auths/auths/packages/auths-verifier-go
    ```

=== "Swift"

    ```swift
    // Package.swift
    dependencies: [
        .package(url: "https://github.com/auths/auths", from: "0.1.0")
    ]
    ```

See [SDKs](../sdks/overview.md) for detailed SDK setup.
