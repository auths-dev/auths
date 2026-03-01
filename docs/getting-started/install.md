# Installation

## System Requirements

| Requirement | Minimum Version |
|-------------|-----------------|
| Rust        | 1.93+           |
| Git         | 2.x             |
| OS          | macOS, Linux, or Windows |

## From Cargo

The recommended way to install Auths is via `cargo install`:

```bash
cargo install auths-cli
```

This installs three binaries:

| Binary | Purpose |
|--------|---------|
| `auths` | Main CLI for identity and key management |
| `auths-sign` | Git SSH signing program (used by `gpg.ssh.program`) |
| `auths-verify` | Signature verification tool |

!!! tip
    Make sure `~/.cargo/bin` is in your `PATH`. Most Rust installations add this automatically.

## From Source

```bash
git clone https://github.com/auths-dev/auths.git
cd auths
cargo install --path crates/auths-cli
```

Use `--force` to overwrite a previous installation:

```bash
cargo install --path crates/auths-cli --force
```

### Run without installing

You can also run directly from the source tree without installing:

```bash
cargo run -p auths-cli -- <arguments>
```

Or set up a cargo alias in `.cargo/config.toml`:

```toml
[alias]
auths = "run -p auths-cli --"
```

Then: `cargo auths key list`

## Pre-built Binaries

Pre-built binaries for macOS, Linux, and Windows are available on the
[GitHub Releases](https://github.com/auths-dev/auths/releases) page.

## Platform Keychain Support

=== "macOS"

    Uses the system Security Framework (Keychain). No extra setup required.

=== "Linux"

    Uses Secret Service (GNOME Keyring) by default. Falls back to an encrypted file if
    Secret Service is unavailable.

=== "Windows"

    Uses the Windows Credential Manager. Requires the `keychain-windows` feature:

    ```bash
    cargo install auths-cli --features keychain-windows
    ```

!!! note
    For CI or headless environments, set `AUTHS_KEYCHAIN_BACKEND=file` to use the
    encrypted file backend instead of a platform keychain.

## Shell Completions

Shell completions are planned for a future release.

## Verify Installation

```bash
auths --version
```

Expected output:

```
auths 0.0.1-rc.5
```

!!! tip
    If `auths` is not found, ensure `~/.cargo/bin` is on your `PATH`:

    === "macOS / Linux"

        ```bash
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
        source ~/.zshrc
        ```

    === "Windows"

        Cargo's installer typically adds `%USERPROFILE%\.cargo\bin` to your `PATH`
        automatically. If not, add it manually via **System Properties > Environment Variables**.
