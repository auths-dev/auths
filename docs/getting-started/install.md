# Installation

## System Requirements

| Requirement | Minimum Version |
|-------------|-----------------|
| Rust        | 1.93+           |
| Git         | 2.x             |
| OS          | macOS, Linux, or Windows |

## Homebrew

```bash
brew tap auths-dev/auths-cli
brew install auths
```

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

On all platforms, auths caches your passphrase for a configurable duration (default: 1 hour) so you are not prompted on every operation. You can adjust this with [`auths config set`](../cli/commands/primary.md#auths-config-set):

```bash
auths config set passphrase.cache duration
auths config set passphrase.duration 7d
```

!!! note
    For CI or headless environments, set `AUTHS_KEYCHAIN_BACKEND=file` to use the
    encrypted file backend instead of a platform keychain.

## Shell Completions

Generate shell completions for your shell:

=== "Bash"

    ```bash
    auths completions bash > ~/.local/share/bash-completion/completions/auths
    ```

=== "Zsh"

    ```bash
    auths completions zsh > ~/.zfunc/_auths
    ```

=== "Fish"

    ```bash
    auths completions fish > ~/.config/fish/completions/auths.fish
    ```

=== "PowerShell"

    ```powershell
    auths completions powershell > $PROFILE.CurrentUserAllHosts
    ```

## Verify Installation

```bash
auths --version
```

Expected output:

```
auths 0.0.1-rc.10
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
