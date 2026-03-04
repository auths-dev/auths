# Configuration

Auths stores its configuration in `~/.auths/config.toml`. This file controls how passphrase caching and authentication behave across commits and signing operations.

## Editing the Configuration

You can manage configuration using the `auths config` command or by editing the file directly.

### Using the CLI

```bash
# Set a value
auths config set <key> <value>

# Get a value
auths config get <key>

# Show full configuration
auths config show
```

### Editing the file directly

```bash
# The config file lives at:
~/.auths/config.toml
```

Example `config.toml`:

```toml
[passphrase]
cache = "always"
biometric = true
```

If the file doesn't exist, Auths uses sensible defaults. Running any `auths config set` command will create it.

---

## Passphrase Caching

Every `git commit` invokes `auths-sign`, which needs your passphrase to decrypt the signing key. The `passphrase.cache` setting controls how often you're prompted.

### `passphrase.cache`

| Value | Behavior |
|------------|----------|
| `session` | **(default)** Passphrase is held in the agent's memory. You're prompted once per agent lifetime. Restarting the agent or your machine clears it. |
| `always` | Passphrase is stored in the OS keychain (macOS Keychain, Linux Secret Service). You're prompted once, then never again until you clear it. |
| `duration` | Like `always`, but the cached passphrase expires after a configurable time window. |
| `never` | Always prompt interactively. No caching of any kind. |

```bash
auths config set passphrase.cache always
auths config set passphrase.cache session
auths config set passphrase.cache duration
auths config set passphrase.cache never
```

### `passphrase.duration`

Only used when `cache = "duration"`. Sets how long the cached passphrase remains valid.

Supported formats: `7d` (days), `24h` (hours), `30m` (minutes), `3600s` or `3600` (seconds).

```bash
auths config set passphrase.cache duration
auths config set passphrase.duration 7d
```

If not set, defaults to `24h`.

### Environment variable override

Setting `AUTHS_PASSPHRASE` bypasses all caching and prompts. This is intended for CI/CD environments.

```bash
AUTHS_PASSPHRASE=my-secret git commit -m "automated commit"
```

---

## Platform-Specific Behavior

### macOS

#### Touch ID (`passphrase.biometric`)

When `passphrase.cache` is set to `always` or `duration`, macOS can protect the cached passphrase with Touch ID. On subsequent commits, macOS presents a Touch ID dialog instead of a text passphrase prompt.

| Value | Behavior |
|-------|----------|
| `true` | **(default on macOS)** Cached passphrase requires Touch ID or device passcode to access. |
| `false` | Cached passphrase is returned silently from the keychain without biometric verification. |

```bash
# Enable Touch ID (default)
auths config set passphrase.biometric true

# Disable Touch ID, use silent keychain access
auths config set passphrase.biometric false
```

The passphrase is stored in macOS Keychain under the service name `dev.auths.passphrase`. You can inspect it in Keychain Access.app.

**Requirements:**
- Touch ID must be enrolled on the device
- If Touch ID is unavailable, macOS falls back to the device passcode

### Linux

When `passphrase.cache` is set to `always` or `duration`, Linux stores the passphrase via the [freedesktop.org Secret Service API](https://specifications.freedesktop.org/secret-service/latest/). This works with:

- GNOME Keyring
- KWallet
- KeePassXC (with Secret Service integration enabled)

The `passphrase.biometric` setting is ignored on Linux.

**Requirements:**
- The `keychain-linux-secretservice` feature must be enabled at compile time.
- A Secret Service provider must be running (most desktop environments include one).

### Windows

Passphrase caching via the OS credential store is not yet implemented on Windows. The `session` and `never` modes work normally.

---

## Configuration Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `passphrase.cache` | `always` \| `session` \| `duration` \| `never` | `session` | How passphrases are cached between signing operations. |
| `passphrase.duration` | string (e.g. `7d`, `24h`) | `24h` | TTL for cached passphrase. Only used with `cache = "duration"`. |
| `passphrase.biometric` | `true` \| `false` | `true` on macOS, `false` elsewhere | Protect cached passphrase with Touch ID on macOS. |
