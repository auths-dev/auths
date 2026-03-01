# Runbook: Sign and Publish Release Artifacts

Sign release tarballs with `auths artifact sign` and upload them to a GitHub release.

---

## Prerequisites

### Tools

| Tool | Check | Install |
|------|-------|---------|
| Rust toolchain | `rustc --version` | `rustup update` |
| GitHub CLI | `gh --version` | `brew install gh` |
| `gh` authenticated | `gh auth status` | `gh auth login` |

### Auths identity

You need a cryptographic identity before you can sign anything. If `auths id show`
already works, skip this section.

```bash
# Install the CLI from source
cargo install --path crates/auths-cli

# Initialize your identity (interactive wizard)
auths init
```

This generates an Ed25519 keypair, stores it in your platform keychain, and creates
the `~/.auths` Git repo. The default key alias is `main`.

Verify it worked:

```bash
auths id show       # shows your DID
auths key list      # shows key aliases (you need at least "main")
```

---

## Sign and publish a release

### 1. Build release binaries

```bash
cargo build --release
```

### 2. Create a tarball

Package the three CLI binaries. Adjust the architecture in the filename to match your
machine.

```bash
tar -czf auths-aarch64-apple-darwin.tar.gz \
  -C target/release auths auths-sign auths-verify
```

### 3. Sign the tarball

```bash
auths artifact sign auths-aarch64-apple-darwin.tar.gz \
  --identity-key-alias main \
  --device-key-alias main
```

You'll be prompted for your passphrase. This creates
`auths-aarch64-apple-darwin.tar.gz.auths.json` next to the tarball.

### 4. Create the GitHub release

```bash
gh release create v0.0.1-rc.9 \
  --title "v0.0.1-rc.9" \
  --notes "Artifact signing" \
  --prerelease
```

### 5. Upload the tarball and signature

```bash
gh release upload v0.0.1-rc.9 \
  auths-aarch64-apple-darwin.tar.gz \
  auths-aarch64-apple-darwin.tar.gz.auths.json
```

### 6. Verify the release page

```bash
gh release view v0.0.1-rc.9
```

The release should list both the `.tar.gz` and the `.auths.json`.

---

## How users verify a download

After downloading a tarball and its `.auths.json` from the release page:

```bash
# Basic verification
auths artifact verify auths-aarch64-apple-darwin.tar.gz \
  --signature auths-aarch64-apple-darwin.tar.gz.auths.json

# JSON output (for scripting / CI)
auths artifact verify auths-aarch64-apple-darwin.tar.gz \
  --signature auths-aarch64-apple-darwin.tar.gz.auths.json \
  --json

# Stateless verification with an identity bundle (no ~/.auths needed)
auths artifact verify auths-aarch64-apple-darwin.tar.gz \
  --signature auths-aarch64-apple-darwin.tar.gz.auths.json \
  --identity-bundle identity-bundle.json
```

Exit codes: `0` = valid, `1` = invalid, `2` = error.

---

## Troubleshooting

### "Failed to load identity"

Run `auths init` (see Prerequisites above).

### "Failed to load device key 'main'"

Your key alias doesn't match. Check with `auths key list` and use the correct alias.

### "unrecognized subcommand 'artifact'"

Your installed `auths` binary is outdated. Reinstall from source:

```bash
cargo install --path crates/auths-cli
```

### Stale `refs/authly/registry` ref

If you initialized with an older version that used the `authly` name, wipe and
re-initialize:

```bash
rm -rf ~/.auths
security delete-generic-password -s "dev.auths.agent" -a "main" 2>/dev/null
security delete-generic-password -s "dev.auths.agent" -a "main--next-0" 2>/dev/null
auths init
```

### `--output` clap panic

The global `--output` flag conflicts with the artifact subcommand. Use `--sig-output`
instead if you need a custom output path:

```bash
auths artifact sign file.tar.gz \
  --identity-key-alias main \
  --device-key-alias main \
  --sig-output custom-path.auths.json
```
