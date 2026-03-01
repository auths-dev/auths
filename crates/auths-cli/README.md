# Auths CLI

A command-line interface for managing Auths identities. It allows you to:

* Create and manage identities stored within Git repositories.
* Securely store and manage associated private keys in your platform's keychain or secure storage.
* Link multiple devices (each with their own key) to your identity via cryptographic attestations stored in the Git repository.
* Configure the Git storage layout for identity and attestations to interoperate with different systems (like Radicle) or use your own conventions.

## 🚀 Installation

### From Source

Ensure you have Rust and Cargo installed.

```bash
# Clone the repository (if you haven't already)
# git clone <repo-url>
# cd <repo-name>
```

# Install the CLI binary
cargo install --path crates/auths-cli --force

This installs the auths binary to your $CARGO_HOME/bin (typically ~/.cargo/bin). Make sure this directory is in your system's PATH:

# Example for zsh/bash: Check and add if missing
```bash
echo $PATH | grep -q ".cargo/bin" || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
```
# Remember to source your shell profile (e.g., source ~/.zshrc) or open a new terminal

Run Without Installing (from workspace root)

cargo run -p auths-cli -- <auths arguments...>

You can also set up a cargo alias in your workspace's .cargo/config.toml for convenience:
```toml
# .cargo/config.toml
[alias]
auths = "run -p auths-cli --"
```

Then run commands like: `cargo auths key list`.

## 🔑 Core Concepts
### Identity Repository
A Git repository that stores the history and state of your Auths identity.

### Identity Commit
A specific commit (referenced by identity-ref, e.g., refs/auths/identity or rad/id) contains a blob (identity-blob, e.g., identity.json or radicle-identity.json) storing the Controller DID and arbitrary Metadata.

### Device Attestation
Commits stored under specific Git references (prefixed by attestation-prefix, e.g., `refs/auths/devices/nodes/...` or `refs/rad/multidevice/nodes/...`) linking device keys/DIDs to the main identity.

These contain attestation-blob files (e.g., `attestation.json`).

### Local Keychain/Secure Storage
Your platform's secure storage (e.g., macOS Keychain, iOS Keychain, Linux Secret Service, file-based fallback) is used to store the encrypted private keys associated with your Controller DID and any linked device DIDs you manage locally. Each stored key has a unique local alias.

### Configurable Layout
Auths doesn't enforce a single Git layout. You can use the default layout or specify a custom one (like Radicle's) using global command-line flags:
```bash
--repo <PATH>: Path to the Git repository directory. (Defaults to ~/.auths)

--identity-ref <GIT_REF>: Reference for the identity commit (Default: refs/auths/identity).

--identity-blob <FILENAME>: Blob name for identity data (Default: identity.json).

--attestation-prefix <GIT_REF_PREFIX>: Base ref prefix for device attestations (Default: refs/auths/devices/nodes).

--attestation-blob <FILENAME>: Blob name for attestation data (Default: attestation.json).
```

## 🛠 Usage

**Note:** Commands interacting with encrypted keys (`id init-did`, `key import`, `key export`, `device link`, `device revoke`, `device extend`) will prompt for passphrases when needed.

### Workflow 1: Default Layout

This workflow uses the default Git layout settings (`refs/auths/identity`, etc.) within the default `~/.auths` repository path.

1.  **Initialize a new Identity & Repository:**
    * Create a metadata file (e.g., `~/my_metadata.json`):

        ```json
        {
          "name": "My Default Identity",
          "email": "user@example.com"
        }
        ```

    * Run `id init-did`. This creates `~/.auths`, initializes it as a Git repo, generates a keypair, stores it locally under the alias `my_id_key`, derives the `controller_did`, and creates the identity commit using the metadata file.

        ```bash
        auths id init-did --metadata-file ~/my_metadata.json --local-key-alias my_id_key
        # Enter a strong passphrase when prompted
        ```

2.  **Verify Identity and Key:**

    ```bash
    # Check local keychain storage
    auths key list
    # Expected output includes: - my_id_key

    # Show identity details from the Git repo
    auths id show
    # Note the Controller DID output, e.g., did:keri:E...
    # Verify metadata is shown
    ```

3.  **Import a Device Key (from seed):**
    * Assume you have a 32-byte seed file `~/device_key.seed`.
    * Get the Controller DID from `auths id show`.
    * Import the seed, associating it with the Controller DID.

        ```bash
        CONTROLLER_DID=$(auths id show | grep 'Controller DID:' | awk -F': ' '{print $2}')
        auths key import --alias my_device1_key --seed-file ~/device_key.seed --controller-did "$CONTROLLER_DID"
        # Enter a strong passphrase for the device key when prompted
        ```

    * Verify the new key:

        ```bash
        auths key list
        # Expected output includes: - my_id_key, - my_device1_key
        ```

4.  **Link the Device:**
    * Derive the device DID:

        ```bash
        # Ensure xxd is installed or use another tool for hex conversion
        DEVICE_DID=$(auths util derive-did --seed-hex $(xxd -p -c 256 ~/device_key.seed) | awk '{print $3}')
        ```

    * Run `device link`. This creates a signed attestation in `~/.auths`.

        ```bash
        auths device link \
          --identity-key-alias my_id_key \
          --device-key-alias my_device1_key \
          --device-did "$DEVICE_DID" \
          --note "My Laptop Key" \
          --expires-in-days 90
        # Enter device passphrase, then identity passphrase, then device passphrase again when prompted
        ```

5.  **Verify Device Link:**

    ```bash
    auths id show-devices
    # Expected output shows the linked device as active with note/expiry
    ```

6.  **Export Keys (Example):**

    ```bash
    # Export identity's public key
    auths key export --alias my_id_key --format pub
    # Enter passphrase for my_id_key

    # Export device's private key (PEM)
    auths key export --alias my_device1_key --format pem
    # Enter passphrase for my_device1_key
    ```

7.  **Revoke Device (Example):**

    ```bash
    auths device revoke --identity-key-alias my_id_key --device-did "$DEVICE_DID" --note "Laptop retired"
    # Enter passphrase for my_id_key
    ```

    * Verify revocation:

        ```bash
        auths id show-devices # Device should be gone
        auths id show-devices --include-revoked # Device should show as revoked
        ```

8.  **Delete Local Keys:**

    ```bash
    auths key delete --alias my_device1_key
    auths key delete --alias my_id_key
    ```

### Workflow 2: Custom Layout (Radicle Example)

This workflow achieves a Radicle-compatible layout by specifying layout flags for relevant commands.

1.  **Initialize with Radicle Layout:**
    * Create metadata (e.g., `~/radicle_meta.json`):

        ```json
        {
          "xyz.radicle.agent": {"alias": "my_rad_alias", "controller": ""},
          "profile": {"name": "Radicle User"}
        }
        ```

    * Run `id init-did` specifying the repo path and all layout flags:

        ```bash
        RAD_REPO_PATH="$HOME/my_radicle_identity_repo"
        auths id init-did \
          --repo "$RAD_REPO_PATH" \
          --identity-ref "refs/rad/id" \
          --identity-blob "radicle-identity.json" \
          --attestation-prefix "refs/rad/multidevice/nodes" \
          --attestation-blob "link-attestation.json" \
          --metadata-file ~/radicle_meta.json \
          --local-key-alias radicle_id_key
        # Enter passphrase
        ```

2.  **Verify (using flags):**

    ```bash
    # List key (no flags needed)
    auths key list | grep radicle_id_key

    # Show identity (MUST provide layout flags to find it)
    auths id show \
      --repo "$RAD_REPO_PATH" \
      --identity-ref "refs/rad/id" \
      --identity-blob "radicle-identity.json" \
      --attestation-prefix "refs/rad/multidevice/nodes" \
      --attestation-blob "link-attestation.json"
    # Note Controller DID, check metadata
    ```

3.  **Import Device Key (as before):**

    ```bash
    # Get Controller DID using flags
    CONTROLLER_DID=$(auths id show --repo "$RAD_REPO_PATH" --identity-ref "refs/rad/id" --identity-blob "radicle-identity.json" --attestation-prefix "refs/rad/multidevice/nodes" --attestation-blob "link-attestation.json" | grep 'Controller DID:' | awk -F': ' '{print $2}')
    auths key import --alias rad_device_key --seed-file ~/rad_device.seed --controller-did "$CONTROLLER_DID"
    # Enter passphrase
    ```

4.  **Link Device (using flags):**
    * Derive device DID as before.
    * Run `device link` providing all layout flags:

        ```bash
        # Ensure xxd is installed or use another tool for hex conversion
        DEVICE_DID=$(auths util derive-did --seed-hex $(xxd -p -c 256 ~/rad_device.seed) | awk '{print $3}')
        auths device link \
          --repo "$RAD_REPO_PATH" \
          --identity-ref "refs/rad/id" \
          --identity-blob "radicle-identity.json" \
          --attestation-prefix "refs/rad/multidevice/nodes" \
          --attestation-blob "link-attestation.json" \
          --identity-key-alias radicle_id_key \
          --device-key-alias rad_device_key \
          --device-did "$DEVICE_DID" \
          --note "Radicle Laptop Key"
        # Enter passphrases (Device, Identity, Device)
        ```

5.  **Verify Device Link (using flags):**

    ```bash
    auths id show-devices \
      --repo "$RAD_REPO_PATH" \
      --identity-ref "refs/rad/id" \
      --identity-blob "radicle-identity.json" \
      --attestation-prefix "refs/rad/multidevice/nodes" \
      --attestation-blob "link-attestation.json"
    # Check for linked device
    ```

### Other Commands

* **Rotate Identity Keys:**

    Auths uses KERI with pre-rotation commitment, allowing secure key rotation while preserving your identity (DID).

    ```bash
    # Rotate keys using the current alias
    auths id rotate --alias my_id_key
    # Enter passphrase when prompted
    # New key is stored as my_id_key-rotated-<timestamp>

    # Or specify a custom alias for the new key
    auths id rotate --alias my_id_key --next-key-alias my_id_key_v2
    ```

    After rotation:
    - Your `did:keri:E...` remains the same
    - The new key becomes active for signing
    - Historical signatures verify against the key state at signing time
    - The Key Event Log (KEL) records the rotation

* **Derive DID from Seed:**

    ```bash
    # Create a 32-byte seed file (replace with your actual seed)
    head -c 32 /dev/urandom > my_seed.raw
    # Derive and print the did:key
    auths util derive-did --seed-hex $(xxd -p -c 256 my_seed.raw)
    ```

## CI Setup (GitHub Actions)

`auths init --profile ci` creates an ephemeral in-memory identity scoped to the
current run — no platform keychain required, no secrets to rotate, no state left
behind after the job ends.

### Signing commits in CI

```yaml
name: Signed Commits

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      AUTHS_KEYCHAIN_BACKEND: memory   # No platform keychain in CI
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install Auths
        run: cargo install --path crates/auths-cli --force

      - name: Set up Auths (CI profile)
        run: auths init --profile ci --non-interactive

      - name: Run doctor (verify setup)
        run: auths doctor

      # All subsequent git commits are signed automatically because
      # auths init --profile ci sets gpg.format=ssh globally.
      - name: Your build step
        run: cargo build --release
```

### Verifying commit signatures in CI (no signing needed)

```yaml
name: Verify Commit Signatures

on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history required for range verification

      - name: Install Auths
        run: cargo install --path crates/auths-cli --force

      - name: Verify commits on this PR
        run: auths verify-commit HEAD
```

### Troubleshooting CI

Run `auths doctor` as the first step in any failing job.
Exit code 0 = all checks pass. Exit code 1 = at least one check failed.
