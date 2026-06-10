# Reset & Uninstall

## Reset (keep the binary, remove your data)

```bash
auths reset --force
```

This removes:

- `~/.auths` — your identity repository, key event logs, and the commit hook directory
- The git signing configuration Auths set (`gpg.format`, `gpg.ssh.program`,
  `user.signingKey`, `commit.gpgSign`, `core.hooksPath`)

Without `--force` you get a confirmation prompt.

!!! warning "This deletes your identity"
    There is no recovery for a deleted identity unless you have a backup of `~/.auths`
    **and** the keychain entries. Commits you signed remain signed (signatures live in
    the commits), but you lose the ability to sign as that identity again. See
    [Backup & Recovery](../guides/identity/backup-and-recovery.md) first.

Keychain entries are platform-managed; if any remain after reset, remove them with
`auths key delete --key-alias <alias>` *before* resetting, or via your OS keychain UI
(items are stored under the key alias names, e.g. `main`).

## Uninstall the binary

=== "Homebrew"

    ```bash
    brew uninstall auths
    brew untap auths-dev/auths-cli
    ```

=== "Cargo"

    ```bash
    cargo uninstall auths-cli
    ```

=== "Installer script"

    ```bash
    rm "$(which auths)" "$(which auths-sign)" "$(which auths-verify)"
    ```

## What stays behind

- Commits signed with Auths keep their signatures and trailers — that's the point;
  they remain verifiable by anyone with your event log or a bundle you exported.
- A repo's committed `.auths/roots` file is part of that repo's history; remove your
  line and commit if you want the trust grant withdrawn going forward.
