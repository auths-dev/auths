# Troubleshooting: Git Commit Signing

This guide covers common failures when Git calls `auths-sign` to sign commits, how to diagnose the root cause, and how to fix each issue.

## Quick Reference

| Error message | Jump to |
|---|---|
| `Agent refused to add identity` | [Agent rejects key loading](#agent-rejects-key-loading) |
| `Agent running but no keys loaded` | [Agent has no keys](#agent-running-but-no-keys-loaded) |
| `No cached pubkey for alias '...'` | [Wrong key alias](#wrong-key-alias-in-git-config) |
| `Key not found` | [Key not in keychain](#key-not-found-in-keychain) |
| `Cannot sign: no keys in agent and keychain is unavailable` | [Subprocess keychain failure](#keychain-unavailable-in-subprocess) |
| `failed to write commit object` | [General signing failure](#general-approach) |

---

## General Approach

When `git commit` fails with `fatal: failed to write commit object`, Git is telling you that `auths-sign` returned a non-zero exit code. The actual error is in the lines above it.

### Step 1: Check agent status

```bash
auths agent status
# or
auths status
```

This tells you whether the agent is running and how many keys are loaded.

### Step 2: Check which key Git is using

```bash
# Check local config first (overrides global)
git config --local user.signingkey

# Then global
git config --global user.signingkey
```

The value should be `auths:<alias>` where `<alias>` matches a key you have.

### Step 3: Check which keys you have

```bash
auths key list
```

### Step 4: Check the agent log

```bash
cat ~/.auths/agent.log
```

This shows server-side errors that may not appear in the terminal.

---

## Agent Rejects Key Loading

### Error

```
auths agent unlock --key main
Passphrase for 'main':
Failed to add key to agent: Protocol error: Agent refused to add identity
```

### Cause

The agent daemon is running an **old binary** that does not support `add_identity`. This happens after you update `auths` but the already-running agent process is still the old version.

### Debug

```bash
# Check which binary the agent process is running
ps aux | grep auths | grep agent

# Check the installed binary version
auths --version

# Check agent log for "UnsupportedCommand" errors
cat ~/.auths/agent.log | grep -i "unsupported"
```

### Fix

Restart the agent so it uses the updated binary:

```bash
auths agent stop
auths agent start
auths agent unlock --key main
```

If you built from source, make sure to install first:

```bash
cargo install --path crates/auths-cli
auths agent stop
auths agent start
auths agent unlock --key main
```

---

## Agent Running but No Keys Loaded

### Error

```
Agent running but no keys loaded
```

### Cause

The agent daemon is running but no keys have been unlocked into it. Keys are cleared when:
- The agent restarts
- The agent idle-locks after 30 minutes of inactivity
- You ran `auths agent lock`

### Debug

```bash
auths agent status
# Look for "keys loaded: 0"
```

### Fix

Unlock your key into the agent:

```bash
auths agent unlock --key main
```

You only need to do this once per session. After unlocking, all subsequent commits sign automatically via the agent without a passphrase prompt.

---

## Wrong Key Alias in Git Config

### Error

```
No cached pubkey for alias 'macbook', need passphrase
[ERROR] Cannot sign: no keys in agent and keychain is unavailable.
  Cause: Key not found

  Fix: Run these commands once, then retry your commit:
    auths agent start
    auths agent unlock --key macbook
```

### Cause

Git is configured to sign with a key alias that doesn't exist or doesn't match the key you unlocked. Common scenarios:
- You renamed or rotated your key
- A **local** `.git/config` overrides your **global** `~/.gitconfig`
- You set up signing on a different device with a different alias

### Debug

```bash
# Check BOTH local and global — local wins
git config --local user.signingkey
git config --global user.signingkey

# See what keys actually exist
auths key list
```

### Fix

Update the config to match your actual key alias:

```bash
# Fix global config
git config --global user.signingkey "auths:main"

# If local config is overriding, fix that too
git config --local user.signingkey "auths:main"

# Or remove the local override entirely so global takes effect
git config --local --unset user.signingkey
```

---

## Key Not Found in Keychain

### Error

```
[ERROR] Key not found
```

### Cause

The key alias in your git config doesn't exist in the platform keychain (macOS Keychain, Linux Secret Service, or file-based fallback).

### Debug

```bash
# List keys in the keychain
auths key list

# Check what alias git is trying to use
git config user.signingkey
```

### Fix

Either create the key or update git config to point to an existing key:

```bash
# Option A: Point git to a key that exists
auths key list                              # find the right alias
git config --global user.signingkey "auths:<alias>"

# Option B: Create a new key with the expected alias
auths key generate --alias main
```

---

## Keychain Unavailable in Subprocess

### Error

```
[ERROR] Cannot sign: no keys in agent and keychain is unavailable.
  Cause: Failed to get platform keychain: ...

  Fix: Run these commands once, then retry your commit:
    auths agent start
    auths agent unlock --key main
```

### Cause

When Git calls `auths-sign` as a subprocess, the environment may be sanitized (no TTY, restricted keychain access). This prevents both the passphrase prompt and direct keychain access from working.

This is expected behavior. The solution is to pre-load keys into the agent.

### Debug

```bash
# Verify the agent is running with keys
auths agent status

# Test signing outside of git to isolate the issue
echo "test" > /tmp/test.txt
auths-sign -Y sign -n git -f auths:main /tmp/test.txt
```

### Fix

The agent-based flow is the intended path for commit signing:

```bash
auths agent start
auths agent unlock --key main
# Now git commit signing will use the agent (no passphrase needed)
```

For CI/headless environments where no interactive passphrase prompt is possible, set `AUTHS_KEYCHAIN_BACKEND=file` and provide the passphrase via `AUTHS_PASSPHRASE`.

---

## Signing Workflow Summary

The recommended workflow for commit signing:

```bash
# One-time setup
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingkey "auths:main"
git config --global commit.gpgsign true

# Once per session (or after agent timeout)
auths agent start          # start the agent daemon
auths agent unlock --key main   # load your key (prompts for passphrase once)

# Then commit as normal — signing is automatic
git commit -m "your message"
```
