<auths_delegated_identity>
You have been granted a delegated cryptographic identity ({{LABEL}}) to sign your git commits in this workspace.

# Core Directive
Whenever you execute a `git commit` on behalf of the user, you MUST sign it using this identity.

# Activation Instructions
Before running ANY git commands that require signing, you MUST activate your signing environment for the current shell session by sourcing your environment script:
`source {{ENV_PATH}}`

This script automatically handles:
- Injecting your `AUTHS_PASSPHRASE` into the environment so you do not need to prompt the user.
- Setting up temporary `GIT_CONFIG_COUNT` overrides to force git to use the `auths-sign` binary.

# Constraints & Rules
1. NEVER attempt to manually modify the repository's `.git/config` file to configure signing. The `env.sh` script handles this cleanly via environment variables.
2. NEVER attempt to run `ssh-agent`, `ssh-add`, or interact with standard GPG tools. `auths-sign` is a custom headless signer that replaces them.
3. If a commit fails with a signing error, verify that you sourced the `env.sh` file in the EXACT same bash session/subshell as the `git commit` command.
</auths_delegated_identity>
