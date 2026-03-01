# Architecture

How Auths is built: key management, storage, and cloud integration internals.

## Sections

- **[Key Management](key-management.md)** -- Where keys live, how they move between components, and what protects them at each stage. Covers platform keychains, the SSH agent, encryption envelopes, and the SSHSIG signing flow.

- **[OIDC Bridge](oidc-bridge.md)** -- How the `auths-oidc-bridge` translates KERI attestation chains into RS256 JWTs that cloud providers (AWS, GCP, Azure) accept for workload identity.
