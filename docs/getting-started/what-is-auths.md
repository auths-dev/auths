# What is Auths?

Auths is a decentralized identity system for developers. It solves a specific problem: **proving who signed a commit, across devices, without a central authority.**

## The problem

Developers sign code. But current signing tools have friction:

- **GPG** requires manual key management, backup, and distribution. It was designed for email encryption in the 1990s.
- **SSH signing** (Git 2.34+) works per-key, but doesn't connect multiple devices to a single identity.
- **Blockchain-based identity** adds latency, cost, and infrastructure you don't need.

## What Auths provides

**One identity, multiple devices, Git-native storage.**

1. **Identity**: A stable `did:keri:E...` identifier derived from your Ed25519 root key. This is your cryptographic identity. It survives key rotation.

2. **Devices**: Each machine (laptop, phone, CI server) gets its own `did:key:z6Mk...` identifier. Devices are linked to your identity via signed attestations.

3. **Attestations**: JSON documents signed by both the identity key and the device key. They prove that a specific device is authorized to act on behalf of your identity.

4. **Git storage**: Everything is stored as Git refs under `refs/auths/`. No database, no server, no blockchain. Just Git.

5. **Verification**: A minimal-dependency verifier (`auths-verifier`) that can run anywhere -- Rust, Python, JavaScript (WASM), Go, Swift, Kotlin. Verify attestation chains without needing the signer's Git repo.

## What Auths is not

- **Not an SSH agent** (though it integrates with `ssh-agent`)
- **Not a certificate authority** -- there's no hierarchy to trust
- **Not a blockchain** -- Git provides the tamper-evident log
- **Not a replacement for all of GPG** -- Auths doesn't do email encryption or file encryption

## Who it's for

- Developers who sign commits and want multi-device identity
- Teams that need to verify commit authorship in CI
- Projects that embed signature verification in their applications
- Mobile apps that create on-device identities (via Swift/Kotlin bindings)
