# Key Management Architecture

This document explains where keys and passphrases physically live, how they move between components, and what security properties protect them at each stage.

## Overview

Auths uses a layered architecture for key management. Private keys are encrypted at rest in platform keychains, decrypted only when needed, and held in agent memory wrapped in zeroizing buffers. Passphrases never leave the user's terminal and are never stored.

```mermaid
graph TB
    subgraph "At Rest (Encrypted)"
        KC["Platform Keychain<br/><small>macOS Keychain / Linux Secret Service /<br/>Windows Credential Manager / Encrypted File</small>"]
    end

    subgraph "In Transit"
        PP["Passphrase<br/><small>entered via /dev/tty</small>"]
        SOCK["Unix Socket<br/><small>~/.auths/agent.sock</small>"]
    end

    subgraph "In Memory (Decrypted)"
        AGENT["Agent Process<br/><small>HashMap&lt;pubkey, Zeroizing&lt;PKCS#8&gt;&gt;</small>"]
    end

    subgraph "Output"
        SIG["SSHSIG Signature<br/><small>&lt;buffer&gt;.sig</small>"]
    end

    PP -->|"Argon2id KDF"| KC
    KC -->|"decrypt with passphrase"| AGENT
    AGENT -->|"Ed25519 sign over socket"| SIG
    SOCK ---|"SSH agent protocol"| AGENT
```

## Key Lifecycle

Every Ed25519 key goes through four phases. This diagram shows the physical locations and transformations at each phase.

```mermaid
flowchart TD
    subgraph phase1["Phase 1: Key Generation"]
        U1["User runs:<br/>auths key generate --alias main"]
        G1["CLI generates Ed25519 keypair<br/>(ring PKCS#8)"]
        P1["User enters passphrase<br/>(via /dev/tty)"]
        K1["Argon2id KDF derives 256-bit key<br/>salt: 16 random bytes<br/>m_cost: 64 MiB, t_cost: 3, p_cost: 1"]
        E1["CLI encrypts PKCS#8<br/>with AES-GCM or ChaCha20-Poly1305"]
        S1["Store encrypted blob + DID<br/>in platform keychain"]
        Z1["Passphrase dropped,<br/>PKCS#8 plaintext zeroized"]
        U1 --> G1 --> P1 --> K1 --> E1 --> S1 --> Z1
    end

    subgraph phase2["Phase 2: Agent Unlock (once per session)"]
        U2["User runs:<br/>auths agent unlock --key main"]
        L2["CLI loads encrypted blob<br/>from keychain"]
        P2["User enters passphrase<br/>(via /dev/tty)"]
        D2["Argon2id re-derives symmetric key"]
        X2["CLI decrypts to PKCS#8 bytes"]
        A2["add_identity over Unix socket"]
        M2["Agent stores key as<br/>Zeroizing Vec in HashMap"]
        U2 --> L2 --> P2 --> D2 --> X2 --> A2 --> M2
    end

    subgraph phase3["Phase 3: Signing (passphrase-free)"]
        G3["Git calls: auths-sign<br/>-Y sign -n git -f auths:main"]
        R3["CLI sends sign request<br/>over Unix socket"]
        S3["Agent signs with<br/>Ed25519KeyPair::from_pkcs8"]
        W3["CLI wraps 64-byte signature<br/>in SSHSIG PEM format"]
        F3["Git reads buffer.sig,<br/>embeds in commit object"]
        G3 --> R3 --> S3 --> W3 --> F3
    end

    subgraph phase4["Phase 4: Cleanup"]
        I4["30min idle timeout reached<br/>or auths agent lock"]
        C4["lock_agent calls<br/>core.clear_keys"]
        Z4["All keys zeroized<br/>via Zeroizing::drop"]
        I4 --> C4 --> Z4
    end

    phase1 --> phase2
    phase2 --> phase3
    phase3 --> phase4
```

## Encryption Envelope

When a key is stored in the keychain, the raw PKCS#8 bytes are encrypted into a self-describing binary envelope. The envelope contains everything needed for decryption except the passphrase.

```mermaid
block-beta
    columns 8

    block:header:1
        TAG["0x03<br/>Argon2"]
    end
    block:salt:2
        SALT["Salt<br/>16 bytes (random)"]
    end
    block:params:3
        M["m_cost<br/>4B LE<br/>65536"]
        T["t_cost<br/>4B LE<br/>3"]
        P["p_cost<br/>4B LE<br/>1"]
    end
    block:alg:1
        ALG["algo<br/>0x01=AES<br/>0x02=ChaCha"]
    end
    block:nonce:1
        NONCE["Nonce<br/>12 bytes"]
    end
    block:ct:8
        CT["Ciphertext + 16-byte AEAD auth tag<br/>(encrypted PKCS#8 key bytes)"]
    end

    style header fill:#8b4049,color:#f0e0e0
    style salt fill:#3d6a8a,color:#d8e8f0
    style params fill:#3d7a5a,color:#d8f0e0
    style alg fill:#6b4a7a,color:#e0d8f0
    style nonce fill:#8a6a30,color:#f0e8d0
    style ct fill:#4a5568,color:#e2e8f0
```

**Source**: `crates/auths-core/src/crypto/encryption.rs`

| Field | Size | Purpose |
|-------|------|---------|
| Tag | 1 byte | `0x03` = Argon2id envelope (legacy: `0x01`/`0x02` = HKDF) |
| Salt | 16 bytes | Random, per-encryption |
| m_cost | 4 bytes (LE) | Argon2id memory: 64 MiB |
| t_cost | 4 bytes (LE) | Argon2id iterations: 3 |
| p_cost | 4 bytes (LE) | Argon2id parallelism: 1 |
| Algo tag | 1 byte | `0x01` = AES-GCM-256, `0x02` = ChaCha20-Poly1305 |
| Nonce | 12 bytes | Random, per-encryption |
| Ciphertext | variable | Encrypted PKCS#8 + 16-byte AEAD authentication tag |

**Security properties**:

- Argon2id parameters follow OWASP recommendations (64 MiB memory makes GPU attacks expensive)
- Unique salt and nonce per encryption prevent rainbow tables and nonce reuse
- AEAD authentication tag detects tampering (wrong passphrase returns `IncorrectPassphrase`, not garbage)
- Passphrase minimum: 12 characters with 3 of 4 character classes

## Platform Keychain Backends

The encrypted envelope is stored in the platform's native credential store. Auths never stores plaintext keys on disk.

```mermaid
graph LR
    subgraph "auths-core"
        KS["KeyStorage trait<br/><small>store_key() / load_key() / delete_key()</small>"]
    end

    subgraph "macOS"
        MAC["MacOSKeychain<br/><small>Security Framework<br/>Service: dev.auths.agent<br/>kSecClassGenericPassword</small>"]
    end

    subgraph "Linux"
        SS["LinuxSecretService<br/><small>D-Bus → GNOME Keyring<br/>or KWallet</small>"]
        EF["EncryptedFileStorage<br/><small>~/.auths/keys.enc<br/>Argon2id + XChaCha20</small>"]
    end

    subgraph "Windows"
        WIN["WindowsCredentialStorage<br/><small>PasswordVault (DPAPI)<br/>Resource: dev.auths.agent:alias</small>"]
    end

    KS --> MAC
    KS --> SS
    SS -.->|"fallback"| EF
    KS --> EF
    KS --> WIN
```

**Source**: `crates/auths-core/src/storage/keychain.rs` (`get_platform_keychain()`)

| Platform | Backend | Storage Location | OS-Level Protection |
|----------|---------|-----------------|---------------------|
| macOS | Security Framework | Keychain database | Secure Enclave (M-series), ACLs, Touch ID |
| Linux | Secret Service (D-Bus) | GNOME Keyring / KWallet | Session encryption, D-Bus policy |
| Linux (headless) | Encrypted File | `~/.auths/keys.enc` | File permissions (0600) + Argon2id + XChaCha20 |
| Windows | PasswordVault | DPAPI vault | Per-user DPAPI encryption |
| CI/testing | Memory | Process heap | None (not for production) |

**Override**: Set `AUTHS_KEYCHAIN_BACKEND=file` to force encrypted file storage on any platform.

### What Gets Stored

Each keychain entry contains:

| Field | macOS | Linux Secret Service | Windows | Encrypted File |
|-------|-------|---------------------|---------|----------------|
| **Key alias** | `kSecAttrAccount` | `alias` attribute | Resource name suffix | HashMap key |
| **Identity DID** | `kSecAttrDescription` | Pipe-delimited in secret | `Username` field | Tuple element |
| **Encrypted key** | `kSecValueData` | Base64 in secret value | Base64 in `Password` | Base64 in JSON |

The encrypted key data is the binary envelope described above -- the keychain provides an additional layer of OS-level encryption on top.

## SSH Agent Architecture

The agent is a daemon process that holds decrypted keys in memory and signs data on request over a Unix domain socket.

```mermaid
graph TB
    subgraph "Agent Daemon Process (PID file: ~/.auths/agent.pid)"
        direction TB

        subgraph "AgentSession"
            REQ["request_identities()"]
            ADD["add_identity()"]
            SIGN["sign()"]
            REM["remove_identity()"]
            REMALL["remove_all_identities()"]
        end

        subgraph "AgentHandle"
            LOCK["locked: AtomicBool"]
            TIMER["last_activity: Instant"]
            TIMEOUT["idle_timeout: 30min"]
        end

        subgraph "AgentCore"
            KEYS["keys: HashMap&lt;Vec&lt;u8&gt;, Zeroizing&lt;Vec&lt;u8&gt;&gt;&gt;<br/><small>pubkey bytes → PKCS#8 v2 DER</small>"]
        end

        REQ --> KEYS
        ADD --> KEYS
        SIGN --> KEYS
        REM --> KEYS
        REMALL --> KEYS
        LOCK --> KEYS
    end

    SOCKET["Unix Socket<br/>~/.auths/agent.sock"]
    CLIENT["auths-sign / auths CLI"]

    CLIENT <-->|"SSH agent protocol<br/>(length-prefixed messages)"| SOCKET
    SOCKET <--> REQ
    SOCKET <--> ADD
    SOCKET <--> SIGN
```

**Source files**:

| File | Role |
|------|------|
| `crates/auths-core/src/agent/core.rs` | `AgentCore` -- in-memory key HashMap with `Zeroizing` wrappers |
| `crates/auths-core/src/agent/handle.rs` | `AgentHandle` -- lifecycle, idle timeout, locking |
| `crates/auths-core/src/agent/session.rs` | `AgentSession` -- SSH agent protocol handler |
| `crates/auths-core/src/agent/client.rs` | Client functions that talk to the agent over the socket |
| `crates/auths-cli/src/commands/agent.rs` | CLI commands: `start`, `stop`, `unlock`, `lock`, `status` |

### Agent File Locations

| File | Path | Purpose |
|------|------|---------|
| Socket | `~/.auths/agent.sock` | Unix domain socket for SSH agent protocol |
| PID file | `~/.auths/agent.pid` | Tracks daemon PID for stop/status |
| Env file | `~/.auths/agent.env` | Shell export for `SSH_AUTH_SOCK` |
| Log file | `~/.auths/agent.log` | Daemon stdout/stderr |
| Pubkey cache | `~/.auths/pubkeys/<alias>.pub` | Hex-encoded 32-byte public keys |

### Memory Security

Keys in the agent are protected by three mechanisms:

1. **Zeroizing wrappers**: Every private key is stored as `Zeroizing<Vec<u8>>`. When dropped (removed, cleared, or process exits), the memory is overwritten with zeros before deallocation.

2. **Idle timeout**: After 30 minutes of inactivity (configurable), `lock_agent()` calls `core.clear_keys()`, which drops all `Zeroizing` values and triggers zeroization. Sign attempts after lock return `AgentError::AgentLocked`.

3. **Activity tracking**: Each successful sign operation calls `touch()` to reset the idle timer. Only active usage keeps keys in memory.

```mermaid
flowchart LR
    START(( )) -->|agent start| Empty
    Empty -->|"unlock<br/>(add_identity)"| Loaded
    Loaded -->|"30min idle /<br/>auths agent lock"| Locked
    Locked -->|"clear_keys +<br/>zeroize"| Empty
    Empty -->|"agent stop /<br/>shutdown"| STOP(( ))
    Loaded -->|"agent stop /<br/>shutdown"| STOP

    subgraph " "
        direction TB
        Loaded
        NOTE1["Each sign() resets the 30min idle timer.<br/>Keys held as Zeroizing Vec u8."]
    end

    subgraph "  "
        direction TB
        Locked
        NOTE2["All keys zeroized.<br/>Sign returns AgentLocked."]
    end

    style NOTE1 fill:none,stroke:none,color:#888
    style NOTE2 fill:none,stroke:none,color:#888
    style START fill:#666,stroke:#666
    style STOP fill:#666,stroke:#666
```

## Git Commit Signing Flow

When you run `git commit`, Git calls `auths-sign` as a subprocess. The signing uses a three-tier strategy that favors the fastest path (agent) and falls back gracefully.

```mermaid
flowchart TD
    GIT["git commit -m 'message'"] --> CALL["Git calls:<br/>auths-sign -Y sign -n git<br/>-f auths:main &lt;buffer&gt;"]

    CALL --> T1{"Tier 1: Agent"}
    T1 -->|"Agent running?<br/>Keys loaded?<br/>Pubkey cached?"| T1Y["Sign via agent socket<br/><small>No passphrase needed</small>"]
    T1 -->|"Any check fails"| T2{"Tier 2: Keychain"}

    T2 -->|"Keychain accessible?<br/>TTY available?"| T2Y["Prompt passphrase<br/>Decrypt key<br/>Cache pubkey<br/>Load key into agent"]
    T2 -->|"Fails"| ERR["Print actionable error:<br/><small>auths agent start<br/>auths agent unlock --key main</small>"]

    T2Y --> T3["Tier 3: Direct Sign<br/><small>Extract seed, create SSHSIG</small>"]

    T1Y --> WRITE["Write &lt;buffer&gt;.sig"]
    T3 --> WRITE

    WRITE --> DONE["Git reads .sig<br/>Embeds in commit object"]
    ERR --> FAIL["fatal: failed to write<br/>commit object"]

    style T1Y fill:#3d7a5a,color:#d8f0e0
    style T3 fill:#3d6a8a,color:#d8e8f0
    style ERR fill:#8b4049,color:#f0e0e0
```

**Source**: `crates/auths-cli/src/bin/sign.rs`

### What Each Tier Does

| Tier | Passphrase? | Speed | When It Runs |
|------|------------|-------|--------------|
| **1: Agent** | No | ~1ms | Agent running with keys loaded AND pubkey cached in `~/.auths/pubkeys/` |
| **2: Keychain** | Yes (once) | ~500ms | Agent has no keys or pubkey not cached; loads key into agent for next time |
| **3: Direct** | N/A | ~1ms | Always runs after Tier 2 succeeds; uses the decrypted key directly |

After the first passphrase entry (Tier 2), subsequent commits use Tier 1 exclusively -- no passphrase, no keychain access, just agent signing.

## SSHSIG Signature Format

The signature written to `<buffer>.sig` follows the [SSHSIG specification](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig), making it compatible with `ssh-keygen -Y verify`.

```mermaid
block-beta
    columns 1

    block:outer:1
        columns 6
        MAGIC["SSHSIG<br/>6 bytes"]
        VER["Version<br/>uint32 = 1"]
        PK["Public Key Blob<br/><small>ssh-ed25519 + 32B key</small>"]
        NS["Namespace<br/><small>'git'</small>"]
        HA["Hash Algo<br/><small>'sha512'</small>"]
        SB["Signature Blob<br/><small>ssh-ed25519 + 64B sig</small>"]
    end

    style MAGIC fill:#8b4049,color:#f0e0e0
    style VER fill:#3d6a8a,color:#d8e8f0
    style PK fill:#3d7a5a,color:#d8f0e0
    style NS fill:#6b4a7a,color:#e0d8f0
    style HA fill:#8a6a30,color:#f0e8d0
    style SB fill:#4a5568,color:#e2e8f0
```

The binary structure is base64-encoded and PEM-armored:

```
-----BEGIN SSH SIGNATURE-----
<base64 of binary blob, wrapped at 70 chars>
-----END SSH SIGNATURE-----
```

### What Gets Signed

The agent doesn't sign the raw commit data. It signs a structured SSHSIG message:

```
string  "SSHSIG"          (magic preamble)
string  "git"              (namespace)
string  ""                 (reserved, empty)
string  "sha512"           (hash algorithm)
string  SHA512(commit)     (64-byte hash of commit data)
```

This ensures the signature is bound to the namespace and commit content.

## Security Summary

| Concern | Protection |
|---------|-----------|
| **Key at rest** | Encrypted with Argon2id + AES-GCM/ChaCha20 in platform keychain |
| **Key in memory** | `Zeroizing<Vec<u8>>` -- zeroed on drop; idle timeout auto-clears after 30min |
| **Passphrase** | Read from `/dev/tty`; never stored, never logged; validated (12+ chars, 3/4 classes) |
| **Agent socket** | Unix domain socket with filesystem permissions; no network exposure |
| **Brute force** | Argon2id with 64 MiB memory cost makes GPU attacks expensive |
| **Tampering** | AEAD authentication tag detects ciphertext modification |
| **Wrong passphrase** | Returns `IncorrectPassphrase` error, not decrypted garbage |
| **Process exit** | `Zeroizing` drop handlers zero all key material |
| **Idle sessions** | Configurable timeout (default 30min) auto-locks and zeroizes keys |
