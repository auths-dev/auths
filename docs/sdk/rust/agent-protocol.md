# Agent Protocol

The auths SSH agent manages Ed25519 key material in memory and exposes a signing interface via the SSH agent protocol over Unix domain sockets.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  CLI Layer (auths-cli)                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ AgentCommand │  │ process::*   │  │ service::*  │ │
│  │ (dispatcher) │  │ (PID, spawn, │  │ (launchd,   │ │
│  │              │  │  terminate)  │  │  systemd)   │ │
│  └──────┬───────┘  └──────────────┘  └─────────────┘ │
│         │                                            │
│  ┌──────┴───────┐                                    │
│  │CliAgentAdapter│ ← implements AgentSigningPort     │
│  └──────┬───────┘                                    │
└─────────┼────────────────────────────────────────────┘
          │
┌─────────┼────────────────────────────────────────────┐
│  SDK Layer (auths-sdk)                               │
│  ┌──────┴───────┐  ┌──────────────────┐              │
│  │AgentSigning  │  │ AgentTransport   │              │
│  │Port (trait)  │  │ (trait)          │              │
│  └──────────────┘  └──────────────────┘              │
└──────────────────────────────────────────────────────┘
          │
┌─────────┼────────────────────────────────────────────┐
│  Core Layer (auths-core)                             │
│  ┌──────┴───────┐  ┌──────────────┐  ┌────────────┐ │
│  │ AgentHandle  │  │ AgentCore    │  │AgentSession│ │
│  │ (lifecycle)  │  │ (key store)  │  │(SSH proto) │ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
└──────────────────────────────────────────────────────┘
```

## State Machine

The agent operates as a state machine with three states:

```
                ┌─────────┐
     ┌─────────►│ Locked  │◄────────────┐
     │          └────┬────┘             │
     │               │ unlock           │ lock / idle timeout
     │               ▼                  │
     │          ┌─────────┐             │
     │          │Unlocked │─────────────┘
     │          └────┬────┘
     │               │ sign request
     │               ▼
     │          ┌─────────┐
     │          │ Signing │ (returns to Unlocked)
     │          └─────────┘
     │
  shutdown
```

**Locked**: No keys in memory. All sign requests fail. Entered on startup, after `lock` command, or after idle timeout.

**Unlocked**: Keys loaded in memory. Ready to accept sign requests. Entered via `unlock` command which loads a key from the platform keychain.

**Signing**: Transient state during a sign operation. `AgentCore::sign()` looks up the key by public key bytes and produces an Ed25519 signature. Returns to Unlocked on completion.

### Idle Timeout

The `AgentHandle` tracks a `last_activity` timestamp (reset on each successful sign). When `idle_duration()` exceeds the configured `idle_timeout` (default 30 minutes, 0 = disabled), `check_idle_timeout()` triggers `lock_agent()`, clearing all keys from memory.

## IPC Wire Protocol

The agent speaks the [SSH agent protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent) over a Unix domain socket. Messages use a 4-byte big-endian length prefix followed by the message body.

### Message Types

| Code | Name | Direction | Description |
|------|------|-----------|-------------|
| 11 | `SSH_AGENTC_REQUEST_IDENTITIES` | Client → Agent | List loaded keys |
| 12 | `SSH_AGENT_IDENTITIES_ANSWER` | Agent → Client | Key list response |
| 13 | `SSH_AGENTC_SIGN_REQUEST` | Client → Agent | Sign data with key |
| 14 | `SSH_AGENT_SIGN_RESPONSE` | Agent → Client | Signature response |
| 17 | `SSH_AGENTC_ADD_IDENTITY` | Client → Agent | Load key into agent |
| 19 | `SSH_AGENTC_REMOVE_ALL_IDENTITIES` | Client → Agent | Clear all keys |
| 5 | `SSH_AGENT_FAILURE` | Agent → Client | Operation failed |
| 6 | `SSH_AGENT_SUCCESS` | Agent → Client | Operation succeeded |

### Sign Request Payload

```
[4 bytes] total length
[1 byte]  message type (13)
[4 bytes] pubkey blob length
[N bytes] pubkey blob (SSH wire format: "ssh-ed25519" + key bytes)
[4 bytes] data length
[M bytes] data to sign
[4 bytes] flags (0)
```

### Sign Response Payload

```
[4 bytes] total length
[1 byte]  message type (14)
[4 bytes] signature blob length
[N bytes] signature blob (SSH wire format: "ssh-ed25519" + raw sig bytes)
```

## Transport Trait Contract

The `AgentTransport` trait in `auths-sdk/src/ports/agent.rs` abstracts the listener mechanism:

```rust
pub trait AgentTransport: Send + Sync + 'static {
    /// Start accepting connections and serving requests (blocks until shutdown).
    fn serve(&self) -> Result<(), AgentTransportError>;

    /// Check if the transport backend is available on this platform.
    fn is_available(&self) -> bool;

    /// Return the listener socket path, if applicable.
    fn socket_path(&self) -> Option<&Path>;
}
```

The CLI provides a Unix socket implementation via `start_agent_listener_with_handle()`. Tests can inject an in-process transport that calls `AgentHandle` methods directly, bypassing IPC.

## Process Lifecycle

Process management is decomposed into standalone functions in `auths-cli/src/commands/agent/process.rs`:

| Function | Purpose |
|----------|---------|
| `write_pid_file(path, pid)` | Write PID to file with restricted permissions |
| `read_pid_file(path)` | Read PID from file, `None` if missing |
| `is_process_running(pid)` | Check process existence via signal 0 |
| `socket_is_connectable(path)` | Test socket connectivity (TOCTOU-safe) |
| `spawn_detached(args, log_path)` | Re-exec current binary as a daemon via `setsid()` |
| `terminate_process(pid, timeout)` | SIGTERM with SIGKILL escalation |
| `cleanup_stale_files(paths)` | Remove stale PID/socket/env files |

All functions have `#[cfg(unix)]` / `#[cfg(not(unix))]` guards. Non-Unix stubs return errors or `false`.

## Key Components

### `AgentCore` (auths-core)

In-memory key registry. Stores `HashMap<Vec<u8>, SecureSeed>` mapping public key bytes to zeroized seed material. Provides `register_key`, `unregister_key`, `sign`, and `clear_keys`.

### `AgentHandle` (auths-core)

Thread-safe lifecycle wrapper around `Arc<Mutex<AgentCore>>`. Adds idle timeout tracking, lock/unlock state, PID file management, and graceful shutdown with key zeroization.

### `AgentSession` (auths-core)

Implements `ssh_agent_lib::agent::Session` for handling individual SSH agent protocol sessions. Delegates all operations to `AgentHandle`.

### `AgentSigningPort` (auths-sdk)

High-level signing trait returning SSHSIG PEM strings. The `CliAgentAdapter` implements this by connecting to the socket, performing the sign, and formatting the result.
