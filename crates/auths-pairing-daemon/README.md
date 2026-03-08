# auths-pairing-daemon

Embeddable LAN pairing daemon for the Auths identity system.

## Scope

Layer 5 crate that provides HTTP server infrastructure for device pairing over a local network. Depends on `auths-core` (which re-exports types from `auths-pairing-protocol`).

**This crate provides:**
- `DaemonState` — shared state for a single pairing session
- `DaemonError` — domain error types (no `anyhow`)
- `RateLimiter` — per-IP rate limiting (feature: `server`)
- `build_pairing_router` — Axum router with all pairing endpoints (feature: `server`)
- `NetworkInterfaces` trait — LAN IP detection abstraction (feature: `server`)
- `NetworkDiscovery` trait — mDNS advertisement/discovery abstraction (feature: `mdns`)
- `PairingDaemonBuilder` — builder API composing all of the above (feature: `server`)

**This crate does NOT:**
- Own the cryptographic pairing protocol (that's `auths-pairing-protocol`)
- Bind TCP listeners or spawn async runtimes (caller responsibility)
- Handle CLI presentation (spinners, QR codes, console output)

## Features

- `server` (default) — Axum HTTP server, rate limiting, token validation, LAN IP detection
- `mdns` (default) — mDNS advertisement and discovery via `mdns-sd`

Without features, only `DaemonError` and `DaemonState` are available.

## Usage

```rust,ignore
use auths_pairing_daemon::{PairingDaemonBuilder, DaemonError};

let daemon = PairingDaemonBuilder::new()
    .build(session_request)?;

let (router, handle) = daemon.into_parts();
let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
let addr = listener.local_addr()?;

tokio::spawn(axum::serve(listener, router.into_make_service()));

let response = handle.wait_for_response(timeout).await?;
```

## Architectural Boundaries

```
auths-pairing-protocol  (Layer 2, crypto + types)
        ↓
    auths-core           (Layer 3, re-exports protocol)
        ↓
auths-pairing-daemon     (Layer 5, HTTP server infra)  ← this crate
        ↓
    auths-sdk            (Layer 5, optional facade)
        ↓
    auths-cli            (Layer 6, presentation)
```
