# auths-rp

Relying-party transport for the Auths **agent passport**: authenticate an HTTP request by presenting proof-of-control of a delegated, scoped, expiring, revocable KERI credential — instead of a bearer API key.

A client (an AI agent, a CI job, a service) signs a server-issued challenge with the **current** key of its credential's subject AID and sends it in an `Authorization` header. The relying party verifies it **offline, holding no secret**, and maps the result to an allow/deny decision. An API key is a bearer secret — anyone who reads it can replay it anywhere, forever, traceable to nobody. A passport is the opposite on every axis.

This crate owns the **wire boundary, the verdict → principal mapping, and the single-use challenge store**. It deliberately does *not* perform the cryptographic check itself — that is the shipped, pure `auths_verifier::verify_presentation` — nor does it bind to any HTTP framework.

## Why a separate crate?

The cryptographic primitive (`verify_presentation`, holder-of-key + audience-binding + single-use nonce + scope + expiry + revocation, all offline) already ships in `auths-verifier`. What did *not* exist was the request-authentication layer around it: a wire format, the proof-carrying principal type, and replay protection. `auths-rp` is that layer, kept separate so:

- **The verifier stays minimal.** `auths-verifier` is built for FFI/WASM embedding and must not pull in transport or HTTP concerns. Replay protection (the challenge store) lives here precisely so the verify path keeps no global state and remains WASM-safe.
- **The transport is framework-agnostic.** This crate has no `axum`/`hyper`/HTTP-server dependency. It parses a raw `Authorization` header string and returns domain types; any server (Axum, Express-over-FFI, an MCP server) wires those into its own request lifecycle.
- **I/O is the consumer's job.** Loading the credential's KELs/TEL/receipts and holding the `CryptoProvider` belong to the server (which has the registry and the keys). This crate stays free of KEL, provider, and network dependencies, so it is trivially unit-testable.

It is an internal workspace crate (`publish = false`): a building block for `auths-sdk`, `auths-mcp-server`, and the language-binding middleware, not a public API surface.

## How it fits in the architecture

```
client (agent / CI / service)
  |  Authorization: Auths-Presentation <base64url(JSON)>
  v
auths-rp  (THIS CRATE — transport + principal mapping + challenge store)
  |   lib.rs        -- WirePresentation -> (PresentationEnvelope, Audience), parsed once
  |   challenge.rs  -- ChallengeStore: mint + remove-on-read single-use nonce
  |   principal.rs  -- PresentationVerdict -> VerifiedPrincipal | Denied; authorize -> Grant
  |
  +--> auths-verifier::verify_presentation   (the pure, offline crypto check — called by the consumer)
  ^
  |  consumed by
auths-sdk (authenticate_presentation) · auths-mcp-server (KERI-native tool auth) · framework middleware
```

**Dependency direction**: `auths-rp` depends only on `auths-verifier` (plus `base64`, `chrono`, `parking_lot`, `ring`, `serde`, `thiserror`). Nothing in the verifier or core layers depends on it.

## What it provides

### 1. The wire boundary (`lib.rs`)

Turns an untrusted header into trusted domain types, exactly once.

- `AUTHS_PRESENTATION_SCHEME` — the `Authorization` scheme name (`"Auths-Presentation"`).
- `WirePresentation` / `WireBinding` — the raw, stringly-typed wire shape (`credential_said`, `audience`, a `Challenge { nonce }` or `Ttl { nonce, not_after }` binding, base64url `signature`).
- `parse_presentation_header(&str)` — `Authorization` value → `WirePresentation`.
- `WirePresentation::parse(self)` — the **only** exit from "wire world": yields the shipped `auths_verifier::PresentationEnvelope` plus the bound `Audience`. After this, no raw field is trusted.
- `Audience` — a non-empty relying-party identifier (empty is unrepresentable).
- `Nonce` — a fixed 32-byte value (`NONCE_LEN`); "wrong-length nonce" cannot be constructed.
- `WireError` — a closed `thiserror` sum for every boundary failure.

### 2. Single-use challenge store (`challenge.rs`)

Replay protection without a global seen-cache in the verifier.

- `ChallengeStore` — bounded and TTL-pruned, so a challenge flood cannot exhaust memory.
- `issue(&Audience, now)` — mint a fresh CSPRNG nonce (via `ring`) bound to an audience → `IssuedChallenge`.
- `consume(&Audience, &Nonce, now)` — **remove-on-read**: a nonce verifies exactly once; a second consume, an expired one, or an unknown one all fail. Returns an `ExpectedNonce` — proof a live challenge was consumed *now*, to pass as the verifier's `expected_challenge`.
- `DEFAULT_CHALLENGE_TTL_SECS`, `ChallengeError`.

### 3. Verified principal + denial mapping (`principal.rs`)

Evidence lives in the type system.

- `VerifiedPrincipal` — constructible **only** via `from_verdict` on a `Valid` verdict; possessing one *is proof* the holder demonstrated current key control. Subject/capabilities are parsed into the shipped `auths_verifier` domain types here.
- `authorize(&Capability) -> Result<Grant, Denied>` — returns a capability **proof**, never a bool. A handler that requires a `Grant` to act cannot be reached on an unauthorized path.
- `Denied` — a closed sum mapping every non-`Valid` verdict to the right HTTP class via `http_status()` (401 for authentication failures, 403 for insufficient capability).

## Design: parse, don't validate

Every type in this crate exists to make an illegal state unrepresentable rather than to be checked at runtime:

| Invariant | Enforced by |
|---|---|
| Raw wire bytes are parsed once, then never re-checked | `WirePresentation::parse` is the sole exit to domain types |
| An audience is never empty | `Audience::parse` (only constructor) |
| A nonce is always exactly 32 bytes | `Nonce` wraps `[u8; 32]`; `parse_b64url` is the only fallible ctor |
| A nonce verifies at most once | `ChallengeStore::consume` is remove-on-read |
| A principal exists only after a successful verdict | `VerifiedPrincipal::from_verdict` is the only constructor |
| "Authorized" is a proof, not a flag | `authorize` returns a `Grant`, not `bool` |
| Every verdict arm is handled | exhaustive match (no `_ =>`) in `from_verdict` |
| Failures are typed, never strings | `WireError` / `ChallengeError` / `Denied` (`thiserror`) |

## Usage

### Parse an incoming header into domain types

```rust
use auths_rp::parse_presentation_header;

let wire = parse_presentation_header(authorization_header)?;     // Authorization value -> WirePresentation
let (envelope, audience) = wire.parse()?;                        // -> auths_verifier::PresentationEnvelope + Audience
// `envelope` and `audience` are now safe to feed to verify_presentation.
```

### Issue and consume a single-use challenge

```rust
use auths_rp::{Audience, ChallengeStore};

let store = ChallengeStore::new(10_000);                         // capacity bound
let audience = Audience::parse("api.example.com")?;

// GET /v1/auth/challenge
let issued = store.issue(&audience, now)?;                       // hand `issued.nonce` to the client

// On the authenticated request:
let expected = store.consume(&audience, &presented_nonce, now)?; // ExpectedNonce, or ChallengeError::NotLive
// pass expected.as_bytes() as verify_presentation's `expected_challenge`.
```

### Map a verdict to a principal and authorize

```rust
use auths_rp::{VerifiedPrincipal, Denied};
use auths_verifier::Capability;

// `verdict` came from the shipped auths_verifier::verify_presentation (run by the consumer).
let principal = VerifiedPrincipal::from_verdict(verdict)?;       // Valid -> proof; else typed Denied
let needed = Capability::parse("acme:deploy")?;
let grant = principal.authorize(&needed)?;                       // Grant proof, or Denied::MissingCapability (403)

// On error, map to a status without leaking which check failed:
// let status = denied.http_status();  // 401 (authn) or 403 (capability)
```

## What this crate does NOT do

- It does **not** call `verify_presentation` — the consumer does, because the consumer holds the `CryptoProvider` and the loaded issuer/subject/delegator KELs, TEL, and receipts.
- It does **not** load anything from Git, a registry, or the network.
- It does **not** depend on an HTTP framework — it has no router, no extractor, no middleware (yet).

## Future directions

- **Drop-in framework middleware**: an Axum layer + a `VerifiedPrincipal` extractor (and, across the language bindings, Express and FastAPI equivalents) that wire the parse → consume → verify → authorize flow into the request lifecycle.
- **Verdict tightening**: once `auths_verifier::PresentationVerdict::Valid` carries `CanonicalDid`/`Capability` directly, the re-parse in `from_verdict` collapses to a move and the capability re-parse disappears.
- **Shared challenge store**: a trait seam over `ChallengeStore` so a multi-instance relying party (behind a load balancer) can back single-use replay protection with a shared store; the current store is single-process.
