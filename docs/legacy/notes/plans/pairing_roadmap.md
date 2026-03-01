# Auths Pair — "Just Works" Device Pairing Epics

> **Singular focus:** Make `auths pair` feel like an Apple experience — delightful, instant, zero-friction.

---

## Epic 1: WebSocket Relay — Kill the Polling Loop

**Problem:** The initiator polls `GET /v1/pairing/sessions/:id` every 2 seconds. This is laggy, wasteful, and feels broken when there's a 1-2s delay after the responder submits.

**Goal:** Sub-200ms response notification via WebSocket push.

### 1.1 — Server: Per-session WebSocket upgrade endpoint

`crates/auths-registry-server/src/routes/pairing.rs`

```rust
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use tokio::sync::broadcast;

/// Per-session event channel. Stored alongside PairingSession.
#[derive(Debug, Clone)]
pub struct SessionNotifier {
    tx: broadcast::Sender<SessionEvent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    Responded { device_did: String, device_name: Option<String> },
    Cancelled,
    Expired,
}

impl SessionNotifier {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(8);
        Self { tx }
    }

    pub fn notify(&self, event: SessionEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.tx.subscribe()
    }
}

/// GET /v1/pairing/sessions/:id/ws — real-time session updates.
pub async fn session_ws(
    ws: WebSocketUpgrade,
    Path(session_id): Path<String>,
    State(state): State<ServerState>,
) -> impl IntoResponse {
    let store = get_store(&state);
    let notifier = {
        let sessions = store.sessions.read().await;
        sessions.get(&session_id).map(|s| s.notifier.clone())
    };

    ws.on_upgrade(move |socket| async move {
        let Some(notifier) = notifier else {
            let _ = socket.close().await;
            return;
        };
        let mut rx = notifier.subscribe();
        let (mut sender, mut receiver) = socket.split();

        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Ok(e) => {
                        let json = serde_json::to_string(&e).unwrap_or_default();
                        if sender.send(Message::Text(json)).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
                msg = receiver.next() => match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                },
            }
        }
    })
}
```

### 1.2 — Fire notification on response submission

In `submit_response`, after `session.status = SessionStatus::Responded`:

```rust
session.notifier.notify(SessionEvent::Responded {
    device_did: request.device_did.clone(),
    device_name: request.device_name.clone(),
});
```

### 1.3 — CLI: Replace polling with WebSocket + fallback

`crates/auths-cli/src/commands/pair.rs`

```rust
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use futures_util::StreamExt;

async fn wait_for_response(
    registry: &str,
    session_id: &str,
    expiry: Duration,
) -> Result<Option<PairingResponseData>> {
    let ws_url = format!(
        "{}/v1/pairing/sessions/{}/ws",
        registry.replace("http", "ws"),
        session_id
    );

    let deadline = tokio::time::Instant::now() + expiry;

    // Try WebSocket first, fall back to polling
    match connect_async(&ws_url).await {
        Ok((mut ws, _)) => {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => return Ok(None),
                    msg = ws.next() => match msg {
                        Some(Ok(WsMessage::Text(text))) => {
                            if let Ok(event) = serde_json::from_str::<SessionEvent>(&text) {
                                match event {
                                    SessionEvent::Responded { .. } => {
                                        return fetch_full_response(registry, session_id).await;
                                    }
                                    SessionEvent::Cancelled | SessionEvent::Expired => {
                                        return Ok(None);
                                    }
                                }
                            }
                        }
                        None | Some(Err(_)) => break, // fall through to polling
                        _ => {}
                    },
                }
            }
        }
        Err(_) => {} // WebSocket unavailable, fall through
    }

    // Fallback: existing polling loop (unchanged)
    poll_for_response(registry, session_id, deadline).await
}
```

---

## Epic 2: Animated Terminal UX — Progress That Feels Alive

**Problem:** The current output is a wall of `println!` with a ticking countdown. It feels like a script, not a product.

**Goal:** Spinners, color, staged progress, and a satisfying completion sequence.

### 2.1 — Add `indicatif` + `console` for terminal rendering

`crates/auths-cli/Cargo.toml` — add:

```toml
indicatif = "0.17"
console = "0.15"
```

### 2.2 — Staged progress display

```rust
use console::{style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};

static LOCK: Emoji<'_, '_> = Emoji("🔐 ", "");
static LINK: Emoji<'_, '_> = Emoji("🔗 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
static PHONE: Emoji<'_, '_> = Emoji("📱 ", "");

fn print_pairing_header(registry: &str, controller_did: &str) {
    println!();
    println!("{}", style("━━━ Auths Device Pairing ━━━").bold().cyan());
    println!();
    println!("  {}Identity  {}", LOCK, style(controller_did).dim());
    println!("  {}Registry  {}", LINK, style(registry).dim());
    println!();
}

fn create_wait_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

fn print_completion(device_name: &str, device_did: &str) {
    println!();
    println!("{}", style("━━━ Pairing Complete ━━━").bold().green());
    println!();
    println!("  {}Device  {}", PHONE, style(device_name).bold());
    println!("  {}DID     {}", CHECK, style(device_did).dim());
    println!();
    println!(
        "  {}",
        style("Attestation created. Device can now sign commits.").green()
    );
    println!();
}
```

### 2.3 — Expiry countdown in spinner message

```rust
// Inside the wait loop
let remaining = deadline.duration_since(tokio::time::Instant::now());
spinner.set_message(format!(
    "{}Waiting for device... ({:02}:{:02})",
    PHONE,
    remaining.as_secs() / 60,
    remaining.as_secs() % 60,
));
```

---

## Epic 3: LAN-First Pairing — Zero Server Required

**Problem:** Pairing requires a running registry server. Most first-time users want to pair their laptop and phone on the same Wi-Fi without deploying infrastructure.

**Goal:** mDNS discovery + direct HTTP when devices share a network.

### 3.1 — mDNS advertisement from the initiator

`crates/auths-core/src/pairing/mdns.rs` (new file)

```rust
use std::net::SocketAddr;
use std::time::Duration;

const SERVICE_TYPE: &str = "_auths-pair._tcp.local.";

/// Advertise a pairing session on the local network.
pub async fn advertise_pairing(
    short_code: &str,
    port: u16,
    ttl: Duration,
) -> Result<mdns_sd::ServiceDaemon, PairingError> {
    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| PairingError::RelayError(format!("mDNS init: {e}")))?;

    let mut properties = std::collections::HashMap::new();
    properties.insert("sc".to_string(), short_code.to_string());
    properties.insert("v".to_string(), "1".to_string());

    let service_info = mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        &format!("auths-{}", short_code),
        &format!("auths-{}.local.", short_code),
        "",
        port,
        properties,
    )
    .map_err(|e| PairingError::RelayError(format!("mDNS service: {e}")))?;

    mdns.register(service_info)
        .map_err(|e| PairingError::RelayError(format!("mDNS register: {e}")))?;

    // Auto-unregister after TTL
    let mdns_clone = mdns.clone();
    tokio::spawn(async move {
        tokio::time::sleep(ttl).await;
        let _ = mdns_clone.shutdown();
    });

    Ok(mdns)
}

/// Discover a pairing session by short code on the local network.
pub async fn discover_pairing(
    short_code: &str,
    timeout: Duration,
) -> Result<SocketAddr, PairingError> {
    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| PairingError::RelayError(format!("mDNS init: {e}")))?;

    let receiver = mdns.browse(SERVICE_TYPE)
        .map_err(|e| PairingError::RelayError(format!("mDNS browse: {e}")))?;

    let deadline = tokio::time::Instant::now() + timeout;
    let target_name = format!("auths-{}", short_code);

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return Err(PairingError::ShortCodeNotFound(short_code.to_string()));
            }
            event = tokio::task::spawn_blocking({
                let rx = receiver.clone();
                move || rx.recv_timeout(std::time::Duration::from_secs(1))
            }) => {
                if let Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) = event {
                    if info.get_fullname().contains(&target_name) {
                        let addr = info.get_addresses().iter().next()
                            .ok_or_else(|| PairingError::RelayError("No address".into()))?;
                        return Ok(SocketAddr::new(*addr, info.get_port()));
                    }
                }
            }
        }
    }
}
```

### 3.2 — Ephemeral HTTP relay on the initiator

```rust
/// Spin up a one-shot axum server for local pairing.
pub async fn serve_local_relay(
    session: &PairingSession,
    port: u16,
) -> Result<tokio::sync::oneshot::Receiver<PairingResponseData>, PairingError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let token = session.token.clone();

    let app = axum::Router::new()
        .route("/pair", axum::routing::get({
            let token = token.clone();
            move || async move { Json(token) }
        }))
        .route("/pair/respond", axum::routing::post({
            let tx = tx.clone();
            move |Json(resp): Json<PairingResponseData>| async move {
                if let Some(sender) = tx.lock().unwrap().take() {
                    let _ = sender.send(resp);
                }
                Json(serde_json::json!({"ok": true}))
            }
        }));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await
        .map_err(|e| PairingError::RelayError(format!("bind: {e}")))?;

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    Ok(rx)
}
```

### 3.3 — Transport selection in pair command

```rust
enum PairingTransport {
    Registry { url: String },
    Lan { addr: SocketAddr },
}

/// Auto-detect: try LAN first (fast), fall back to registry.
async fn resolve_transport(registry: &str, short_code: &str) -> PairingTransport {
    match discover_pairing(short_code, Duration::from_secs(3)).await {
        Ok(addr) => PairingTransport::Lan { addr },
        Err(_) => PairingTransport::Registry { url: registry.to_string() },
    }
}
```

---

## Epic 4: QR Deep Link → Mobile App

**Problem:** The `auths://pair?...` URI exists but the mobile FFI has no pairing support — it only does identity creation. The mobile app can't respond to a pairing session.

**Goal:** Add `respond_to_pairing` to the mobile FFI so the iOS app can scan → approve → done.

### 4.1 — Add pairing response to mobile FFI

`crates/auths-mobile-ffi/src/lib.rs` — new exports:

```rust
/// Result of responding to a pairing request.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingResult {
    pub controller_did: String,
    pub device_did: String,
    pub shared_secret_hex: String,
    pub capabilities: Vec<String>,
}

/// Parse a scanned QR code / deep link URI into structured data for display.
#[uniffi::export]
pub fn parse_pairing_uri(uri: String) -> Result<PairingInfo, MobileError> {
    let token = parse_token_from_uri(&uri)
        .map_err(|e| MobileError::InvalidKeyData(format!("Bad URI: {e}")))?;

    Ok(PairingInfo {
        controller_did: token.controller_did,
        endpoint: token.endpoint,
        short_code: token.short_code,
        capabilities: token.capabilities,
        expires_at_unix: token.expires_at_unix,
    })
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingInfo {
    pub controller_did: String,
    pub endpoint: String,
    pub short_code: String,
    pub capabilities: Vec<String>,
    pub expires_at_unix: i64,
}

/// Respond to a pairing session. Call after user approves.
///
/// Takes the QR URI, the device's signing key (from Keychain),
/// and submits the response to the registry.
#[uniffi::export]
pub fn respond_to_pairing(
    uri: String,
    current_key_pkcs8_hex: String,
    device_name: String,
) -> Result<PairingResult, MobileError> {
    let token = parse_token_from_uri(&uri)
        .map_err(|e| MobileError::InvalidKeyData(format!("{e}")))?;

    let pkcs8 = hex::decode(&current_key_pkcs8_hex)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    let device_pubkey = keypair.public_key().as_ref();
    let device_did = generate_device_did(hex::encode(device_pubkey))?;

    // Generate X25519 ephemeral, do ECDH, sign binding
    let (response_payload, shared_secret) =
        build_pairing_response(&token, &keypair, &device_did, &device_name)?;

    // Submit to registry
    submit_pairing_response_sync(&token.endpoint, &token.short_code, &response_payload)?;

    Ok(PairingResult {
        controller_did: token.controller_did,
        device_did,
        shared_secret_hex: hex::encode(shared_secret.as_ref()),
        capabilities: token.capabilities,
    })
}
```

### 4.2 — Swift usage (in the iOS app)

```swift
// After QR scan or deep link open
func handlePairingURI(_ uri: String) async throws {
    let info = try parsePairingUri(uri: uri)

    // Show approval sheet
    let approved = await showPairingApproval(
        controllerDID: info.controllerDid,
        capabilities: info.capabilities
    )
    guard approved else { return }

    // Load key from Keychain
    let pkcs8Hex = try KeychainService.shared.loadCurrentKeyPkcs8()

    let result = try respondToPairing(
        uri: uri,
        currentKeyPkcs8Hex: pkcs8Hex,
        deviceName: UIDevice.current.name
    )

    await showPairingSuccess(controllerDID: result.controllerDid)
}
```

---

## Epic 5: Short Code Entry — Forgiveness Built In

**Problem:** The 6-char short code (e.g., `AB3-DEF`) works, but manual entry is fragile. No autocompletion, no error recovery, no "did you mean..." for typos.

**Goal:** Graceful short-code entry on both CLI and mobile.

### 5.1 — Fuzzy code matching on the server

`crates/auths-registry-server/src/routes/pairing.rs`

```rust
/// Find the closest matching short code (Hamming distance ≤ 1).
async fn fuzzy_lookup(store: &PairingSessionStore, code: &str) -> Option<(String, String)> {
    let index = store.short_code_index.read().await;

    // Exact match first
    if let Some(id) = index.get(code) {
        return Some((code.to_string(), id.clone()));
    }

    // Hamming distance 1: try each position with each alphabet char
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let code_bytes: Vec<u8> = code.bytes().collect();

    for pos in 0..code_bytes.len() {
        for &ch in ALPHABET {
            if ch == code_bytes[pos] { continue; }
            let mut candidate = code_bytes.clone();
            candidate[pos] = ch;
            let candidate_str = String::from_utf8(candidate).unwrap_or_default();
            if let Some(id) = index.get(&candidate_str) {
                return Some((candidate_str, id.clone()));
            }
        }
    }

    None
}
```

### 5.2 — Server returns `did_you_mean` on 404

```rust
// In lookup_by_short_code, when exact match fails:
if let Some((suggested, _session_id)) = fuzzy_lookup(&store, &normalized).await {
    return Err(ApiError::NotFoundWithSuggestion {
        message: format!("Code '{}' not found", normalized),
        suggestion: format!("{}-{}", &suggested[..3], &suggested[3..]),
    });
}
```

### 5.3 — CLI: Interactive retry with suggestion

```rust
async fn handle_join(code: &str, registry: &str) -> Result<()> {
    let normalized = normalize_short_code(code);

    match lookup_session(registry, &normalized).await {
        Ok(session) => proceed_with_join(session, registry).await,
        Err(JoinError::NotFound { suggestion: Some(suggested) }) => {
            println!(
                "  Code {} not found. Did you mean {}?",
                style(&normalized).red(),
                style(&suggested).green().bold(),
            );
            print!("  Try {} instead? [Y/n] ", style(&suggested).bold());
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y") {
                let clean = normalize_short_code(&suggested);
                handle_join(&clean, registry).await
            } else {
                Ok(())
            }
        }
        Err(e) => Err(e.into()),
    }
}
```

---

## Epic 6: Auto-Pair for Same-User Devices

**Problem:** If I have `auths` initialized on my MacBook and I install the CLI on my work laptop, I have to manually initiate a pairing session. This should be automatic if both machines can prove they're the same person.

**Goal:** `auths init` on a second device detects the existing identity and offers to pair.

### 6.1 — Registry: identity discovery endpoint

```rust
/// GET /v1/identities/:prefix/devices — list devices for an identity.
/// Only returns device DIDs (not secrets). Used for discovery.
pub async fn list_devices(
    State(state): State<ServerState>,
    Path(prefix): Path<String>,
) -> ApiResult<Json<Vec<DeviceSummary>>> {
    // ...load attestations for this prefix...
    Ok(Json(devices))
}

#[derive(Serialize)]
pub struct DeviceSummary {
    pub device_did: String,
    pub device_name: Option<String>,
    pub capabilities: Vec<String>,
    pub paired_at: DateTime<Utc>,
    pub is_revoked: bool,
}
```

### 6.2 — CLI: Detect existing identity during `auths init`

```rust
/// In handle_init, after the user provides their identity:
async fn maybe_offer_pairing(controller_did: &str, registry: &str) -> Result<bool> {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/identities/{}/devices", registry, controller_did);

    let resp = client.get(&url).send().await;
    let devices: Vec<DeviceSummary> = match resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => return Ok(false),
    };

    if devices.is_empty() {
        return Ok(false);
    }

    println!();
    println!(
        "  {} Found {} existing device(s) for this identity:",
        Emoji("🔍 ", ""),
        devices.len()
    );
    for d in &devices {
        let name = d.device_name.as_deref().unwrap_or("unnamed");
        println!("    • {} ({})", style(name).bold(), style(&d.device_did[..24]).dim());
    }
    println!();
    print!("  Pair this device to your identity? [Y/n] ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y"))
}
```

---

## Epic 7: Capability Approval UX — Show What You're Granting

**Problem:** `--capabilities sign_commit` is a CLI flag buried in the help text. The user never sees what they're granting, and the mobile device never shows what it's being offered.

**Goal:** Explicit capability review on both sides.

### 7.1 — Structured capability display

```rust
/// Human-readable capability descriptions.
fn capability_description(cap: &str) -> (&str, &str) {
    match cap {
        "sign_commit" => ("Sign Commits", "Sign Git commits on behalf of this identity"),
        "sign_release" => ("Sign Releases", "Sign release artifacts and tags"),
        "manage_members" => ("Manage Members", "Add/remove members from organizations"),
        "rotate_keys" => ("Rotate Keys", "Initiate key rotation for this identity"),
        _ => (cap, "Custom capability"),
    }
}

fn print_capability_review(capabilities: &[String]) {
    println!("  {} Capabilities to grant:", style("Permissions").bold());
    println!();
    for cap in capabilities {
        let (name, desc) = capability_description(cap);
        println!("    {} {}  {}", Emoji("🔑 ", "•"), style(name).bold(), style(desc).dim());
    }
    println!();
}
```

### 7.2 — Interactive capability selection (initiator side)

```rust
/// If no --capabilities flag given, prompt interactively.
fn prompt_capabilities() -> Vec<String> {
    let options = vec![
        ("sign_commit", "Sign Git commits", true),    // default on
        ("sign_release", "Sign release tags", false),
        ("manage_members", "Manage org members", false),
        ("rotate_keys", "Rotate identity keys", false),
    ];

    println!("  Select capabilities to grant (space to toggle, enter to confirm):");
    // Use dialoguer::MultiSelect or similar
    // ...
    selected
}
```

### 7.3 — Mobile: approval sheet shows capabilities

```swift
struct PairingApprovalView: View {
    let info: PairingInfo

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "link.badge.plus")
                .font(.system(size: 48))
                .foregroundColor(.blue)

            Text("Device Pairing Request")
                .font(.title2.bold())

            Text(info.controllerDid)
                .font(.caption)
                .foregroundColor(.secondary)

            Divider()

            ForEach(info.capabilities, id: \.self) { cap in
                HStack {
                    Image(systemName: iconForCapability(cap))
                    VStack(alignment: .leading) {
                        Text(nameForCapability(cap)).bold()
                        Text(descForCapability(cap))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
            }
        }
    }
}
```

---

## Epic 8: Pairing Session Encryption — Encrypted Relay Channel

**Problem:** The pairing response (containing the device's signing pubkey and DID) transits the relay server in cleartext. The relay is trusted-but-shouldn't-need-to-be.

**Goal:** Encrypt the response payload so the relay only sees opaque ciphertext.

### 8.1 — Encrypt response with initiator's X25519 pubkey

In `PairingResponse::create`, after ECDH produces `shared_secret`:

```rust
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadCore, Aead};
use chacha20poly1305::aead::OsRng;

/// Encrypt the response body so only the initiator can read it.
fn encrypt_response(
    shared_secret: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), PairingError> {
    let cipher = ChaCha20Poly1305::new_from_slice(shared_secret)
        .map_err(|e| PairingError::KeyExchangeFailed(format!("cipher init: {e}")))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| PairingError::KeyExchangeFailed(format!("encrypt: {e}")))?;

    Ok((ciphertext, nonce.into()))
}
```

### 8.2 — Wire format change

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPairingResponse {
    pub device_x25519_pubkey: String,  // still cleartext (needed for initiator ECDH)
    pub encrypted_payload: String,     // base64url of ChaCha20Poly1305 ciphertext
    pub nonce: String,                 // base64url of 12-byte nonce
}
```

### 8.3 — Initiator decrypts after ECDH

```rust
fn decrypt_response(
    shared_secret: &[u8; 32],
    encrypted: &EncryptedPairingResponse,
) -> Result<PairingResponseData, PairingError> {
    let cipher = ChaCha20Poly1305::new_from_slice(shared_secret).unwrap();
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&encrypted.nonce)
        .map_err(|_| PairingError::InvalidSignature)?;
    let ciphertext = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_payload)
        .map_err(|_| PairingError::InvalidSignature)?;

    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| PairingError::InvalidSignature)?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| PairingError::Serialization(e.to_string()))
}
```

---

## Epic 9: `auths pair --qr` Opens a Browser Preview

**Problem:** Terminal QR codes are hard to scan — font size, terminal width, and color scheme all affect readability. Some terminals (especially over SSH) can't render them at all.

**Goal:** `auths pair` opens a clean local HTML page with a massive, perfectly-rendered QR code.

### 9.1 — Generate and serve an HTML QR page

`crates/auths-cli/src/commands/pair_qr_server.rs` (new file)

```rust
use std::net::TcpListener;
use axum::{Router, response::Html, routing::get};

const QR_HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Auths Device Pairing</title>
  <script src="https://cdn.jsdelivr.net/npm/qrcode@1/build/qrcode.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, system-ui, sans-serif;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; background: #fafafa;
    }
    .card {
      background: white; border-radius: 20px; padding: 48px;
      box-shadow: 0 2px 40px rgba(0,0,0,0.08); text-align: center;
      max-width: 440px;
    }
    h1 { font-size: 24px; margin-bottom: 8px; }
    .subtitle { color: #666; margin-bottom: 32px; }
    #qr { margin: 0 auto 24px; }
    .code {
      font-size: 36px; letter-spacing: 0.2em; font-weight: 700;
      font-family: SF Mono, monospace; margin-bottom: 16px;
    }
    .meta { color: #999; font-size: 13px; }
    .expire { color: #e74c3c; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Pair Your Device</h1>
    <p class="subtitle">Scan with the Auths app</p>
    <canvas id="qr"></canvas>
    <p class="code">{{SHORT_CODE}}</p>
    <p class="meta">
      <span class="expire" id="timer"></span><br>
      {{CONTROLLER_DID}}
    </p>
  </div>
  <script>
    QRCode.toCanvas(document.getElementById('qr'), '{{URI}}', {
      width: 280, margin: 2,
      color: { dark: '#000', light: '#fff' }
    });
    const expires = {{EXPIRES_UNIX}} * 1000;
    setInterval(() => {
      const left = Math.max(0, Math.floor((expires - Date.now()) / 1000));
      const m = Math.floor(left / 60), s = left % 60;
      document.getElementById('timer').textContent =
        left > 0 ? `${m}:${String(s).padStart(2,'0')} remaining` : 'Expired';
    }, 1000);
  </script>
</body>
</html>"##;

pub async fn serve_qr_page(
    uri: &str,
    short_code: &str,
    controller_did: &str,
    expires_unix: i64,
) -> Result<u16, anyhow::Error> {
    let html = QR_HTML_TEMPLATE
        .replace("{{URI}}", uri)
        .replace("{{SHORT_CODE}}", &format!("{}-{}", &short_code[..3], &short_code[3..]))
        .replace("{{CONTROLLER_DID}}", controller_did)
        .replace("{{EXPIRES_UNIX}}", &expires_unix.to_string());

    let app = Router::new()
        .route("/", get(move || async move { Html(html.clone()) }));

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, app).await.ok();
    });

    // Open browser
    let _ = open::that(format!("http://127.0.0.1:{}", port));

    Ok(port)
}
```

### 9.2 — Wire into pair command

```rust
// After session is created, before the wait loop:
if !cmd.no_qr {
    // Terminal QR as fallback
    let options = QrOptions::default();
    let qr = render_qr(&session.token, &options)?;
    println!("{}", qr);

    // Also open browser
    let _ = serve_qr_page(
        &session.token.to_uri(),
        &session.token.short_code,
        &controller_did,
        session.token.expires_at.timestamp(),
    ).await;
}
```

---

## Epic 10: End-to-End Integration Tests

**Problem:** The pairing flow spans CLI → registry server → mobile FFI. There are unit tests for each piece but no test that exercises the full handshake.

**Goal:** A single `cargo test` that simulates: generate → register → lookup → respond → verify → attest.

### 10.1 — Full-cycle integration test

`crates/auths-cli/tests/pairing_e2e.rs` (new file)

```rust
use auths_core::pairing::{PairingResponse, PairingToken};
use auths_registry_server::{ServerConfig, ServerState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;
use tower::ServiceExt;

async fn setup_server() -> (axum::Router, TempDir) {
    let temp = TempDir::new().unwrap();
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(temp.path())
        .output()
        .unwrap();

    let backend = auths_id::storage::registry::PackedRegistryBackend::new(temp.path());
    backend.init_if_needed().unwrap();
    let state = ServerState::from_repo_path(temp.path()).unwrap();
    let config = ServerConfig::default();
    (routes::router(state, &config), temp)
}

#[tokio::test]
async fn full_pairing_handshake() {
    let (app, _temp) = setup_server().await;

    // Step 1: Initiator generates session
    let session = PairingToken::generate(
        "did:keri:Etest123".to_string(),
        "http://localhost:3000".to_string(),
        vec!["sign_commit".to_string()],
    )
    .unwrap();

    // Step 2: Register session with server
    let create_body = serde_json::json!({
        "session_id": session.token.short_code,
        "controller_did": session.token.controller_did,
        "ephemeral_pubkey": session.token.ephemeral_pubkey,
        "short_code": session.token.short_code,
        "capabilities": session.token.capabilities,
        "expires_at": session.token.expires_at.timestamp(),
    });

    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/pairing/sessions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&create_body).unwrap()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Step 3: Responder looks up session by short code
    let resp = app.clone().oneshot(
        Request::builder()
            .uri(format!("/v1/pairing/sessions/by-code/{}", session.token.short_code))
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Step 4: Responder creates pairing response
    let rng = SystemRandom::new();
    let device_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let device_keypair = Ed25519KeyPair::from_pkcs8(device_pkcs8.as_ref()).unwrap();

    let (pairing_response, responder_secret) = PairingResponse::create(
        &session.token,
        &device_keypair,
        "did:key:z6MkTestDevice".to_string(),
        Some("Test iPhone".to_string()),
    ).unwrap();

    // Step 5: Submit response to server
    let submit_body = serde_json::json!({
        "device_x25519_pubkey": pairing_response.device_x25519_pubkey,
        "device_signing_pubkey": pairing_response.device_signing_pubkey,
        "device_did": pairing_response.device_did,
        "signature": pairing_response.signature,
        "device_name": pairing_response.device_name,
    });

    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/pairing/sessions/{}/response", session.token.short_code))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&submit_body).unwrap()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Step 6: Initiator polls and gets response
    let resp = app.clone().oneshot(
        Request::builder()
            .uri(format!("/v1/pairing/sessions/{}", session.token.short_code))
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let session_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session_data["status"], "responded");
    assert!(session_data["response"].is_object());

    // Step 7: Verify signature binding
    assert!(pairing_response.verify(&session.token).is_ok());

    // Step 8: Initiator completes ECDH — shared secrets match
    let mut initiator_session = session;
    let device_x25519 = pairing_response.device_x25519_pubkey_bytes().unwrap();
    let initiator_secret = initiator_session.complete_exchange(&device_x25519).unwrap();
    assert_eq!(*initiator_secret, *responder_secret);
}
```

### 10.2 — Expiry and cancellation tests

```rust
#[tokio::test]
async fn expired_session_rejected() {
    let (app, _temp) = setup_server().await;

    let session = PairingToken::generate_with_expiry(
        "did:keri:Etest".to_string(),
        "http://localhost:3000".to_string(),
        vec![],
        chrono::Duration::seconds(-1), // already expired
    ).unwrap();

    // Register (should succeed — server uses its own timer)
    // ...create session...

    // Wait for server-side expiry check
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Submitting a response to an expired session should fail
    // ...assert 400 response...
}

#[tokio::test]
async fn cancelled_session_rejects_response() {
    // Create → Cancel → Attempt response → assert failure
}
```

---

## Dependency Summary

| Crate | Epics | Purpose |
|-------|-------|---------|
| `tokio-tungstenite` | 1 | WebSocket client for CLI |
| `indicatif` | 2 | Spinners and progress bars |
| `console` | 2 | Terminal colors and emoji |
| `mdns-sd` | 3 | LAN service discovery |
| `chacha20poly1305` | 8 | Relay channel encryption |
| `open` | 9 | Open browser from CLI |
| `dialoguer` | 7 | Interactive capability selection |

## Priority Order

| Priority | Epic | Impact | Effort |
|----------|------|--------|--------|
| P0 | 1 — WebSocket Relay | Eliminates perceived latency | Medium |
| P0 | 4 — Mobile FFI Pairing | Unlocks the entire mobile flow | Medium |
| P0 | 10 — E2E Tests | Confidence to ship everything else | Small |
| P1 | 2 — Animated Terminal | Makes CLI feel like a product | Small |
| P1 | 5 — Fuzzy Short Codes | Removes the #1 error case | Small |
| P1 | 7 — Capability Approval | Security UX done right | Small |
| P2 | 3 — LAN-First Pairing | Zero-infra first experience | Large |
| P2 | 9 — Browser QR | Fixes terminal rendering edge cases | Small |
| P2 | 8 — Encrypted Relay | Defense in depth | Medium |
| P3 | 6 — Auto-Pair Detection | Power user delight | Medium |
