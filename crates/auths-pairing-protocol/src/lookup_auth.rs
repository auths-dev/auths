//! Client-side `Auths-HMAC` lookup-auth for the pairing `/lookup` endpoint.
//!
//! The joining device proves it holds the 6-character short code without ever
//! sending it in the clear: it HMACs a canonical request string with a key
//! derived from the short code. The client (`auths-infra-http`) builds the
//! `Authorization` header with [`build_lookup_authorization`]; the daemon
//! (`auths-pairing-daemon::auth`) verifies it.
//!
//! **These functions MUST stay byte-identical to `auths-pairing-daemon::auth`**
//! (`derive_hmac_key` / `derive_hmac_kid` / `canonical_string` / the
//! `DAEMON_HMAC_INFO` context). That invariant is enforced, not assumed: the
//! daemon's `hmac_lookup_client_header_is_accepted` test signs a request via
//! [`build_lookup_authorization`] and asserts the daemon's `verify_hmac` accepts
//! it, so any drift between the two copies fails the build. (The daemon owns the
//! verify path; duplicating only these pure builders here keeps the client off a
//! dependency on the server crate.)
//!
//! Canonical signing string (newline-separated):
//! `<context>\n<method>\n<path>\n<sha256-hex(body)>\n<ts>\n<nonce-b64>`

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Domain-separation context for the HMAC lookup scheme. Included in the signed
/// bytes so a lookup HMAC can never be replayed as a different scheme's message.
pub const DAEMON_HMAC_INFO: &[u8] = b"auths-daemon-hmac-v1";

/// The path the short-code lookup is served at (also part of the signed bytes).
pub const LOOKUP_PATH: &str = "/v1/pairing/sessions/lookup";

/// Build the canonical signing input for a request.
///
/// `context` is [`DAEMON_HMAC_INFO`] for the HMAC scheme. Binding method, path,
/// a hash of the body, the timestamp, and the nonce prevents cross-request and
/// cross-endpoint replay.
pub fn canonical_string(
    context: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    ts: i64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_hex = hex::encode(hasher.finalize());
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    let mut out = Vec::with_capacity(context.len() + method.len() + path.len() + 200);
    out.extend_from_slice(context);
    out.push(b'\n');
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body_hash_hex.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(ts.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce_b64.as_bytes());
    out
}

/// Derive the 32-byte HMAC key from the pairing short code.
pub fn derive_hmac_key(short_code: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, short_code.as_bytes());
    let mut key = [0u8; 32];
    let _ = hk.expand(DAEMON_HMAC_INFO, &mut key);
    key
}

/// First 16 bytes of `SHA-256(short_code)` — the `kid` on the `Auths-HMAC`
/// scheme. Lets the server look up which short code a request claims without the
/// code appearing anywhere in the clear.
pub fn derive_hmac_kid(short_code: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(short_code.as_bytes());
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Build the `Authorization: Auths-HMAC …` header value for a `GET` on
/// [`LOOKUP_PATH`] with an empty body — the client half of the scheme.
///
/// The caller supplies `ts` (current unix seconds) and a fresh random `nonce`
/// (the daemon rejects replays), keeping this a pure, testable function.
pub fn build_lookup_authorization(short_code: &str, ts: i64, nonce: &[u8]) -> String {
    let kid = derive_hmac_kid(short_code);
    let key = derive_hmac_key(short_code);
    let canonical = canonical_string(DAEMON_HMAC_INFO, "GET", LOOKUP_PATH, b"", ts, nonce);

    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&key) else {
        unreachable!("HMAC-SHA256 accepts a key of any length")
    };
    mac.update(&canonical);
    let sig = mac.finalize().into_bytes();

    format!(
        "Auths-HMAC kid={},ts={},nonce={},sig={}",
        URL_SAFE_NO_PAD.encode(kid),
        ts,
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(sig),
    )
}
