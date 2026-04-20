//! HKDF info labels and MAC/signature domain tags used by the daemon.
//!
//! Labels are immutable once shipped. Changing any byte invalidates
//! every authentication computation that used the old label — a
//! protocol-level break. Add a new label (e.g. `…-v2`) rather than
//! editing an existing one.
//!
//! Each crate owns the labels it uses. The daemon MUST NOT import
//! domain-separation constants from `auths-pairing-protocol`; its
//! labels live in this module, uniquely prefixed by purpose
//! (`auths-daemon-*`) so collisions with sibling crates are
//! impossible.

/// HKDF `info` used when deriving the 32-byte HMAC key from the
/// pairing short code. The short-code bytes are the IKM; the salt is
/// empty (no session_id is known at lookup time).
pub const DAEMON_HMAC_INFO: &[u8] = b"auths-daemon-hmac-v1";

/// Prefix byte string included in the canonical signing input for
/// device-signature auth on session-scoped endpoints. Prevents a
/// signature captured on one auths-facing RPC from being replayed
/// against a different auths-facing context (pairing protocol,
/// transparency log, etc.).
pub const DAEMON_SIG_CONTEXT: &[u8] = b"auths-daemon-sig-v1";
