//! SSH agent session handler.
//!
//! This module provides `AgentSession`, which implements the `ssh_agent_lib::agent::Session`
//! trait to handle SSH agent protocol requests.

use crate::agent::AgentHandle;
use crate::error::AgentError as AuthsAgentError;
use log::{debug, error, warn};
#[cfg(unix)]
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError as SSHAgentError;
use ssh_agent_lib::proto::{AddIdentity, Credential, Identity, RemoveIdentity, SignRequest};
use ssh_key::private::KeypairData;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, Signature};
use std::convert::TryInto;
use std::io;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The identity of a process connected to the agent socket, read from the peer
/// credentials of the connection.
///
/// Args (fields): `uid`, `pid`.
///
/// Usage:
/// ```ignore
/// let peer = PeerIdentity { uid: 1000, pid: Some(4242) };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Effective user id of the connecting process.
    pub uid: u32,
    /// Process id of the connecting process, when the platform exposes it (Linux via
    /// `SO_PEERCRED`; `None` on macOS, whose `getpeereid` returns no pid).
    pub pid: Option<i32>,
}

impl PeerIdentity {
    /// The agent's own process — used for in-process / default sessions where no
    /// external peer applies.
    pub fn local() -> Self {
        Self { uid: 0, pid: None }
    }
}

/// Decides whether a connected peer may make the agent sign *right now*.
///
/// Connection-level UID authorization (same user only) is enforced separately. This is
/// the per-request gate that lets the host require approval — e.g. a per-caller
/// biometric — before each signature, so an unlocked agent does not grant silent
/// signing to every same-user process.
pub trait SignAuthorizer: Send + Sync {
    /// Returns true iff `peer` is allowed to obtain a signature now.
    ///
    /// Args:
    /// * `peer`: the connecting process's identity.
    fn authorize_sign(&self, peer: &PeerIdentity) -> bool;
}

/// The permissive authorizer: every signature is allowed. Used for in-process/default
/// sessions and for explicitly non-interactive (headless/automation) contexts.
///
/// Usage:
/// ```ignore
/// let auth = std::sync::Arc::new(AllowAllSigning);
/// ```
pub struct AllowAllSigning;

impl SignAuthorizer for AllowAllSigning {
    fn authorize_sign(&self, _peer: &PeerIdentity) -> bool {
        true
    }
}

/// Per-caller signing approval — the policy for #354. The first time a given peer
/// process asks to sign, the injected `approve` function is consulted (e.g. a
/// biometric / user prompt). Approved peers are pinned for the life of this authorizer
/// (the unlock window), so the legitimate caller is not re-prompted on every signature,
/// while a *different* process triggers a fresh approval.
///
/// Peers are keyed by `(uid, pid)`. On platforms without a peer pid (macOS), `pid` is
/// `None`, so callers collapse to per-uid; there the host's `approve` function should
/// apply a time-bucketed re-auth rather than pinning forever.
///
/// Usage:
/// ```ignore
/// let auth = PerCallerAuthorizer::new(|peer| prompt_biometric_for(peer));
/// ```
pub struct PerCallerAuthorizer {
    approve: Box<dyn Fn(&PeerIdentity) -> bool + Send + Sync>,
    approved: std::sync::Mutex<std::collections::HashSet<(u32, Option<i32>)>>,
}

impl PerCallerAuthorizer {
    /// Builds a per-caller authorizer that consults `approve` once per new peer and
    /// pins peers it approves.
    ///
    /// Args:
    /// * `approve`: called for a not-yet-approved peer; returning true pins it.
    pub fn new(approve: impl Fn(&PeerIdentity) -> bool + Send + Sync + 'static) -> Self {
        Self {
            approve: Box::new(approve),
            approved: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

impl SignAuthorizer for PerCallerAuthorizer {
    fn authorize_sign(&self, peer: &PeerIdentity) -> bool {
        let key = (peer.uid, peer.pid);
        let mut approved = self
            .approved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if approved.contains(&key) {
            return true;
        }
        if (self.approve)(peer) {
            approved.insert(key);
            true
        } else {
            false
        }
    }
}

/// Wraps an `AgentHandle` to implement the `ssh_agent_lib::agent::Session` trait.
///
/// Each `AgentSession` holds a reference to an `AgentHandle`, the identity of the peer
/// it serves, and the per-request `SignAuthorizer` consulted before each signature.
#[derive(Clone)]
pub struct AgentSession {
    /// Reference to the agent handle
    handle: Arc<AgentHandle>,
    /// The connecting peer this session serves.
    peer: PeerIdentity,
    /// Per-request gate consulted before every signature.
    authorizer: Arc<dyn SignAuthorizer>,
}

impl AgentSession {
    /// Creates a session that allows every signature (in-process / default use).
    ///
    /// Args:
    /// * `handle`: the agent handle holding the unlocked keys.
    pub fn new(handle: Arc<AgentHandle>) -> Self {
        Self {
            handle,
            peer: PeerIdentity::local(),
            authorizer: Arc::new(AllowAllSigning),
        }
    }

    /// Creates a session for a specific peer, gated by `authorizer` on every sign.
    ///
    /// Args:
    /// * `handle`: the agent handle holding the unlocked keys.
    /// * `peer`: the connecting process's identity.
    /// * `authorizer`: the per-request signing gate.
    pub fn with_authorizer(
        handle: Arc<AgentHandle>,
        peer: PeerIdentity,
        authorizer: Arc<dyn SignAuthorizer>,
    ) -> Self {
        Self {
            handle,
            peer,
            authorizer,
        }
    }

    /// Returns a reference to the underlying agent handle.
    pub fn handle(&self) -> &AgentHandle {
        &self.handle
    }
}

impl std::fmt::Debug for AgentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSession")
            .field("socket_path", self.handle.socket_path())
            .field("is_running", &self.handle.is_running())
            .finish()
    }
}

/// Build a PKCS#8 v2 DER encoding for an Ed25519 key from seed and public key.
///
/// Ring's `Ed25519KeyPair::from_pkcs8()` requires v2 format (RFC 8410) which
/// includes the public key. Produces the fixed 85-byte structure:
pub use auths_crypto::build_ed25519_pkcs8_v2;

#[ssh_agent_lib::async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, SSHAgentError> {
        let core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        let pubkey_byte_vectors = core.public_keys();
        debug!(
            "request_identities: Agent core has {} keys.",
            pubkey_byte_vectors.len()
        );

        let identities = pubkey_byte_vectors
            .into_iter()
            .filter_map(|pubkey_bytes| {
                let key_data = match pubkey_bytes.len() {
                    32 => {
                        let key_bytes_array: &[u8; 32] = pubkey_bytes.as_slice().try_into().ok()?;
                        KeyData::Ed25519(Ed25519PublicKey(*key_bytes_array))
                    }
                    33 | 65 => {
                        // P-256: try to parse as ECDSA SEC1 point
                        let ecdsa_pk =
                            ssh_key::public::EcdsaPublicKey::from_sec1_bytes(&pubkey_bytes).ok()?;
                        KeyData::Ecdsa(ecdsa_pk)
                    }
                    n => {
                        warn!("request_identities: unsupported key length ({n}). Skipping.");
                        return None;
                    }
                };
                let comment = format!(
                    "auths-key-{}",
                    hex::encode(&pubkey_bytes[..4.min(pubkey_bytes.len())])
                );
                debug!("Adding identity with comment: {}", comment);
                Some(Identity {
                    pubkey: key_data,
                    comment,
                })
            })
            .collect();

        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, SSHAgentError> {
        if !self.authorizer.authorize_sign(&self.peer) {
            warn!(
                "Sign request refused: peer not authorized to sign (uid={}, pid={:?})",
                self.peer.uid, self.peer.pid
            );
            return Err(SSHAgentError::Failure);
        }

        debug!(
            "Handling sign request for key type: {:?}",
            request.pubkey.algorithm()
        );

        let (pubkey_bytes_to_sign_with, algorithm) = match &request.pubkey {
            KeyData::Ed25519(key) => (key.as_ref().to_vec(), Algorithm::Ed25519),
            KeyData::Ecdsa(ecdsa_key) => {
                let point_bytes = ecdsa_key.as_ref();
                (
                    point_bytes.to_vec(),
                    Algorithm::Ecdsa {
                        curve: ssh_key::EcdsaCurve::NistP256,
                    },
                )
            }
            other_key_type => {
                let err_msg = format!(
                    "Unsupported key type requested for signing: {:?}",
                    other_key_type.algorithm()
                );
                error!("{}", err_msg);
                return Err(SSHAgentError::other(io::Error::new(
                    io::ErrorKind::Unsupported,
                    err_msg,
                )));
            }
        };

        match self.handle.sign(&pubkey_bytes_to_sign_with, &request.data) {
            Ok(signature_bytes) => {
                debug!("Successfully signed data using agent core.");
                Signature::new(algorithm, signature_bytes).map_err(|e| {
                    let err_msg = format!(
                        "Internal error: Failed to create ssh_key::Signature from core signature: {}",
                        e
                    );
                    error!("{}", err_msg);
                    SSHAgentError::other(io::Error::new(io::ErrorKind::InvalidData, err_msg))
                })
            }
            Err(AuthsAgentError::KeyNotFound) => {
                warn!("Sign request failed: Key not found in agent core.");
                Err(SSHAgentError::Failure)
            }
            Err(AuthsAgentError::AgentLocked) => {
                warn!("Sign request refused: agent is locked.");
                Err(SSHAgentError::Failure)
            }
            Err(other_core_error) => {
                let err_msg = format!("Agent core signing error: {}", other_core_error);
                error!("{}", err_msg);
                Err(SSHAgentError::other(io::Error::other(err_msg)))
            }
        }
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), SSHAgentError> {
        debug!("Handling add_identity request");

        let pkcs8_bytes: Zeroizing<Vec<u8>> = match &identity.credential {
            Credential::Key { privkey, .. } => match privkey {
                KeypairData::Ed25519(kp) => {
                    let seed = kp.private.to_bytes();
                    let pubkey = kp.public.0;
                    build_ed25519_pkcs8_v2(&seed, &pubkey)
                }
                KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 {
                    private, ..
                }) => {
                    use auths_crypto::{TypedSeed, TypedSignerKey};
                    let scalar_bytes = private.as_slice();
                    if scalar_bytes.len() != 32 {
                        let err_msg = format!(
                            "Invalid P-256 scalar length: expected 32, got {}",
                            scalar_bytes.len()
                        );
                        error!("{}", err_msg);
                        return Err(SSHAgentError::other(io::Error::new(
                            io::ErrorKind::InvalidData,
                            err_msg,
                        )));
                    }
                    #[allow(clippy::expect_used)] // INVARIANT: length checked above
                    let mut scalar = [0u8; 32];
                    scalar.copy_from_slice(scalar_bytes);
                    let signer =
                        TypedSignerKey::from_seed(TypedSeed::P256(scalar)).map_err(|e| {
                            let err_msg = format!("P-256 signer construction failed: {}", e);
                            error!("{}", err_msg);
                            SSHAgentError::other(io::Error::other(err_msg))
                        })?;
                    let pkcs8 = signer.to_pkcs8().map_err(|e| {
                        let err_msg = format!("P-256 PKCS8 encoding failed: {}", e);
                        error!("{}", err_msg);
                        SSHAgentError::other(io::Error::other(err_msg))
                    })?;
                    Zeroizing::new(pkcs8.as_ref().to_vec())
                }
                other => {
                    let err_msg = format!(
                        "Unsupported key type for add_identity: {:?}",
                        other.algorithm()
                    );
                    error!("{}", err_msg);
                    return Err(SSHAgentError::other(io::Error::new(
                        io::ErrorKind::Unsupported,
                        err_msg,
                    )));
                }
            },
            Credential::Cert { .. } => {
                error!("Certificate credentials are not supported for add_identity");
                return Err(SSHAgentError::other(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Certificate credentials are not supported",
                )));
            }
        };

        self.handle.register_key(pkcs8_bytes).map_err(|e| {
            let err_msg = format!("Failed to register key in agent: {}", e);
            error!("{}", err_msg);
            SSHAgentError::other(io::Error::other(err_msg))
        })?;

        debug!("Successfully added identity to agent");
        Ok(())
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), SSHAgentError> {
        debug!("Handling remove_identity request");

        let pubkey_bytes = match &identity.pubkey {
            KeyData::Ed25519(key) => key.as_ref().to_vec(),
            KeyData::Ecdsa(key) => key.as_ref().to_vec(),
            other => {
                let err_msg = format!(
                    "Unsupported key type for remove_identity: {:?}",
                    other.algorithm()
                );
                error!("{}", err_msg);
                return Err(SSHAgentError::other(io::Error::new(
                    io::ErrorKind::Unsupported,
                    err_msg,
                )));
            }
        };

        let mut core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        core.unregister_key(&pubkey_bytes).map_err(|e| {
            let err_msg = format!("Failed to remove key from agent: {}", e);
            error!("{}", err_msg);
            SSHAgentError::other(io::Error::new(io::ErrorKind::NotFound, err_msg))
        })?;

        debug!("Successfully removed identity from agent");
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), SSHAgentError> {
        debug!("Handling remove_all_identities request");

        let mut core = self.handle.lock().map_err(|_| {
            error!("AgentSession failed to lock agent core (mutex poisoned).");
            SSHAgentError::Failure
        })?;

        core.clear_keys();
        debug!("Successfully removed all identities from agent");
        Ok(())
    }
}

/// Returns whether a connecting peer is allowed to use the agent.
///
/// Only the user that owns the running agent may request signatures; a connection
/// from any other user is refused.
///
/// Args:
/// * `peer_uid`: The effective user id of the connecting process.
/// * `owner_uid`: The effective user id that owns the agent.
///
/// Usage:
/// ```ignore
/// if peer_is_authorized(peer_uid, owner_uid) { /* serve the connection */ }
/// ```
fn peer_is_authorized(peer_uid: u32, owner_uid: u32) -> bool {
    peer_uid == owner_uid
}

/// A session for a connection, gated on peer authorization.
///
/// `Authorized` connections are served by an `AgentSession`; `Denied` connections
/// have every request refused, so an unauthorized peer can neither sign nor list keys.
#[cfg(unix)]
pub(crate) enum MaybeAuthorized {
    /// The peer owns the agent and is served normally.
    Authorized(AgentSession),
    /// The peer is not the owner; every request is refused.
    Denied,
}

#[cfg(unix)]
#[ssh_agent_lib::async_trait]
impl Session for MaybeAuthorized {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, SSHAgentError> {
        match self {
            Self::Authorized(session) => session.request_identities().await,
            Self::Denied => Err(SSHAgentError::Failure),
        }
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, SSHAgentError> {
        match self {
            Self::Authorized(session) => session.sign(request).await,
            Self::Denied => Err(SSHAgentError::Failure),
        }
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), SSHAgentError> {
        match self {
            Self::Authorized(session) => session.add_identity(identity).await,
            Self::Denied => Err(SSHAgentError::Failure),
        }
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), SSHAgentError> {
        match self {
            Self::Authorized(session) => session.remove_identity(identity).await,
            Self::Denied => Err(SSHAgentError::Failure),
        }
    }

    async fn remove_all_identities(&mut self) -> Result<(), SSHAgentError> {
        match self {
            Self::Authorized(session) => session.remove_all_identities().await,
            Self::Denied => Err(SSHAgentError::Failure),
        }
    }
}

/// Session factory that authorizes each incoming connection by peer UID before
/// handing it an `AgentSession`.
///
/// `ssh_agent_lib` calls `new_session` once per accepted connection, giving access
/// to the connecting socket. We read the peer's credentials there and refuse any
/// connection that is not the owning user (failing closed if the credentials
/// cannot be read).
#[cfg(unix)]
pub(crate) struct PeerAuthorizedAgent {
    handle: Arc<AgentHandle>,
    owner_uid: u32,
    authorizer: Arc<dyn SignAuthorizer>,
}

#[cfg(unix)]
impl PeerAuthorizedAgent {
    /// Creates a factory that serves only connections from `owner_uid`.
    ///
    /// Args:
    /// * `handle`: The agent handle that holds the unlocked keys.
    /// * `owner_uid`: The effective user id permitted to use the agent.
    ///
    /// Usage:
    /// ```ignore
    /// let agent = PeerAuthorizedAgent::new(handle, owner_uid, authorizer);
    /// ```
    pub(crate) fn new(
        handle: Arc<AgentHandle>,
        owner_uid: u32,
        authorizer: Arc<dyn SignAuthorizer>,
    ) -> Self {
        Self {
            handle,
            owner_uid,
            authorizer,
        }
    }
}

#[cfg(unix)]
impl Agent<tokio::net::UnixListener> for PeerAuthorizedAgent {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        match socket.peer_cred() {
            Ok(cred) if peer_is_authorized(cred.uid(), self.owner_uid) => {
                let peer = PeerIdentity {
                    uid: cred.uid(),
                    pid: cred.pid(),
                };
                MaybeAuthorized::Authorized(AgentSession::with_authorizer(
                    self.handle.clone(),
                    peer,
                    self.authorizer.clone(),
                ))
            }
            Ok(cred) => {
                warn!(
                    "Refusing agent connection from uid {} (agent owner uid {})",
                    cred.uid(),
                    self.owner_uid
                );
                MaybeAuthorized::Denied
            }
            Err(e) => {
                error!("Refusing agent connection: cannot read peer credentials: {e}");
                MaybeAuthorized::Denied
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use ssh_key::private::Ed25519Keypair as SshEd25519Keypair;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    fn generate_test_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate PKCS#8");
        pkcs8_doc.as_ref().to_vec()
    }

    /// A session whose per-request authorizer denies the peer must refuse to sign,
    /// even with the agent unlocked and the key present. This is the #354 gate: an
    /// unlocked agent does not grant silent signing to an unapproved same-user caller.
    #[tokio::test]
    async fn agent_refuses_to_sign_when_authorizer_denies() {
        struct DenyAll;
        impl SignAuthorizer for DenyAll {
            fn authorize_sign(&self, _peer: &PeerIdentity) -> bool {
                false
            }
        }

        let seed: [u8; 32] = {
            let pkcs8 = generate_test_pkcs8();
            let mut s = [0u8; 32];
            s.copy_from_slice(&pkcs8[16..48]);
            s
        };
        let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
        let pubkey_bytes = ssh_keypair.public.0;

        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-deny.sock")));
        let peer = PeerIdentity {
            uid: 1000,
            pid: Some(4242),
        };
        let mut session = AgentSession::with_authorizer(handle.clone(), peer, Arc::new(DenyAll));

        session
            .add_identity(AddIdentity {
                credential: Credential::Key {
                    privkey: KeypairData::Ed25519(ssh_keypair),
                    comment: "test-key".to_string(),
                },
            })
            .await
            .unwrap();
        assert_eq!(handle.key_count().unwrap(), 1);

        let request = SignRequest {
            pubkey: KeyData::Ed25519(Ed25519PublicKey(pubkey_bytes)),
            data: b"unauthorized payload".to_vec(),
            flags: 0,
        };
        let result = session.sign(request).await;
        assert!(
            result.is_err(),
            "a denied peer must not obtain a signature even when the agent is unlocked and the key is present"
        );
    }

    /// The per-caller policy: an approved caller is pinned (not re-prompted), and a
    /// *different* process — even at the same uid — triggers its own approval.
    #[test]
    fn per_caller_pins_approved_and_reprompts_a_different_process() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let prompts = Arc::new(AtomicUsize::new(0));
        let p = prompts.clone();
        let auth = PerCallerAuthorizer::new(move |peer: &PeerIdentity| {
            p.fetch_add(1, Ordering::SeqCst);
            peer.uid == 1000 // approve only the owner uid
        });

        let git = PeerIdentity {
            uid: 1000,
            pid: Some(11),
        };
        let malware = PeerIdentity {
            uid: 1000,
            pid: Some(22),
        };
        let stranger = PeerIdentity {
            uid: 1001,
            pid: Some(33),
        };

        assert!(
            auth.authorize_sign(&git),
            "first request from git is approved"
        );
        assert!(auth.authorize_sign(&git), "git is now pinned");
        assert_eq!(
            prompts.load(Ordering::SeqCst),
            1,
            "an approved caller is not re-prompted per signature"
        );

        assert!(
            !auth.authorize_sign(&stranger),
            "an unapproved peer is refused"
        );
        assert!(
            auth.authorize_sign(&malware),
            "a different same-uid process is approved by this fn, but only via its own prompt"
        );
        assert_eq!(
            prompts.load(Ordering::SeqCst),
            3,
            "a different process triggers a fresh approval; pinning is per-(uid,pid)"
        );
    }

    #[test]
    fn test_agent_session_new() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test.sock")));
        let session = AgentSession::new(handle.clone());

        assert_eq!(
            session.handle().socket_path(),
            &PathBuf::from("/tmp/test.sock")
        );
    }

    #[test]
    fn test_agent_session_clone_shares_handle() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test.sock")));

        let pkcs8_bytes = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8_bytes))
            .expect("Failed to register key");

        let session1 = AgentSession::new(handle.clone());
        let session2 = session1.clone();

        // Both sessions share the same handle
        assert_eq!(session1.handle().key_count().unwrap(), 1);
        assert_eq!(session2.handle().key_count().unwrap(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_add_identity_round_trip() {
        // Generate a test seed and create an SSH keypair from it
        let seed: [u8; 32] = {
            let pkcs8 = generate_test_pkcs8();
            // Extract seed from the PKCS#8 bytes (bytes 16..48 in ring's format)
            let mut s = [0u8; 32];
            s.copy_from_slice(&pkcs8[16..48]);
            s
        };

        let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
        let pubkey_bytes = ssh_keypair.public.0;

        // Build an AddIdentity request (what the client sends over the wire)
        let identity = AddIdentity {
            credential: Credential::Key {
                privkey: KeypairData::Ed25519(ssh_keypair),
                comment: "test-key".to_string(),
            },
        };

        // Create session with empty handle
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-add.sock")));
        let mut session = AgentSession::new(handle.clone());

        // Verify no keys initially
        assert_eq!(handle.key_count().unwrap(), 0);

        // Add the identity via the session (this is what was broken before)
        session.add_identity(identity).await.unwrap();

        // Verify the key is now registered
        assert_eq!(handle.key_count().unwrap(), 1);

        // Sign data via the session and verify the signature
        let sign_request = SignRequest {
            pubkey: KeyData::Ed25519(Ed25519PublicKey(pubkey_bytes)),
            data: b"test data for signing".to_vec(),
            flags: 0,
        };

        let signature = session.sign(sign_request).await.unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        assert!(!signature.as_bytes().is_empty());

        // Verify the signature using ring
        let ring_pubkey =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey_bytes);
        ring_pubkey
            .verify(b"test data for signing", signature.as_bytes())
            .expect("Signature verification failed");
    }

    #[tokio::test]
    async fn test_remove_identity() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-rm.sock")));
        let mut session = AgentSession::new(handle.clone());

        // Add a key via add_identity
        let seed: [u8; 32] = {
            let pkcs8 = generate_test_pkcs8();
            let mut s = [0u8; 32];
            s.copy_from_slice(&pkcs8[16..48]);
            s
        };
        let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
        let pubkey_bytes = ssh_keypair.public.0;

        let identity = AddIdentity {
            credential: Credential::Key {
                privkey: KeypairData::Ed25519(ssh_keypair),
                comment: "test-key".to_string(),
            },
        };
        session.add_identity(identity).await.unwrap();
        assert_eq!(handle.key_count().unwrap(), 1);

        // Remove it
        let remove = RemoveIdentity {
            pubkey: KeyData::Ed25519(Ed25519PublicKey(pubkey_bytes)),
        };
        session.remove_identity(remove).await.unwrap();
        assert_eq!(handle.key_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_remove_all_identities() {
        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/test-rmall.sock")));
        let mut session = AgentSession::new(handle.clone());

        // Add two keys
        for _ in 0..2 {
            let seed: [u8; 32] = {
                let pkcs8 = generate_test_pkcs8();
                let mut s = [0u8; 32];
                s.copy_from_slice(&pkcs8[16..48]);
                s
            };
            let ssh_keypair = SshEd25519Keypair::from_seed(&seed);
            let identity = AddIdentity {
                credential: Credential::Key {
                    privkey: KeypairData::Ed25519(ssh_keypair),
                    comment: "test-key".to_string(),
                },
            };
            session.add_identity(identity).await.unwrap();
        }
        assert_eq!(handle.key_count().unwrap(), 2);

        // Remove all
        session.remove_all_identities().await.unwrap();
        assert_eq!(handle.key_count().unwrap(), 0);
    }

    #[cfg(unix)]
    fn registered_sign_request(handle: &Arc<AgentHandle>) -> SignRequest {
        let pkcs8 = generate_test_pkcs8();
        handle
            .register_key(Zeroizing::new(pkcs8))
            .expect("register key");
        let pubkeys = handle.public_keys().expect("public keys");
        let pubkey_bytes: [u8; 32] = pubkeys[0]
            .as_slice()
            .try_into()
            .expect("ed25519 pubkey is 32 bytes");
        SignRequest {
            pubkey: KeyData::Ed25519(Ed25519PublicKey(pubkey_bytes)),
            data: b"data to sign".to_vec(),
            flags: 0,
        }
    }

    #[test]
    fn peer_authorized_only_for_matching_uid() {
        assert!(peer_is_authorized(1000, 1000));
        assert!(!peer_is_authorized(1001, 1000));
        assert!(!peer_is_authorized(0, 1000));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_session_serves_owner_uid() {
        use tokio::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let owner_uid = a.peer_cred().expect("peer cred").uid();

        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/peer-allow.sock")));
        let request = registered_sign_request(&handle);

        let mut agent = PeerAuthorizedAgent::new(handle, owner_uid, Arc::new(AllowAllSigning));
        let mut session = agent.new_session(&a);
        assert!(
            session.sign(request).await.is_ok(),
            "the owning uid must be able to sign"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_session_denies_foreign_uid() {
        use tokio::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let peer_uid = a.peer_cred().expect("peer cred").uid();

        let handle = Arc::new(AgentHandle::new(PathBuf::from("/tmp/peer-deny.sock")));
        let request = registered_sign_request(&handle);

        // Owner is a different uid than the connecting peer: the connection must be denied
        // even though a key is loaded and signing would otherwise succeed.
        let mut agent =
            PeerAuthorizedAgent::new(handle, peer_uid.wrapping_add(1), Arc::new(AllowAllSigning));
        let mut session = agent.new_session(&a);
        assert!(
            session.sign(request).await.is_err(),
            "a foreign-uid peer must not be able to sign"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn denied_session_refuses_every_request() {
        let mut session = MaybeAuthorized::Denied;
        assert!(session.request_identities().await.is_err());
        let request = SignRequest {
            pubkey: KeyData::Ed25519(Ed25519PublicKey([7u8; 32])),
            data: b"x".to_vec(),
            flags: 0,
        };
        assert!(session.sign(request).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn denied_session_refuses_every_request_variant() {
        use ssh_agent_lib::proto::{
            AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, Request, Response,
            SmartcardKey,
        };

        fn ed_keydata() -> KeyData {
            KeyData::Ed25519(Ed25519PublicKey([0u8; 32]))
        }
        fn an_add_identity() -> AddIdentity {
            AddIdentity {
                credential: Credential::Key {
                    privkey: KeypairData::Ed25519(SshEd25519Keypair::from_seed(&[0u8; 32])),
                    comment: String::new(),
                },
            }
        }
        fn a_smartcard() -> SmartcardKey {
            SmartcardKey {
                id: String::new(),
                pin: String::new().into(),
            }
        }

        // Every request the SSH agent protocol defines. A denied connection must refuse
        // all of them, so an upstream change that adds a permissive default cannot open
        // a hole. Payloads are minimal — a denied session never inspects them.
        let requests = vec![
            Request::RequestIdentities,
            Request::SignRequest(SignRequest {
                pubkey: ed_keydata(),
                data: Vec::new(),
                flags: 0,
            }),
            Request::AddIdentity(an_add_identity()),
            Request::RemoveIdentity(RemoveIdentity {
                pubkey: ed_keydata(),
            }),
            Request::RemoveAllIdentities,
            Request::AddSmartcardKey(a_smartcard()),
            Request::RemoveSmartcardKey(a_smartcard()),
            Request::Lock(String::new()),
            Request::Unlock(String::new()),
            Request::AddIdConstrained(AddIdentityConstrained {
                identity: an_add_identity(),
                constraints: Vec::new(),
            }),
            Request::AddSmartcardKeyConstrained(AddSmartcardKeyConstrained {
                key: a_smartcard(),
                constraints: Vec::new(),
            }),
            Request::Extension(Extension {
                name: String::new(),
                details: Vec::<u8>::new().into(),
            }),
        ];
        assert_eq!(requests.len(), 12, "all agent request variants are covered");

        for request in requests {
            let mut session = MaybeAuthorized::Denied;
            // Drive the real dispatcher and map its result the way the wire loop does.
            let response = match session.handle(request).await {
                Err(SSHAgentError::ExtensionFailure) => Response::ExtensionFailure,
                Err(_) => Response::Failure,
                Ok(r) => r,
            };
            assert!(
                matches!(response, Response::Failure | Response::ExtensionFailure),
                "a denied session must refuse every request variant, got {response:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sign_resets_idle_timer() {
        use std::time::Duration;
        let handle = Arc::new(AgentHandle::with_timeout(
            PathBuf::from("/tmp/idle-touch.sock"),
            Duration::from_millis(300),
        ));
        let request = registered_sign_request(&handle);
        let mut session = AgentSession::new(handle.clone());

        tokio::time::sleep(Duration::from_millis(200)).await;
        session.sign(request).await.expect("sign should succeed");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !handle.is_idle_timed_out(),
            "a successful sign must reset the idle timer so the agent stays unlocked"
        );
    }
}
