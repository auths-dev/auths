//! SSH agent client for communicating with a running agent.
//!
//! This module provides client functions to communicate with an SSH agent
//! over a Unix domain socket, enabling passphrase-free signing operations.

use crate::error::AgentError;
use log::{debug, error, info, warn};
use ssh_agent_lib::proto::Identity;
use ssh_key::PrivateKey as SshPrivateKey;
use ssh_key::private::{Ed25519Keypair as SshEd25519Keypair, KeypairData};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Status of the agent connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    /// Agent is running and responding.
    Running {
        /// Number of keys currently loaded in the agent.
        key_count: usize,
    },
    /// Agent socket exists but connection failed.
    ConnectionFailed,
    /// Agent socket does not exist.
    NotRunning,
}

/// SSH Agent protocol message types (from RFC draft-miller-ssh-agent).
mod proto {
    // Request message types
    pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
    pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;

    // Response message types
    pub const SSH_AGENT_FAILURE: u8 = 5;
    pub const SSH_AGENT_SUCCESS: u8 = 6;
    pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
}

/// Check the status of the SSH agent.
///
/// Connects to the agent socket and queries for loaded identities to verify
/// the agent is running and responsive.
///
/// # Arguments
/// * `socket_path` - Path to the agent's Unix domain socket.
///
/// # Returns
/// * `AgentStatus::Running { key_count }` if agent is running with keys.
/// * `AgentStatus::ConnectionFailed` if socket exists but connection failed.
/// * `AgentStatus::NotRunning` if socket doesn't exist.
pub fn check_agent_status<P: AsRef<Path>>(socket_path: P) -> AgentStatus {
    let socket_path = socket_path.as_ref();

    if !socket_path.exists() {
        debug!("Agent socket does not exist: {:?}", socket_path);
        return AgentStatus::NotRunning;
    }

    // Try to connect to the agent
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to connect to agent socket {:?}: {}", socket_path, e);
            return AgentStatus::ConnectionFailed;
        }
    };

    // Set a timeout for the connection
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
        warn!("Failed to set read timeout: {}", e);
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(5))) {
        warn!("Failed to set write timeout: {}", e);
    }

    // Send SSH_AGENTC_REQUEST_IDENTITIES
    match request_identities_raw(&mut stream) {
        Ok(identities) => {
            info!("Agent is running with {} keys loaded", identities.len());
            AgentStatus::Running {
                key_count: identities.len(),
            }
        }
        Err(e) => {
            warn!("Failed to query agent identities: {}", e);
            AgentStatus::ConnectionFailed
        }
    }
}

/// Sign data using a key loaded in the SSH agent.
///
/// This function communicates with the agent to sign data using the specified
/// public key. The key must already be loaded in the agent.
///
/// # Arguments
/// * `socket_path` - Path to the agent's Unix domain socket.
/// * `pubkey` - The 32-byte Ed25519 public key bytes.
/// * `data` - The data to sign.
///
/// # Returns
/// * `Ok(Vec<u8>)` - The signature bytes on success.
/// * `Err(AgentError)` - On failure.
pub fn agent_sign<P: AsRef<Path>>(
    socket_path: P,
    pubkey: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AgentError> {
    let socket_path = socket_path.as_ref();

    debug!(
        "Signing via agent at {:?} with pubkey {:?}...",
        socket_path,
        hex::encode(&pubkey[..4.min(pubkey.len())])
    );

    // Connect to the agent
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        error!("Failed to connect to agent: {}", e);
        AgentError::IO(e)
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(AgentError::IO)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(AgentError::IO)?;

    // Build the sign request — detect key type from length
    let key_data = match pubkey.len() {
        32 => {
            #[allow(clippy::unwrap_used)] // INVARIANT: length checked
            let pubkey_array: [u8; 32] = pubkey.try_into().unwrap();
            KeyData::Ed25519(Ed25519PublicKey(pubkey_array))
        }
        33 | 65 => {
            let ecdsa_pk = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(pubkey)
                .map_err(|e| AgentError::InvalidInput(format!("Invalid P-256 public key: {e}")))?;
            KeyData::Ecdsa(ecdsa_pk)
        }
        n => {
            return Err(AgentError::InvalidInput(format!(
                "Unsupported public key length for agent signing: {n}"
            )));
        }
    };

    // Encode the sign request using the wire protocol
    let signature = sign_request_raw(&mut stream, &key_data, data)?;

    debug!("Successfully signed via agent");
    Ok(signature)
}

/// Add an identity (private key) to the SSH agent.
///
/// This function loads a private key into the agent so it can be used for
/// subsequent signing operations without requiring a passphrase.
///
/// # Arguments
/// * `socket_path` - Path to the agent's Unix domain socket.
/// * `pkcs8_bytes` - The PKCS#8 encoded Ed25519 private key bytes.
///
/// # Returns
/// * `Ok(Vec<u8>)` - The public key bytes of the added identity.
/// * `Err(AgentError)` - On failure.
pub fn add_identity<P: AsRef<Path>>(
    socket_path: P,
    pkcs8_bytes: &[u8],
) -> Result<Vec<u8>, AgentError> {
    let socket_path = socket_path.as_ref();

    debug!("Adding identity to agent at {:?}", socket_path);

    // Parse the PKCS#8 to detect curve + extract seed+public
    let parsed = auths_crypto::parse_key_material(pkcs8_bytes)
        .map_err(|e| AgentError::KeyDeserializationError(e.to_string()))?;

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        error!("Failed to connect to agent: {}", e);
        AgentError::IO(e)
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(AgentError::IO)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(AgentError::IO)?;

    let (keypair_data, pubkey_bytes) = match parsed.seed.curve() {
        auths_crypto::CurveType::Ed25519 => {
            let ssh_keypair = SshEd25519Keypair::from_seed(parsed.seed.as_bytes());
            let pubkey = ssh_keypair.public.0.to_vec();
            (KeypairData::Ed25519(ssh_keypair), pubkey)
        }
        auths_crypto::CurveType::P256 => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey};

            let secret = p256::SecretKey::from_slice(parsed.seed.as_bytes())
                .map_err(|e| AgentError::CryptoError(format!("P-256 secret key parse: {e}")))?;
            let public = secret.public_key();
            let keypair = EcdsaKeypair::NistP256 {
                public: public.to_encoded_point(false),
                private: EcdsaPrivateKey::from(secret),
            };
            (KeypairData::Ecdsa(keypair), parsed.public_key.clone())
        }
    };

    let private_key = SshPrivateKey::new(keypair_data, "auths-key")
        .map_err(|e| AgentError::CryptoError(format!("Failed to create SSH key: {}", e)))?;

    add_identity_raw(&mut stream, &private_key)?;

    info!(
        "Successfully added identity to agent: {:?}...",
        hex::encode(&pubkey_bytes[..4.min(pubkey_bytes.len())])
    );
    Ok(pubkey_bytes)
}

/// List all identities (public keys) loaded in the agent.
///
/// # Arguments
/// * `socket_path` - Path to the agent's Unix domain socket.
///
/// # Returns
/// * `Ok(Vec<Vec<u8>>)` - List of public key bytes on success.
/// * `Err(AgentError)` - On failure.
pub fn list_identities<P: AsRef<Path>>(socket_path: P) -> Result<Vec<Vec<u8>>, AgentError> {
    let socket_path = socket_path.as_ref();

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        error!("Failed to connect to agent: {}", e);
        AgentError::IO(e)
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(AgentError::IO)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(AgentError::IO)?;

    let identities = request_identities_raw(&mut stream)?;

    let pubkeys: Vec<Vec<u8>> = identities
        .into_iter()
        .filter_map(|id| match id.pubkey {
            KeyData::Ed25519(pk) => Some(pk.0.to_vec()),
            KeyData::Ecdsa(pk) => Some(pk.as_ref().to_vec()),
            _ => None,
        })
        .collect();

    Ok(pubkeys)
}

/// Remove all identities (keys) from the SSH agent.
///
/// This clears all loaded keys from the agent's memory, effectively
/// "locking" the agent so no signing operations can proceed until
/// keys are re-added.
///
/// # Arguments
/// * `socket_path` - Path to the agent's Unix domain socket.
pub fn remove_all_identities<P: AsRef<Path>>(socket_path: P) -> Result<(), AgentError> {
    let socket_path = socket_path.as_ref();

    debug!("Removing all identities from agent at {:?}", socket_path);

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        error!("Failed to connect to agent: {}", e);
        AgentError::IO(e)
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(AgentError::IO)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(AgentError::IO)?;

    let msg = [proto::SSH_AGENTC_REMOVE_ALL_IDENTITIES];
    send_message(&mut stream, &msg)?;

    let response = read_message(&mut stream)?;
    if response.is_empty() {
        return Err(AgentError::Proto(
            "Empty remove-all response from agent".to_string(),
        ));
    }

    match response[0] {
        proto::SSH_AGENT_SUCCESS => {
            info!("All identities removed from agent");
            Ok(())
        }
        proto::SSH_AGENT_FAILURE => Err(AgentError::Proto(
            "Agent refused to remove identities".to_string(),
        )),
        other => Err(AgentError::Proto(format!(
            "Unexpected remove-all response: {}",
            other
        ))),
    }
}

// --- Internal protocol helpers ---

/// Send SSH_AGENTC_REQUEST_IDENTITIES and parse response.
fn request_identities_raw(stream: &mut UnixStream) -> Result<Vec<Identity>, AgentError> {
    // Send request: length (4 bytes) + message type (1 byte)
    let msg = [proto::SSH_AGENTC_REQUEST_IDENTITIES];
    send_message(stream, &msg)?;

    // Read response
    let response = read_message(stream)?;

    if response.is_empty() {
        return Err(AgentError::Proto("Empty response from agent".to_string()));
    }

    match response[0] {
        proto::SSH_AGENT_IDENTITIES_ANSWER => parse_identities_answer(&response[1..]),
        proto::SSH_AGENT_FAILURE => Err(AgentError::Proto("Agent returned failure".to_string())),
        other => Err(AgentError::Proto(format!(
            "Unexpected response type: {}",
            other
        ))),
    }
}

/// Parse SSH_AGENT_IDENTITIES_ANSWER message.
fn parse_identities_answer(data: &[u8]) -> Result<Vec<Identity>, AgentError> {
    if data.len() < 4 {
        return Err(AgentError::Proto("Identities answer too short".to_string()));
    }

    let num_keys = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut identities = Vec::with_capacity(num_keys);
    let mut pos = 4;

    for _ in 0..num_keys {
        // Read key blob length
        if pos + 4 > data.len() {
            return Err(AgentError::Proto("Truncated key blob length".to_string()));
        }
        let blob_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        // Read key blob
        if pos + blob_len > data.len() {
            return Err(AgentError::Proto("Truncated key blob".to_string()));
        }
        let blob = &data[pos..pos + blob_len];
        pos += blob_len;

        // Read comment length
        if pos + 4 > data.len() {
            return Err(AgentError::Proto("Truncated comment length".to_string()));
        }
        let comment_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        // Read comment
        if pos + comment_len > data.len() {
            return Err(AgentError::Proto("Truncated comment".to_string()));
        }
        let comment = String::from_utf8_lossy(&data[pos..pos + comment_len]).to_string();
        pos += comment_len;

        // Parse the key blob
        if let Some(pubkey) = parse_ssh_pubkey_blob(blob) {
            identities.push(Identity { pubkey, comment });
        }
    }

    Ok(identities)
}

/// Parse an SSH public key blob.
fn parse_ssh_pubkey_blob(blob: &[u8]) -> Option<KeyData> {
    if blob.len() < 4 {
        return None;
    }

    // Read key type string length
    let type_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if blob.len() < 4 + type_len {
        return None;
    }

    let key_type = std::str::from_utf8(&blob[4..4 + type_len]).ok()?;
    let rest = &blob[4 + type_len..];

    match key_type {
        "ssh-ed25519" => {
            if rest.len() < 4 {
                return None;
            }
            let key_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if rest.len() < 4 + key_len || key_len != 32 {
                return None;
            }
            let key_bytes: [u8; 32] = rest[4..4 + 32].try_into().ok()?;
            Some(KeyData::Ed25519(Ed25519PublicKey(key_bytes)))
        }
        "ecdsa-sha2-nistp256" => {
            // ECDSA SSH format: curve-name-string + ec-point-string
            if rest.len() < 4 {
                return None;
            }
            let curve_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let after_curve = 4 + curve_len;
            if rest.len() < after_curve + 4 {
                return None;
            }
            let point_len =
                u32::from_be_bytes(rest[after_curve..after_curve + 4].try_into().ok()?) as usize;
            let point_start = after_curve + 4;
            if rest.len() < point_start + point_len {
                return None;
            }
            let point = &rest[point_start..point_start + point_len];
            let ecdsa_pk = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(point).ok()?;
            Some(KeyData::Ecdsa(ecdsa_pk))
        }
        _ => None,
    }
}

/// Send a sign request and get the signature.
fn sign_request_raw(
    stream: &mut UnixStream,
    pubkey: &KeyData,
    data: &[u8],
) -> Result<Vec<u8>, AgentError> {
    // Encode the public key blob
    let pubkey_blob = encode_pubkey_blob(pubkey)?;

    // Build the sign request message
    let mut msg = Vec::new();
    msg.push(proto::SSH_AGENTC_SIGN_REQUEST);

    // Key blob (length-prefixed)
    msg.extend_from_slice(&(pubkey_blob.len() as u32).to_be_bytes());
    msg.extend_from_slice(&pubkey_blob);

    // Data to sign (length-prefixed)
    msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
    msg.extend_from_slice(data);

    // Flags (0 for default)
    msg.extend_from_slice(&0u32.to_be_bytes());

    send_message(stream, &msg)?;

    // Read response
    let response = read_message(stream)?;

    if response.is_empty() {
        return Err(AgentError::Proto("Empty sign response".to_string()));
    }

    match response[0] {
        proto::SSH_AGENT_SIGN_RESPONSE => parse_sign_response(&response[1..]),
        proto::SSH_AGENT_FAILURE => Err(AgentError::SigningFailed(
            "Agent refused to sign".to_string(),
        )),
        other => Err(AgentError::Proto(format!(
            "Unexpected sign response type: {}",
            other
        ))),
    }
}

/// Parse SSH_AGENT_SIGN_RESPONSE message.
fn parse_sign_response(data: &[u8]) -> Result<Vec<u8>, AgentError> {
    if data.len() < 4 {
        return Err(AgentError::Proto("Sign response too short".to_string()));
    }

    // Read signature blob length
    let sig_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + sig_len {
        return Err(AgentError::Proto("Truncated signature blob".to_string()));
    }

    let sig_blob = &data[4..4 + sig_len];

    // Parse the signature blob (format: string type, string sig)
    if sig_blob.len() < 4 {
        return Err(AgentError::Proto("Signature blob too short".to_string()));
    }

    let type_len =
        u32::from_be_bytes([sig_blob[0], sig_blob[1], sig_blob[2], sig_blob[3]]) as usize;
    if sig_blob.len() < 4 + type_len + 4 {
        return Err(AgentError::Proto("Truncated signature type".to_string()));
    }

    let rest = &sig_blob[4 + type_len..];
    let sig_data_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if rest.len() < 4 + sig_data_len {
        return Err(AgentError::Proto("Truncated signature data".to_string()));
    }

    Ok(rest[4..4 + sig_data_len].to_vec())
}

/// Encode a public key as an SSH blob.
fn encode_pubkey_blob(pubkey: &KeyData) -> Result<Vec<u8>, AgentError> {
    match pubkey {
        KeyData::Ed25519(pk) => Ok(crate::crypto::ssh::encode_ssh_pubkey(
            &pk.0,
            auths_crypto::CurveType::Ed25519,
        )),
        KeyData::Ecdsa(pk) => Ok(crate::crypto::ssh::encode_ssh_pubkey(
            pk.as_ref(),
            auths_crypto::CurveType::P256,
        )),
        _ => Err(AgentError::InvalidInput(
            "Only Ed25519 and NistP256 keys are supported".to_string(),
        )),
    }
}

/// Send add identity request.
fn add_identity_raw(
    stream: &mut UnixStream,
    private_key: &SshPrivateKey,
) -> Result<(), AgentError> {
    // Encode the add identity message
    let mut msg = Vec::new();
    msg.push(proto::SSH_AGENTC_ADD_IDENTITY);

    match private_key.key_data() {
        KeypairData::Ed25519(kp) => {
            // Key type string
            let key_type = b"ssh-ed25519";
            msg.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
            msg.extend_from_slice(key_type);

            // Public key (32 bytes, length-prefixed)
            msg.extend_from_slice(&32u32.to_be_bytes());
            msg.extend_from_slice(&kp.public.0);

            // Private key (64 bytes = seed + public, length-prefixed)
            let mut priv_bytes = Vec::with_capacity(64);
            priv_bytes.extend_from_slice(&kp.private.to_bytes());
            priv_bytes.extend_from_slice(&kp.public.0);
            msg.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
            msg.extend_from_slice(&priv_bytes);

            // Comment
            let comment = b"auths-key";
            msg.extend_from_slice(&(comment.len() as u32).to_be_bytes());
            msg.extend_from_slice(comment);
        }
        KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 { public, private }) => {
            // Key type string
            let key_type = b"ecdsa-sha2-nistp256";
            msg.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
            msg.extend_from_slice(key_type);

            // Curve name
            let curve_name = b"nistp256";
            msg.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
            msg.extend_from_slice(curve_name);

            // Public key (SEC1 uncompressed encoding)
            let public_bytes = public.as_bytes();
            msg.extend_from_slice(&(public_bytes.len() as u32).to_be_bytes());
            msg.extend_from_slice(public_bytes);

            // Private scalar (mpint-encoded — RFC 5656 §3.1.2)
            let scalar_bytes = private.as_slice();
            let mpint = crate::crypto::ssh::encode_mpint_for_agent(scalar_bytes);
            msg.extend_from_slice(&(mpint.len() as u32).to_be_bytes());
            msg.extend_from_slice(&mpint);

            // Comment
            let comment = b"auths-key";
            msg.extend_from_slice(&(comment.len() as u32).to_be_bytes());
            msg.extend_from_slice(comment);
        }
        _ => {
            return Err(AgentError::InvalidInput(
                "Only Ed25519 and NistP256 keys are supported".to_string(),
            ));
        }
    }

    send_message(stream, &msg)?;

    // Read response
    let response = read_message(stream)?;

    if response.is_empty() {
        return Err(AgentError::Proto("Empty add identity response".to_string()));
    }

    match response[0] {
        proto::SSH_AGENT_SUCCESS => Ok(()),
        proto::SSH_AGENT_FAILURE => Err(AgentError::Proto(
            "Agent refused to add identity".to_string(),
        )),
        other => Err(AgentError::Proto(format!(
            "Unexpected add identity response: {}",
            other
        ))),
    }
}

/// Send a length-prefixed message to the agent.
fn send_message(stream: &mut UnixStream, msg: &[u8]) -> Result<(), AgentError> {
    let len = (msg.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(AgentError::IO)?;
    stream.write_all(msg).map_err(AgentError::IO)?;
    stream.flush().map_err(AgentError::IO)?;
    Ok(())
}

/// Read a length-prefixed message from the agent.
fn read_message(stream: &mut UnixStream) -> Result<Vec<u8>, AgentError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(AgentError::IO)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 256 * 1024 {
        return Err(AgentError::Proto(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).map_err(AgentError::IO)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_agent_status_not_running() {
        let status = check_agent_status("/nonexistent/path/to/socket.sock");
        assert_eq!(status, AgentStatus::NotRunning);
    }

    #[test]
    fn test_encode_pubkey_blob() {
        let pubkey = Ed25519PublicKey([0x42; 32]);
        let key_data = KeyData::Ed25519(pubkey);
        let blob = encode_pubkey_blob(&key_data).unwrap();

        // Verify format: 4-byte length + "ssh-ed25519" + 4-byte length + 32-byte key
        assert_eq!(&blob[0..4], &11u32.to_be_bytes()); // "ssh-ed25519" length
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes()); // key length
        assert_eq!(&blob[19..51], &[0x42; 32]); // key data
    }

    #[test]
    fn test_parse_ssh_pubkey_blob() {
        // Create a valid Ed25519 blob
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes()); // type length
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes()); // key length
        blob.extend_from_slice(&[0x42; 32]); // key data

        let result = parse_ssh_pubkey_blob(&blob);
        assert!(result.is_some());

        if let Some(KeyData::Ed25519(pk)) = result {
            assert_eq!(pk.0, [0x42; 32]);
        } else {
            panic!("Expected Ed25519 key");
        }
    }

    #[test]
    fn test_parse_invalid_pkcs8() {
        let result = auths_crypto::parse_key_material(&[0u8; 10]);
        assert!(result.is_err());
    }
}
