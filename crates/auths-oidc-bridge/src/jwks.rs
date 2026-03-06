//! RSA key management and JWK/JWKS types.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::BridgeError;

/// Manages the RSA signing key and exposes the public JWK.
pub struct KeyManager {
    /// PEM-encoded private key bytes (for jsonwebtoken).
    private_key_pem: Vec<u8>,
    /// Public JWK representation.
    pub jwk: Jwk,
    /// Previous public JWK (kept during key rotation for overlap).
    previous_jwk: Option<Jwk>,
}

/// JSON Web Key (RSA public key).
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

/// JSON Web Key Set.
#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl KeyManager {
    /// Load a key manager from a PEM-encoded RSA private key.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, BridgeError> {
        let pem_str = std::str::from_utf8(pem_bytes)
            .map_err(|e| BridgeError::KeyError(format!("invalid PEM encoding: {e}")))?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem_str)
            .map_err(|e| BridgeError::KeyError(format!("failed to parse RSA PEM: {e}")))?;
        let jwk = build_jwk(&private_key)?;
        Ok(Self {
            private_key_pem: pem_bytes.to_vec(),
            jwk,
            previous_jwk: None,
        })
    }

    /// Generate a new RSA-2048 key pair.
    pub fn generate() -> Result<Self, BridgeError> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| BridgeError::KeyError(format!("failed to generate RSA key: {e}")))?;
        let pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| BridgeError::KeyError(format!("failed to encode PEM: {e}")))?;
        let jwk = build_jwk(&private_key)?;
        Ok(Self {
            private_key_pem: pem.as_bytes().to_vec(),
            jwk,
            previous_jwk: None,
        })
    }

    /// Load from a PEM file path, or generate a new key if the file doesn't exist.
    pub fn load_or_generate(path: &std::path::Path) -> Result<Self, BridgeError> {
        if path.exists() {
            let pem = std::fs::read(path)
                .map_err(|e| BridgeError::KeyError(format!("failed to read key file: {e}")))?;
            Self::from_pem(&pem)
        } else {
            tracing::warn!(
                "No RSA key found at {}, generating ephemeral key",
                path.display()
            );
            Self::generate()
        }
    }

    /// Returns the PEM-encoded private key bytes.
    pub fn private_key_pem(&self) -> &[u8] {
        &self.private_key_pem
    }

    /// Returns the JWKS containing the public key(s).
    ///
    /// During key rotation, returns both the active and previous key.
    pub fn jwks(&self) -> Jwks {
        let mut keys = vec![self.jwk.clone()];
        if let Some(ref prev) = self.previous_jwk {
            keys.push(prev.clone());
        }
        Jwks { keys }
    }

    /// Rotate to a new key. The current key becomes the previous key
    /// (retained in JWKS for overlap), and the new PEM becomes the active signing key.
    pub fn rotate(&self, new_pem: &[u8]) -> Result<KeyManager, BridgeError> {
        let new = KeyManager::from_pem(new_pem)?;
        Ok(KeyManager {
            private_key_pem: new.private_key_pem,
            jwk: new.jwk,
            previous_jwk: Some(self.jwk.clone()),
        })
    }

    /// Remove the previous key from JWKS (call after the overlap window).
    pub fn drop_previous(&mut self) {
        self.previous_jwk = None;
    }

    /// Returns a `DecodingKey` for verifying JWTs issued by this key manager.
    ///
    /// Usage:
    /// ```ignore
    /// let dk = key_manager.decoding_key()?;
    /// let token_data = jsonwebtoken::decode::<Claims>(&token, &dk, &validation)?;
    /// ```
    pub fn decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, BridgeError> {
        jsonwebtoken::DecodingKey::from_rsa_pem(&self.private_key_pem)
            .map_err(|e| BridgeError::KeyError(format!("failed to create decoding key: {e}")))
    }
}

/// Build a JWK from an RSA private key, including RFC 7638 thumbprint as `kid`.
fn build_jwk(private_key: &RsaPrivateKey) -> Result<Jwk, BridgeError> {
    let public_key = private_key.to_public_key();
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let n = URL_SAFE_NO_PAD.encode(&n_bytes);
    let e = URL_SAFE_NO_PAD.encode(&e_bytes);

    // RFC 7638 JWK thumbprint: SHA-256 of canonical {"e":...,"kty":"RSA","n":...}
    let thumbprint_input = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    let thumbprint = Sha256::digest(thumbprint_input.as_bytes());
    let kid = URL_SAFE_NO_PAD.encode(thumbprint);

    // Verify we can produce a valid public key PEM (sanity check)
    let _pub_pem = public_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| BridgeError::KeyError(format!("failed to encode public key: {e}")))?;

    Ok(Jwk {
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        use_: "sig".to_string(),
        kid,
        n,
        e,
    })
}
