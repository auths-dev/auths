//! Error code registry — **generated** by `cargo xtask gen-error-docs`.
//!
//! Do not edit manually. Re-run the generator after changing any `AuthsErrorInfo` impl:
//! ```sh
//! cargo xtask gen-error-docs
//! ```
//!
//! ## Range Allocation
//!
//! | Range   | Crate            | Layer |
//! |---------|------------------|-------|
//! | E0xxx   | Reserved/meta    | -     |
//! | E1xxx   | auths-crypto     | 0     |
//! | E2xxx   | auths-verifier   | 1     |
//! | E3xxx   | auths-core       | 2     |
//! | E4xxx   | auths-id         | 3     |
//! | E5xxx   | auths-sdk        | 3-4   |
//! | E6xxx   | auths-cli        | 6     |

/// Returns the explanation markdown for a given error code, or `None` if unknown.
///
/// Args:
/// * `code`: An error code string like `"AUTHS-E3001"`.
pub fn explain(code: &str) -> Option<&'static str> {
    match code {
        // --- auths-crypto (CryptoError) ---
        "AUTHS-E1001" => Some(
            "# AUTHS-E1001\n\n**Crate:** `auths-crypto`  \n**Type:** `CryptoError::InvalidSignature`\n\n## Message\n\nInvalid signature\n\n## Suggestion\n\nThe signature does not match the data or public key\n",
        ),
        "AUTHS-E1003" => Some(
            "# AUTHS-E1003\n\n**Crate:** `auths-crypto`  \n**Type:** `CryptoError::InvalidPrivateKey`\n\n## Message\n\nInvalid private key: {0}\n",
        ),
        "AUTHS-E1004" => Some(
            "# AUTHS-E1004\n\n**Crate:** `auths-crypto`  \n**Type:** `CryptoError::OperationFailed`\n\n## Message\n\nCrypto operation failed: {0}\n",
        ),
        "AUTHS-E1005" => Some(
            "# AUTHS-E1005\n\n**Crate:** `auths-crypto`  \n**Type:** `CryptoError::UnsupportedTarget`\n\n## Message\n\nOperation not supported on current compilation target\n",
        ),

        // --- auths-crypto (DidKeyError) ---
        "AUTHS-E1101" => Some(
            "# AUTHS-E1101\n\n**Crate:** `auths-crypto`  \n**Type:** `DidKeyError::InvalidPrefix`\n\n## Message\n\nDID must start with 'did:key:z', got: {0}\n\n## Suggestion\n\nDID must start with 'did:key:z'\n",
        ),
        "AUTHS-E1102" => Some(
            "# AUTHS-E1102\n\n**Crate:** `auths-crypto`  \n**Type:** `DidKeyError::Base58DecodeFailed`\n\n## Message\n\nBase58 decoding failed: {0}\n",
        ),
        "AUTHS-E1103" => Some(
            "# AUTHS-E1103\n\n**Crate:** `auths-crypto`  \n**Type:** `DidKeyError::UnsupportedMulticodec`\n\n## Message\n\nUnsupported or malformed multicodec: expected Ed25519 [0xED, 0x01] or P-256 [0x80, 0x24]\n\n## Suggestion\n\nUse a `did:key:` with a supported multicodec prefix (Ed25519: `z6Mk…`, P-256: `zDna…`)\n",
        ),
        "AUTHS-E1104" => Some(
            "# AUTHS-E1104\n\n**Crate:** `auths-crypto`  \n**Type:** `DidKeyError::InvalidKeyLength`\n\n## Message\n\nInvalid public key length: expected 32 bytes (Ed25519) or 33 bytes (P-256 compressed SEC1), got {0}\n",
        ),

        // --- auths-crypto (KeriDecodeError) ---
        "AUTHS-E1201" => Some(
            "# AUTHS-E1201\n\n**Crate:** `auths-crypto`  \n**Type:** `KeriDecodeError::InvalidPrefix`\n\n## Message\n\nUnsupported KERI key prefix: got '{0}', expected 'D' (Ed25519) or '1AAI' (P-256)\n\n## Suggestion\n\nKERI verkeys use CESR derivation codes: `D` for Ed25519 (32 bytes) or `1AAI` for P-256 compressed SEC1 (33 bytes). `1AAJ` is the spec's P-256 *signature* code; do not use as a verkey.\n",
        ),
        "AUTHS-E1202" => Some(
            "# AUTHS-E1202\n\n**Crate:** `auths-crypto`  \n**Type:** `KeriDecodeError::EmptyInput`\n\n## Message\n\nMissing KERI prefix: empty string\n\n## Suggestion\n\nProvide a non-empty KERI-encoded key string\n",
        ),
        "AUTHS-E1203" => Some(
            "# AUTHS-E1203\n\n**Crate:** `auths-crypto`  \n**Type:** `KeriDecodeError::DecodeError`\n\n## Message\n\nBase64url decode failed: {0}\n",
        ),
        "AUTHS-E1204" => Some(
            "# AUTHS-E1204\n\n**Crate:** `auths-crypto`  \n**Type:** `KeriDecodeError::InvalidLength`\n\n## Message\n\nInvalid KERI verkey length: expected 32 bytes (Ed25519, `D` prefix) or 33 bytes (P-256 compressed SEC1, `1AAI` prefix), got {0}\n",
        ),

        // --- auths-crypto (SshKeyError) ---
        "AUTHS-E1301" => Some(
            "# AUTHS-E1301\n\n**Crate:** `auths-crypto`  \n**Type:** `SshKeyError::InvalidFormat`\n\n## Message\n\nMalformed or invalid OpenSSH public key: {0}\n\n## Suggestion\n\nCheck that the public key is a valid OpenSSH format\n",
        ),
        "AUTHS-E1302" => Some(
            "# AUTHS-E1302\n\n**Crate:** `auths-crypto`  \n**Type:** `SshKeyError::UnsupportedKeyType`\n\n## Message\n\nUnsupported key type: expected ssh-ed25519\n\n## Suggestion\n\nOnly ssh-ed25519 keys are supported\n",
        ),

        // --- auths-verifier (AttestationError) ---
        "AUTHS-E2001" => Some(
            "# AUTHS-E2001\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::IssuerSignatureFailed`\n\n## Message\n\nIssuer signature verification failed: {0}\n",
        ),
        "AUTHS-E2002" => Some(
            "# AUTHS-E2002\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::DeviceSignatureFailed`\n\n## Message\n\nDevice signature verification failed: {0}\n\n## Suggestion\n\nVerify the device key matches the attestation\n",
        ),
        "AUTHS-E2003" => Some(
            "# AUTHS-E2003\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::AttestationExpired`\n\n## Message\n\nAttestation expired on {at}\n\n## Suggestion\n\nRequest a new attestation from the issuer\n",
        ),
        "AUTHS-E2004" => Some(
            "# AUTHS-E2004\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::AttestationRevoked`\n\n## Message\n\nAttestation revoked\n",
        ),
        "AUTHS-E2005" => Some(
            "# AUTHS-E2005\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::TimestampInFuture`\n\n## Message\n\nAttestation timestamp {at} is in the future\n\n## Suggestion\n\nCheck system clock synchronization\n",
        ),
        "AUTHS-E2006" => Some(
            "# AUTHS-E2006\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::MissingCapability`\n\n## Message\n\nMissing required capability: required {required:?}, available {available:?}\n",
        ),
        "AUTHS-E2007" => Some(
            "# AUTHS-E2007\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::SigningError`\n\n## Message\n\nSigning failed: {0}\n",
        ),
        "AUTHS-E2008" => Some(
            "# AUTHS-E2008\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::DidResolutionError`\n\n## Message\n\nDID resolution failed: {0}\n\n## Suggestion\n\nCheck that the DID is valid and resolvable\n",
        ),
        "AUTHS-E2009" => Some(
            "# AUTHS-E2009\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::SerializationError`\n\n## Message\n\nSerialization error: {0}\n",
        ),
        "AUTHS-E2010" => Some(
            "# AUTHS-E2010\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::InputTooLarge`\n\n## Message\n\nInput too large: {0}\n",
        ),
        "AUTHS-E2011" => Some(
            "# AUTHS-E2011\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::InvalidInput`\n\n## Message\n\nInvalid input: {0}\n",
        ),
        "AUTHS-E2012" => Some(
            "# AUTHS-E2012\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::CryptoError`\n\n## Message\n\nCrypto error: {0}\n",
        ),
        "AUTHS-E2013" => Some(
            "# AUTHS-E2013\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::InternalError`\n\n## Message\n\nInternal error: {0}\n",
        ),
        "AUTHS-E2014" => Some(
            "# AUTHS-E2014\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::OrgVerificationFailed`\n\n## Message\n\nOrganizational Attestation verification failed: {0}\n",
        ),
        "AUTHS-E2015" => Some(
            "# AUTHS-E2015\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::OrgAttestationExpired`\n\n## Message\n\nOrganizational Attestation expired\n",
        ),
        "AUTHS-E2016" => Some(
            "# AUTHS-E2016\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::OrgDidResolutionFailed`\n\n## Message\n\nOrganizational DID resolution failed: {0}\n",
        ),
        "AUTHS-E2017" => Some(
            "# AUTHS-E2017\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::BundleExpired`\n\n## Message\n\nBundle is {age_secs}s old (max {max_secs}s). Refresh with: auths id export-bundle\n",
        ),
        "AUTHS-E2018" => Some(
            "# AUTHS-E2018\n\n**Crate:** `auths-verifier`  \n**Type:** `AttestationError::AttestationTooOld`\n\n## Message\n\nAttestation is {age_secs}s old (max {max_secs}s)\n",
        ),

        // --- auths-verifier (CommitVerificationError) ---
        "AUTHS-E2101" => Some(
            "# AUTHS-E2101\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::UnsignedCommit`\n\n## Message\n\ncommit is unsigned\n\n## Suggestion\n\nSign commits with: git commit -S\n",
        ),
        "AUTHS-E2102" => Some(
            "# AUTHS-E2102\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::GpgNotSupported`\n\n## Message\n\nGPG signatures not supported, use SSH signing\n\n## Suggestion\n\nConfigure SSH signing: git config gpg.format ssh\n",
        ),
        "AUTHS-E2103" => Some(
            "# AUTHS-E2103\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::SshSigParseFailed`\n\n## Message\n\nSSHSIG parse failed: {0}\n",
        ),
        "AUTHS-E2104" => Some(
            "# AUTHS-E2104\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::UnsupportedKeyType`\n\n## Message\n\nunsupported SSH key type: {found}\n\n## Suggestion\n\nUse `ssh-ed25519` (Ed25519) or `ecdsa-sha2-nistp256` (P-256, RFC 5656) for signing\n",
        ),
        "AUTHS-E2105" => Some(
            "# AUTHS-E2105\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::NamespaceMismatch`\n\n## Message\n\nnamespace mismatch: expected \\\"{expected}\\\", found \\\"{found}\\\"\n",
        ),
        "AUTHS-E2106" => Some(
            "# AUTHS-E2106\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::HashAlgorithmUnsupported`\n\n## Message\n\nunsupported hash algorithm: {0}\n",
        ),
        "AUTHS-E2107" => Some(
            "# AUTHS-E2107\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::SignatureInvalid`\n\n## Message\n\nsignature verification failed\n",
        ),
        "AUTHS-E2108" => Some(
            "# AUTHS-E2108\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::UnknownSigner`\n\n## Message\n\nsigner key not in allowed keys\n\n## Suggestion\n\nAdd the signer's key to the allowed signers list\n",
        ),
        "AUTHS-E2109" => Some(
            "# AUTHS-E2109\n\n**Crate:** `auths-verifier`  \n**Type:** `CommitVerificationError::CommitParseFailed`\n\n## Message\n\ncommit parse failed: {0}\n",
        ),

        // --- auths-core (AgentError) ---
        "AUTHS-E3001" => Some(
            "# AUTHS-E3001\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::KeyNotFound`\n\n## Message\n\nKey not found\n\n## Suggestion\n\nRun `auths key list` to see available keys\n",
        ),
        "AUTHS-E3002" => Some(
            "# AUTHS-E3002\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::IncorrectPassphrase`\n\n## Message\n\nIncorrect passphrase\n",
        ),
        "AUTHS-E3003" => Some(
            "# AUTHS-E3003\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::MissingPassphrase`\n\n## Message\n\nMissing Passphrase\n",
        ),
        "AUTHS-E3004" => Some(
            "# AUTHS-E3004\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::SecurityError`\n\n## Message\n\nSecurity error: {0}\n",
        ),
        "AUTHS-E3005" => Some(
            "# AUTHS-E3005\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::CryptoError`\n\n## Message\n\nCrypto error: {0}\n",
        ),
        "AUTHS-E3006" => Some(
            "# AUTHS-E3006\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::KeyDeserializationError`\n\n## Message\n\nKey deserialization error: {0}\n",
        ),
        "AUTHS-E3007" => Some(
            "# AUTHS-E3007\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::SigningFailed`\n\n## Message\n\nSigning failed: {0}\n",
        ),
        "AUTHS-E3008" => Some(
            "# AUTHS-E3008\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::Proto`\n\n## Message\n\nProtocol error: {0}\n",
        ),
        "AUTHS-E3009" => Some(
            "# AUTHS-E3009\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::IO`\n\n## Message\n\nIO error: {0}\n\n## Suggestion\n\nCheck file permissions and that the filesystem is not read-only\n",
        ),
        "AUTHS-E3010" => Some(
            "# AUTHS-E3010\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::GitError`\n\n## Message\n\ngit error: {0}\n\n## Suggestion\n\nEnsure you're in a Git repository\n",
        ),
        "AUTHS-E3011" => Some(
            "# AUTHS-E3011\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::InvalidInput`\n\n## Message\n\nInvalid input: {0}\n\n## Suggestion\n\nCheck the command arguments and try again\n",
        ),
        "AUTHS-E3012" => Some(
            "# AUTHS-E3012\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::MutexError`\n\n## Message\n\nMutex lock poisoned: {0}\n\n## Suggestion\n\nA concurrency error occurred; restart the operation\n",
        ),
        "AUTHS-E3013" => Some(
            "# AUTHS-E3013\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::StorageError`\n\n## Message\n\nStorage error: {0}\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),
        "AUTHS-E3014" => Some(
            "# AUTHS-E3014\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::UserInputCancelled`\n\n## Message\n\nUser input cancelled\n",
        ),
        "AUTHS-E3015" => Some(
            "# AUTHS-E3015\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::BackendUnavailable`\n\n## Message\n\nKeychain backend unavailable: {backend} - {reason}\n",
        ),
        "AUTHS-E3016" => Some(
            "# AUTHS-E3016\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::StorageLocked`\n\n## Message\n\nStorage is locked, authentication required\n\n## Suggestion\n\nAuthenticate with your platform keychain\n",
        ),
        "AUTHS-E3017" => Some(
            "# AUTHS-E3017\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::BackendInitFailed`\n\n## Message\n\nFailed to initialize keychain backend: {backend} - {error}\n",
        ),
        "AUTHS-E3018" => Some(
            "# AUTHS-E3018\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::CredentialTooLarge`\n\n## Message\n\nCredential too large for backend (max {max_bytes} bytes, got {actual_bytes})\n",
        ),
        "AUTHS-E3019" => Some(
            "# AUTHS-E3019\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::AgentLocked`\n\n## Message\n\nAgent is locked. Unlock with 'auths agent unlock' or restart the agent.\n",
        ),
        "AUTHS-E3020" => Some(
            "# AUTHS-E3020\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::WeakPassphrase`\n\n## Message\n\nPassphrase too weak: {0}\n",
        ),
        "AUTHS-E3021" => Some(
            "# AUTHS-E3021\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::HsmPinLocked`\n\n## Message\n\nHSM PIN is locked — reset required\n\n## Suggestion\n\nReset the HSM PIN using your HSM vendor's admin tools\n",
        ),
        "AUTHS-E3022" => Some(
            "# AUTHS-E3022\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::HsmDeviceRemoved`\n\n## Message\n\nHSM device removed\n\n## Suggestion\n\nReconnect the HSM device and try again\n",
        ),
        "AUTHS-E3023" => Some(
            "# AUTHS-E3023\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::HsmSessionExpired`\n\n## Message\n\nHSM session expired\n\n## Suggestion\n\nRetry the operation — a new session will be opened\n",
        ),
        "AUTHS-E3024" => Some(
            "# AUTHS-E3024\n\n**Crate:** `auths-core`  \n**Type:** `AgentError::HsmUnsupportedMechanism`\n\n## Message\n\nHSM does not support mechanism: {0}\n",
        ),

        // --- auths-core (TrustError) ---
        "AUTHS-E3101" => Some(
            "# AUTHS-E3101\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::Io`\n\n## Message\n\nI/O error: {0}\n\n## Suggestion\n\nCheck disk space and file permissions\n",
        ),
        "AUTHS-E3102" => Some(
            "# AUTHS-E3102\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::InvalidData`\n\n## Message\n\n{0}\n",
        ),
        "AUTHS-E3103" => Some(
            "# AUTHS-E3103\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::NotFound`\n\n## Message\n\nnot found: {0}\n\n## Suggestion\n\nRun `auths trust list` to see pinned identities\n",
        ),
        "AUTHS-E3104" => Some(
            "# AUTHS-E3104\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::Serialization`\n\n## Message\n\nserialization error: {0}\n",
        ),
        "AUTHS-E3105" => Some(
            "# AUTHS-E3105\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::AlreadyExists`\n\n## Message\n\nalready exists: {0}\n\n## Suggestion\n\nRun `auths trust list` to see existing entries\n",
        ),
        "AUTHS-E3106" => Some(
            "# AUTHS-E3106\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::Lock`\n\n## Message\n\nlock acquisition failed: {0}\n\n## Suggestion\n\nCheck file permissions and try again\n",
        ),
        "AUTHS-E3107" => Some(
            "# AUTHS-E3107\n\n**Crate:** `auths-core`  \n**Type:** `TrustError::PolicyRejected`\n\n## Message\n\npolicy rejected: {0}\n\n## Suggestion\n\nRun `auths trust add` to pin this identity\n",
        ),

        // --- auths-core (PairingError) ---
        "AUTHS-E3201" => Some(
            "# AUTHS-E3201\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::Protocol`\n\n## Message\n\n_(transparent — see inner error)_\n\n## Suggestion\n\nEnsure both devices are running compatible auths versions\n",
        ),
        "AUTHS-E3202" => Some(
            "# AUTHS-E3202\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::QrCodeFailed`\n\n## Message\n\nQR code generation failed: {0}\n",
        ),
        "AUTHS-E3203" => Some(
            "# AUTHS-E3203\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::RelayError`\n\n## Message\n\nRelay error: {0}\n\n## Suggestion\n\nCheck your internet connection\n",
        ),
        "AUTHS-E3204" => Some(
            "# AUTHS-E3204\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::LocalServerError`\n\n## Message\n\nLocal server error: {0}\n",
        ),
        "AUTHS-E3205" => Some(
            "# AUTHS-E3205\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::MdnsError`\n\n## Message\n\nmDNS error: {0}\n",
        ),
        "AUTHS-E3206" => Some(
            "# AUTHS-E3206\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::NoPeerFound`\n\n## Message\n\nNo peer found on local network\n\n## Suggestion\n\nEnsure both devices are on the same network\n",
        ),
        "AUTHS-E3207" => Some(
            "# AUTHS-E3207\n\n**Crate:** `auths-core`  \n**Type:** `PairingError::LanTimeout`\n\n## Message\n\nLAN pairing timed out\n\n## Suggestion\n\nCheck your network and try again\n",
        ),

        // --- auths-core (CryptoError) ---
        "AUTHS-E3301" => Some(
            "# AUTHS-E3301\n\n**Crate:** `auths-core`  \n**Type:** `CryptoError::SshKeyConstruction`\n\n## Message\n\nSSH key construction failed: {0}\n",
        ),
        "AUTHS-E3302" => Some(
            "# AUTHS-E3302\n\n**Crate:** `auths-core`  \n**Type:** `CryptoError::SigningFailed`\n\n## Message\n\nsigning failed: {0}\n",
        ),
        "AUTHS-E3303" => Some(
            "# AUTHS-E3303\n\n**Crate:** `auths-core`  \n**Type:** `CryptoError::PemEncoding`\n\n## Message\n\nPEM encoding failed: {0}\n",
        ),
        "AUTHS-E3304" => Some(
            "# AUTHS-E3304\n\n**Crate:** `auths-core`  \n**Type:** `CryptoError::InvalidSeedLength`\n\n## Message\n\ninvalid seed length: expected 32, got {0}\n\n## Suggestion\n\nEnsure the seed is exactly 32 bytes\n",
        ),
        "AUTHS-E3305" => Some(
            "# AUTHS-E3305\n\n**Crate:** `auths-core`  \n**Type:** `CryptoError::InvalidKeyFormat`\n\n## Message\n\ninvalid key format: {0}\n\n## Suggestion\n\nCheck that the key file is a valid PKCS#8 v1/v2 key (Ed25519 or P-256) or a raw 32-byte seed\n",
        ),

        // --- auths-core (WitnessError) ---
        "AUTHS-E3401" => Some(
            "# AUTHS-E3401\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::Network`\n\n## Message\n\nnetwork error: {0}\n\n## Suggestion\n\nCheck your internet connection\n",
        ),
        "AUTHS-E3402" => Some(
            "# AUTHS-E3402\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::Duplicity`\n\n## Message\n\nduplicity detected: {0}\n",
        ),
        "AUTHS-E3403" => Some(
            "# AUTHS-E3403\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::Rejected`\n\n## Message\n\nevent rejected: {reason}\n",
        ),
        "AUTHS-E3404" => Some(
            "# AUTHS-E3404\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::Timeout`\n\n## Message\n\ntimeout after {0}ms\n\n## Suggestion\n\nCheck witness endpoint availability and retry\n",
        ),
        "AUTHS-E3405" => Some(
            "# AUTHS-E3405\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::InvalidSignature`\n\n## Message\n\ninvalid receipt signature from witness {witness_id}\n",
        ),
        "AUTHS-E3406" => Some(
            "# AUTHS-E3406\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::InsufficientReceipts`\n\n## Message\n\ninsufficient receipts: got {got}, need {required}\n\n## Suggestion\n\nEnsure enough witnesses are online\n",
        ),
        "AUTHS-E3407" => Some(
            "# AUTHS-E3407\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::SaidMismatch`\n\n## Message\n\nreceipt SAID mismatch: expected {expected}, got {got}\n",
        ),
        "AUTHS-E3408" => Some(
            "# AUTHS-E3408\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::Storage`\n\n## Message\n\nstorage error: {0}\n",
        ),
        "AUTHS-E3409" => Some(
            "# AUTHS-E3409\n\n**Crate:** `auths-core`  \n**Type:** `WitnessError::Serialization`\n\n## Message\n\nserialization error: {0}\n",
        ),

        // --- auths-core (StorageError) ---
        "AUTHS-E3501" => Some(
            "# AUTHS-E3501\n\n**Crate:** `auths-core`  \n**Type:** `StorageError::NotFound`\n\n## Message\n\nnot found: {path}\n",
        ),
        "AUTHS-E3502" => Some(
            "# AUTHS-E3502\n\n**Crate:** `auths-core`  \n**Type:** `StorageError::AlreadyExists`\n\n## Message\n\nalready exists: {path}\n",
        ),
        "AUTHS-E3503" => Some(
            "# AUTHS-E3503\n\n**Crate:** `auths-core`  \n**Type:** `StorageError::CasConflict`\n\n## Message\n\ncompare-and-swap conflict\n",
        ),
        "AUTHS-E3504" => Some(
            "# AUTHS-E3504\n\n**Crate:** `auths-core`  \n**Type:** `StorageError::Io`\n\n## Message\n\nstorage I/O error: {0}\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),
        "AUTHS-E3505" => Some(
            "# AUTHS-E3505\n\n**Crate:** `auths-core`  \n**Type:** `StorageError::Internal`\n\n## Message\n\ninternal storage error: {0}\n",
        ),

        // --- auths-core (NetworkError) ---
        "AUTHS-E3601" => Some(
            "# AUTHS-E3601\n\n**Crate:** `auths-core`  \n**Type:** `NetworkError::Unreachable`\n\n## Message\n\nendpoint unreachable: {endpoint}\n\n## Suggestion\n\nCheck your internet connection\n",
        ),
        "AUTHS-E3602" => Some(
            "# AUTHS-E3602\n\n**Crate:** `auths-core`  \n**Type:** `NetworkError::Timeout`\n\n## Message\n\nrequest timed out: {endpoint}\n\n## Suggestion\n\nThe server may be overloaded — retry later\n",
        ),
        "AUTHS-E3603" => Some(
            "# AUTHS-E3603\n\n**Crate:** `auths-core`  \n**Type:** `NetworkError::NotFound`\n\n## Message\n\nresource not found: {resource}\n",
        ),
        "AUTHS-E3604" => Some(
            "# AUTHS-E3604\n\n**Crate:** `auths-core`  \n**Type:** `NetworkError::Unauthorized`\n\n## Message\n\nunauthorized\n\n## Suggestion\n\nCheck your authentication credentials\n",
        ),
        "AUTHS-E3605" => Some(
            "# AUTHS-E3605\n\n**Crate:** `auths-core`  \n**Type:** `NetworkError::InvalidResponse`\n\n## Message\n\ninvalid response: {detail}\n",
        ),
        "AUTHS-E3606" => Some(
            "# AUTHS-E3606\n\n**Crate:** `auths-core`  \n**Type:** `NetworkError::Internal`\n\n## Message\n\ninternal network error: {0}\n",
        ),

        // --- auths-core (ResolutionError) ---
        "AUTHS-E3701" => Some(
            "# AUTHS-E3701\n\n**Crate:** `auths-core`  \n**Type:** `ResolutionError::DidNotFound`\n\n## Message\n\nDID not found: {did}\n\n## Suggestion\n\nVerify the DID is correct and the identity exists\n",
        ),
        "AUTHS-E3702" => Some(
            "# AUTHS-E3702\n\n**Crate:** `auths-core`  \n**Type:** `ResolutionError::InvalidDid`\n\n## Message\n\ninvalid DID {did}: {reason}\n",
        ),
        "AUTHS-E3703" => Some(
            "# AUTHS-E3703\n\n**Crate:** `auths-core`  \n**Type:** `ResolutionError::KeyRevoked`\n\n## Message\n\nkey revoked for DID: {did}\n",
        ),
        "AUTHS-E3704" => Some(
            "# AUTHS-E3704\n\n**Crate:** `auths-core`  \n**Type:** `ResolutionError::Network`\n\n## Message\n\nnetwork error: {0}\n\n## Suggestion\n\nCheck your internet connection\n",
        ),

        // --- auths-core (PlatformError) ---
        "AUTHS-E3801" => Some(
            "# AUTHS-E3801\n\n**Crate:** `auths-core`  \n**Type:** `PlatformError::AuthorizationPending`\n\n## Message\n\nOAuth authorization pending\n",
        ),
        "AUTHS-E3802" => Some(
            "# AUTHS-E3802\n\n**Crate:** `auths-core`  \n**Type:** `PlatformError::SlowDown`\n\n## Message\n\nOAuth slow down\n",
        ),
        "AUTHS-E3803" => Some(
            "# AUTHS-E3803\n\n**Crate:** `auths-core`  \n**Type:** `PlatformError::AccessDenied`\n\n## Message\n\nOAuth access denied\n\n## Suggestion\n\nRe-run the command and approve the authorization request\n",
        ),
        "AUTHS-E3804" => Some(
            "# AUTHS-E3804\n\n**Crate:** `auths-core`  \n**Type:** `PlatformError::ExpiredToken`\n\n## Message\n\ndevice code expired\n\n## Suggestion\n\nThe device code expired — restart the flow\n",
        ),
        "AUTHS-E3805" => Some(
            "# AUTHS-E3805\n\n**Crate:** `auths-core`  \n**Type:** `PlatformError::Network`\n\n## Message\n\nnetwork error: {0}\n\n## Suggestion\n\nCheck your internet connection\n",
        ),
        "AUTHS-E3806" => Some(
            "# AUTHS-E3806\n\n**Crate:** `auths-core`  \n**Type:** `PlatformError::Platform`\n\n## Message\n\nplatform error: {message}\n",
        ),

        // --- auths-core (SshAgentError) ---
        "AUTHS-E3901" => Some(
            "# AUTHS-E3901\n\n**Crate:** `auths-core`  \n**Type:** `SshAgentError::CommandFailed`\n\n## Message\n\nssh-add command failed: {0}\n",
        ),
        "AUTHS-E3902" => Some(
            "# AUTHS-E3902\n\n**Crate:** `auths-core`  \n**Type:** `SshAgentError::NotAvailable`\n\n## Message\n\nSSH agent not available: {0}\n\n## Suggestion\n\nStart the SSH agent: eval $(ssh-agent -s)\n",
        ),
        "AUTHS-E3903" => Some(
            "# AUTHS-E3903\n\n**Crate:** `auths-core`  \n**Type:** `SshAgentError::IoError`\n\n## Message\n\nI/O error: {0}\n\n## Suggestion\n\nCheck file permissions\n",
        ),

        // --- auths-core (ConfigStoreError) ---
        "AUTHS-E3951" => Some(
            "# AUTHS-E3951\n\n**Crate:** `auths-core`  \n**Type:** `ConfigStoreError::Read`\n\n## Message\n\nfailed to read config from {path}\n\n## Suggestion\n\nCheck that ~/.auths/config.toml exists and is readable\n",
        ),
        "AUTHS-E3952" => Some(
            "# AUTHS-E3952\n\n**Crate:** `auths-core`  \n**Type:** `ConfigStoreError::Write`\n\n## Message\n\nfailed to write config to {path}\n\n## Suggestion\n\nCheck file permissions for ~/.auths/config.toml\n",
        ),

        // --- auths-core (NamespaceVerifyError) ---
        "AUTHS-E3961" => Some(
            "# AUTHS-E3961\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::UnsupportedEcosystem`\n\n## Message\n\nunsupported ecosystem: {ecosystem}\n",
        ),
        "AUTHS-E3962" => Some(
            "# AUTHS-E3962\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::PackageNotFound`\n\n## Message\n\npackage '{package_name}' not found in {ecosystem}\n",
        ),
        "AUTHS-E3963" => Some(
            "# AUTHS-E3963\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::OwnershipNotConfirmed`\n\n## Message\n\nownership of '{package_name}' on {ecosystem} not confirmed for the given identity\n",
        ),
        "AUTHS-E3964" => Some(
            "# AUTHS-E3964\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::ChallengeExpired`\n\n## Message\n\nverification challenge expired\n\n## Suggestion\n\nStart a new verification challenge\n",
        ),
        "AUTHS-E3965" => Some(
            "# AUTHS-E3965\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::InvalidToken`\n\n## Message\n\ninvalid verification token: {reason}\n",
        ),
        "AUTHS-E3966" => Some(
            "# AUTHS-E3966\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::InvalidPackageName`\n\n## Message\n\ninvalid package name '{name}': {reason}\n",
        ),
        "AUTHS-E3967" => Some(
            "# AUTHS-E3967\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::NetworkError`\n\n## Message\n\nverification network error: {message}\n\n## Suggestion\n\nCheck your internet connection and try again\n",
        ),
        "AUTHS-E3968" => Some(
            "# AUTHS-E3968\n\n**Crate:** `auths-core`  \n**Type:** `NamespaceVerifyError::RateLimited`\n\n## Message\n\nrate limited by {ecosystem} registry\n\n## Suggestion\n\nWait a moment and retry the verification\n",
        ),

        // --- auths-id (FreezeError) ---
        "AUTHS-E4001" => Some(
            "# AUTHS-E4001\n\n**Crate:** `auths-id`  \n**Type:** `FreezeError::Io`\n\n## Message\n\n_(transparent — see inner error)_\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),
        "AUTHS-E4002" => Some(
            "# AUTHS-E4002\n\n**Crate:** `auths-id`  \n**Type:** `FreezeError::Deserialization`\n\n## Message\n\nfailed to parse freeze state: {0}\n",
        ),
        "AUTHS-E4003" => Some(
            "# AUTHS-E4003\n\n**Crate:** `auths-id`  \n**Type:** `FreezeError::InvalidDuration`\n\n## Message\n\ninvalid duration format: {0}\n",
        ),
        "AUTHS-E4004" => Some(
            "# AUTHS-E4004\n\n**Crate:** `auths-id`  \n**Type:** `FreezeError::ZeroDuration`\n\n## Message\n\nduration must be greater than zero\n\n## Suggestion\n\nSpecify a positive duration\n",
        ),

        // --- auths-id (StorageError) ---
        "AUTHS-E4101" => Some(
            "# AUTHS-E4101\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::Git`\n\n## Message\n\n_(transparent — see inner error)_\n\n## Suggestion\n\nCheck that the Git repository is not corrupted\n",
        ),
        "AUTHS-E4102" => Some(
            "# AUTHS-E4102\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::Serialization`\n\n## Message\n\nserialization error: {0}\n",
        ),
        "AUTHS-E4103" => Some(
            "# AUTHS-E4103\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::Io`\n\n## Message\n\nI/O error: {0}\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),
        "AUTHS-E4104" => Some(
            "# AUTHS-E4104\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::NotFound`\n\n## Message\n\nnot found: {0}\n\n## Suggestion\n\nVerify the identity or resource exists\n",
        ),
        "AUTHS-E4105" => Some(
            "# AUTHS-E4105\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::InvalidData`\n\n## Message\n\n{0}\n\n## Suggestion\n\nThe stored data may be corrupted; try re-initializing\n",
        ),
        "AUTHS-E4106" => Some(
            "# AUTHS-E4106\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::SchemaValidation`\n\n## Message\n\nschema validation failed: {0}\n\n## Suggestion\n\nEnsure data matches the expected schema version\n",
        ),
        "AUTHS-E4107" => Some(
            "# AUTHS-E4107\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::Index`\n\n## Message\n\nindex error: {0}\n\n## Suggestion\n\nTry rebuilding the index\n",
        ),

        // --- auths-id (InitError) ---
        "AUTHS-E4201" => Some(
            "# AUTHS-E4201\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Git`\n\n## Message\n\n_(transparent — see inner error)_\n\n## Suggestion\n\nCheck that the Git repository is accessible\n",
        ),
        "AUTHS-E4202" => Some(
            "# AUTHS-E4202\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Keri`\n\n## Message\n\nKERI operation failed: {0}\n\n## Suggestion\n\nKERI event processing failed; check identity state\n",
        ),
        "AUTHS-E4203" => Some(
            "# AUTHS-E4203\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Key`\n\n## Message\n\nkey operation failed: {0}\n\n## Suggestion\n\nCheck keychain access and passphrase\n",
        ),
        "AUTHS-E4204" => Some(
            "# AUTHS-E4204\n\n**Crate:** `auths-id`  \n**Type:** `InitError::InvalidData`\n\n## Message\n\n{0}\n",
        ),
        "AUTHS-E4205" => Some(
            "# AUTHS-E4205\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Storage`\n\n## Message\n\nstorage operation failed: {0}\n\n## Suggestion\n\nCheck storage backend connectivity\n",
        ),
        "AUTHS-E4206" => Some(
            "# AUTHS-E4206\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Registry`\n\n## Message\n\nregistry error: {0}\n\n## Suggestion\n\nCheck registry backend configuration\n",
        ),
        "AUTHS-E4207" => Some(
            "# AUTHS-E4207\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Crypto`\n\n## Message\n\ncrypto operation failed: {0}\n",
        ),
        "AUTHS-E4208" => Some(
            "# AUTHS-E4208\n\n**Crate:** `auths-id`  \n**Type:** `InitError::Identity`\n\n## Message\n\nidentity error: {0}\n",
        ),

        // --- auths-id (AgentProvisioningError) ---
        "AUTHS-E4301" => Some(
            "# AUTHS-E4301\n\n**Crate:** `auths-id`  \n**Type:** `AgentProvisioningError::RepoCreation`\n\n## Message\n\nrepository creation failed: {0}\n\n## Suggestion\n\nCheck that the agent repo path is writable\n",
        ),
        "AUTHS-E4302" => Some(
            "# AUTHS-E4302\n\n**Crate:** `auths-id`  \n**Type:** `AgentProvisioningError::IdentityCreation`\n\n## Message\n\nidentity creation failed: {0}\n",
        ),
        "AUTHS-E4303" => Some(
            "# AUTHS-E4303\n\n**Crate:** `auths-id`  \n**Type:** `AgentProvisioningError::AttestationCreation`\n\n## Message\n\nattestation creation failed: {0}\n\n## Suggestion\n\nAttestation signing failed; verify key access\n",
        ),
        "AUTHS-E4304" => Some(
            "# AUTHS-E4304\n\n**Crate:** `auths-id`  \n**Type:** `AgentProvisioningError::KeychainAccess`\n\n## Message\n\nkeychain access failed: {0}\n\n## Suggestion\n\nCheck keychain permissions and passphrase\n",
        ),
        "AUTHS-E4305" => Some(
            "# AUTHS-E4305\n\n**Crate:** `auths-id`  \n**Type:** `AgentProvisioningError::ConfigWrite`\n\n## Message\n\nconfig write failed: {0}\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),

        // --- auths-id (IdentityError) ---
        "AUTHS-E4401" => Some(
            "# AUTHS-E4401\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::Keri`\n\n## Message\n\nKERI error: {0}\n\n## Suggestion\n\nKERI operation failed; check identity state\n",
        ),
        "AUTHS-E4402" => Some(
            "# AUTHS-E4402\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::Pkcs8EncodeError`\n\n## Message\n\nPKCS#8 encoding error: {0}\n",
        ),
        "AUTHS-E4403" => Some(
            "# AUTHS-E4403\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::Pkcs8DecodeError`\n\n## Message\n\nPKCS#8 decoding error: {0}\n\n## Suggestion\n\nThe key may be in an unsupported format\n",
        ),
        "AUTHS-E4404" => Some(
            "# AUTHS-E4404\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::EmptyPassphrase`\n\n## Message\n\nPassphrase required\n\n## Suggestion\n\nProvide a non-empty passphrase\n",
        ),
        "AUTHS-E4405" => Some(
            "# AUTHS-E4405\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::InvalidKeyLength`\n\n## Message\n\nInvalid key length: expected 32 bytes (Ed25519) or 33 bytes (P-256 compressed SEC1), got {0}\n\n## Suggestion\n\nKey length must match the declared curve. See `docs/architecture/cryptography.md`.\n",
        ),
        "AUTHS-E4406" => Some(
            "# AUTHS-E4406\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::KeyStorage`\n\n## Message\n\nKey storage error: {0}\n\n## Suggestion\n\nCheck keychain permissions\n",
        ),
        "AUTHS-E4407" => Some(
            "# AUTHS-E4407\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::KeyRetrieval`\n\n## Message\n\nKey retrieval error: {0}\n\n## Suggestion\n\nCheck that the key alias exists in the keychain\n",
        ),
        "AUTHS-E4408" => Some(
            "# AUTHS-E4408\n\n**Crate:** `auths-id`  \n**Type:** `IdentityError::RingError`\n\n## Message\n\nRing crypto error: {0}\n",
        ),

        // --- auths-id (StorageError) ---
        "AUTHS-E4409" => Some(
            "# AUTHS-E4409\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::NotFound`\n\n## Message\n\n_(transparent — see inner error)_\n\n## Suggestion\n\nVerify the storage path exists and is initialized\n",
        ),
        "AUTHS-E4410" => Some(
            "# AUTHS-E4410\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::CasConflict`\n\n## Message\n\n_(transparent — see inner error)_\n",
        ),
        "AUTHS-E4411" => Some(
            "# AUTHS-E4411\n\n**Crate:** `auths-id`  \n**Type:** `StorageError::Io`\n\n## Message\n\n_(transparent — see inner error)_\n",
        ),

        // --- auths-id (ValidationError) ---
        "AUTHS-E4501" => Some(
            "# AUTHS-E4501\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::InvalidSaid`\n\n## Message\n\nInvalid SAID: expected {expected}, got {actual}\n",
        ),
        "AUTHS-E4502" => Some(
            "# AUTHS-E4502\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::BrokenChain`\n\n## Message\n\nBroken chain: event {sequence} references {referenced}, but previous was {actual}\n",
        ),
        "AUTHS-E4503" => Some(
            "# AUTHS-E4503\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::InvalidSequence`\n\n## Message\n\nInvalid sequence: expected {expected}, got {actual}\n",
        ),
        "AUTHS-E4504" => Some(
            "# AUTHS-E4504\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::CommitmentMismatch`\n\n## Message\n\nPre-rotation commitment mismatch at sequence {sequence}\n",
        ),
        "AUTHS-E4505" => Some(
            "# AUTHS-E4505\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::SignatureFailed`\n\n## Message\n\nSignature verification failed at sequence {sequence}\n",
        ),
        "AUTHS-E4506" => Some(
            "# AUTHS-E4506\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::NotInception`\n\n## Message\n\nFirst event must be inception\n\n## Suggestion\n\nThe first event in a KEL must be an inception event\n",
        ),
        "AUTHS-E4507" => Some(
            "# AUTHS-E4507\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::EmptyKel`\n\n## Message\n\nEmpty KEL\n\n## Suggestion\n\nNo events found; initialize the identity first\n",
        ),
        "AUTHS-E4508" => Some(
            "# AUTHS-E4508\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::MultipleInceptions`\n\n## Message\n\nMultiple inception events in KEL\n\n## Suggestion\n\nA KEL must contain exactly one inception event\n",
        ),
        "AUTHS-E4509" => Some(
            "# AUTHS-E4509\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::Serialization`\n\n## Message\n\nSerialization error: {0}\n",
        ),
        "AUTHS-E4510" => Some(
            "# AUTHS-E4510\n\n**Crate:** `auths-id`  \n**Type:** `ValidationError::MalformedSequence`\n\n## Message\n\nMalformed sequence number: {raw:?}\n",
        ),

        // --- auths-id (KelError) ---
        "AUTHS-E4601" => Some(
            "# AUTHS-E4601\n\n**Crate:** `auths-id`  \n**Type:** `KelError::Git`\n\n## Message\n\nGit error: {0}\n\n## Suggestion\n\nCheck that the Git repository is accessible and not corrupted\n",
        ),
        "AUTHS-E4602" => Some(
            "# AUTHS-E4602\n\n**Crate:** `auths-id`  \n**Type:** `KelError::Serialization`\n\n## Message\n\nSerialization error: {0}\n",
        ),
        "AUTHS-E4603" => Some(
            "# AUTHS-E4603\n\n**Crate:** `auths-id`  \n**Type:** `KelError::NotFound`\n\n## Message\n\nKEL not found for prefix: {0}\n\n## Suggestion\n\nInitialize the identity first with 'auths init'\n",
        ),
        "AUTHS-E4604" => Some(
            "# AUTHS-E4604\n\n**Crate:** `auths-id`  \n**Type:** `KelError::InvalidOperation`\n\n## Message\n\nInvalid operation: {0}\n",
        ),
        "AUTHS-E4605" => Some(
            "# AUTHS-E4605\n\n**Crate:** `auths-id`  \n**Type:** `KelError::InvalidData`\n\n## Message\n\nInvalid data: {0}\n\n## Suggestion\n\nThe KEL data may be corrupted; try re-syncing\n",
        ),
        "AUTHS-E4606" => Some(
            "# AUTHS-E4606\n\n**Crate:** `auths-id`  \n**Type:** `KelError::ChainIntegrity`\n\n## Message\n\nChain integrity error: {0}\n",
        ),
        "AUTHS-E4607" => Some(
            "# AUTHS-E4607\n\n**Crate:** `auths-id`  \n**Type:** `KelError::ValidationFailed`\n\n## Message\n\nValidation failed: {0}\n",
        ),

        // --- auths-id (RotationError) ---
        "AUTHS-E4701" => Some(
            "# AUTHS-E4701\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::KeyGeneration`\n\n## Message\n\nKey generation failed: {0}\n",
        ),
        "AUTHS-E4702" => Some(
            "# AUTHS-E4702\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::Kel`\n\n## Message\n\nKEL error: {0}\n\n## Suggestion\n\nCheck the KEL state for the identity\n",
        ),
        "AUTHS-E4703" => Some(
            "# AUTHS-E4703\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::Storage`\n\n## Message\n\nStorage error: {0}\n\n## Suggestion\n\nCheck storage backend connectivity\n",
        ),
        "AUTHS-E4704" => Some(
            "# AUTHS-E4704\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::Validation`\n\n## Message\n\nValidation error: {0}\n",
        ),
        "AUTHS-E4705" => Some(
            "# AUTHS-E4705\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::IdentityAbandoned`\n\n## Message\n\nIdentity is abandoned (cannot rotate)\n",
        ),
        "AUTHS-E4706" => Some(
            "# AUTHS-E4706\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::CommitmentMismatch`\n\n## Message\n\nCommitment mismatch: next key does not match previous commitment\n",
        ),
        "AUTHS-E4707" => Some(
            "# AUTHS-E4707\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::Serialization`\n\n## Message\n\nSerialization error: {0}\n",
        ),
        "AUTHS-E4708" => Some(
            "# AUTHS-E4708\n\n**Crate:** `auths-id`  \n**Type:** `RotationError::InvalidKey`\n\n## Message\n\nInvalid key: {0}\n\n## Suggestion\n\nProvide a valid Ed25519 or P-256 key in PKCS#8 v1/v2 format\n",
        ),

        // --- auths-id (ResolveError) ---
        "AUTHS-E4801" => Some(
            "# AUTHS-E4801\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::InvalidFormat`\n\n## Message\n\nInvalid DID format: {0}\n\n## Suggestion\n\nUse the format 'did:keri:E<prefix>'\n",
        ),
        "AUTHS-E4802" => Some(
            "# AUTHS-E4802\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::NotFound`\n\n## Message\n\nKEL not found for prefix: {0}\n\n## Suggestion\n\nThe identity does not exist; check the DID prefix\n",
        ),
        "AUTHS-E4803" => Some(
            "# AUTHS-E4803\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::Kel`\n\n## Message\n\nKEL error: {0}\n",
        ),
        "AUTHS-E4804" => Some(
            "# AUTHS-E4804\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::Validation`\n\n## Message\n\nValidation error: {0}\n",
        ),
        "AUTHS-E4805" => Some(
            "# AUTHS-E4805\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::InvalidKeyEncoding`\n\n## Message\n\nInvalid key encoding: {0}\n",
        ),
        "AUTHS-E4806" => Some(
            "# AUTHS-E4806\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::NoCurrentKey`\n\n## Message\n\nNo current key in identity\n\n## Suggestion\n\nThe identity has no active key; it may be abandoned\n",
        ),
        "AUTHS-E4807" => Some(
            "# AUTHS-E4807\n\n**Crate:** `auths-id`  \n**Type:** `ResolveError::UnknownKeyType`\n\n## Message\n\nUnknown key type: {0}\n\n## Suggestion\n\nKERI supports Ed25519 (`D` prefix) and P-256 (`1AAI` prefix). Other curves are not yet supported.\n",
        ),

        // --- auths-id (TenantIdError) ---
        "AUTHS-E4851" => Some(
            "# AUTHS-E4851\n\n**Crate:** `auths-id`  \n**Type:** `TenantIdError::InvalidLength`\n\n## Message\n\nmust be 1–64 characters (got {0})\n\n## Suggestion\n\nTenant ID must be between 1 and 64 characters\n",
        ),
        "AUTHS-E4852" => Some(
            "# AUTHS-E4852\n\n**Crate:** `auths-id`  \n**Type:** `TenantIdError::InvalidCharacter`\n\n## Message\n\ncontains disallowed character {0:?} (only [a-z0-9_-] allowed)\n",
        ),
        "AUTHS-E4853" => Some(
            "# AUTHS-E4853\n\n**Crate:** `auths-id`  \n**Type:** `TenantIdError::Reserved`\n\n## Message\n\n'{0}' is reserved\n\n## Suggestion\n\nChoose a different tenant ID; this name is reserved\n",
        ),

        // --- auths-id (RegistryError) ---
        "AUTHS-E4861" => Some(
            "# AUTHS-E4861\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::Storage`\n\n## Message\n\nStorage error: {0}\n\n## Suggestion\n\nCheck storage backend connectivity\n",
        ),
        "AUTHS-E4862" => Some(
            "# AUTHS-E4862\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::InvalidPrefix`\n\n## Message\n\nInvalid prefix '{prefix}': {reason}\n\n## Suggestion\n\nKERI prefixes must start with 'E' (Blake3 SAID)\n",
        ),
        "AUTHS-E4863" => Some(
            "# AUTHS-E4863\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::InvalidDeviceDid`\n\n## Message\n\nInvalid device DID '{did}': {reason}\n\n## Suggestion\n\nDevice DIDs must be in 'did:key:z...' format\n",
        ),
        "AUTHS-E4864" => Some(
            "# AUTHS-E4864\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::EventExists`\n\n## Message\n\nEvent already exists: {prefix} seq {seq}\n\n## Suggestion\n\nThis event has already been appended to the KEL\n",
        ),
        "AUTHS-E4865" => Some(
            "# AUTHS-E4865\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::SequenceGap`\n\n## Message\n\nSequence gap for {prefix}: expected {expected}, got {got}\n\n## Suggestion\n\nEvents must be appended in strict sequence order\n",
        ),
        "AUTHS-E4866" => Some(
            "# AUTHS-E4866\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::NotFound`\n\n## Message\n\nNot found: {entity_type} '{id}'\n",
        ),
        "AUTHS-E4867" => Some(
            "# AUTHS-E4867\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::Serialization`\n\n## Message\n\nSerialization error: {0}\n",
        ),
        "AUTHS-E4868" => Some(
            "# AUTHS-E4868\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::ConcurrentModification`\n\n## Message\n\nConcurrent modification: {0}\n",
        ),
        "AUTHS-E4869" => Some(
            "# AUTHS-E4869\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::SaidMismatch`\n\n## Message\n\nSAID mismatch: expected {expected}, got {actual}\n\n## Suggestion\n\nThe event content does not match its declared SAID\n",
        ),
        "AUTHS-E4870" => Some(
            "# AUTHS-E4870\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::InvalidEvent`\n\n## Message\n\nInvalid event: {reason}\n",
        ),
        "AUTHS-E4871" => Some(
            "# AUTHS-E4871\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::Io`\n\n## Message\n\nI/O error: {0}\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),
        "AUTHS-E4872" => Some(
            "# AUTHS-E4872\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::Internal`\n\n## Message\n\nInternal error: {0}\n",
        ),
        "AUTHS-E4873" => Some(
            "# AUTHS-E4873\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::InvalidTenantId`\n\n## Message\n\ninvalid tenant ID '{tenant_id}': {kind}\n",
        ),
        "AUTHS-E4874" => Some(
            "# AUTHS-E4874\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::Attestation`\n\n## Message\n\nAttestation error: {0}\n",
        ),
        "AUTHS-E4875" => Some(
            "# AUTHS-E4875\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::StaleAttestation`\n\n## Message\n\nStale attestation: {0}\n",
        ),
        "AUTHS-E4876" => Some(
            "# AUTHS-E4876\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::NotImplemented`\n\n## Message\n\nNot implemented: {method}\n",
        ),
        "AUTHS-E4877" => Some(
            "# AUTHS-E4877\n\n**Crate:** `auths-id`  \n**Type:** `RegistryError::BatchValidationFailed`\n\n## Message\n\nBatch validation failed at index {index}: {source}\n",
        ),

        // --- auths-id (InceptionError) ---
        "AUTHS-E4901" => Some(
            "# AUTHS-E4901\n\n**Crate:** `auths-id`  \n**Type:** `InceptionError::KeyGeneration`\n\n## Message\n\nKey generation failed: {0}\n",
        ),
        "AUTHS-E4902" => Some(
            "# AUTHS-E4902\n\n**Crate:** `auths-id`  \n**Type:** `InceptionError::Kel`\n\n## Message\n\nKEL error: {0}\n\n## Suggestion\n\nCheck the KEL state; a KEL may already exist for this prefix\n",
        ),
        "AUTHS-E4903" => Some(
            "# AUTHS-E4903\n\n**Crate:** `auths-id`  \n**Type:** `InceptionError::Storage`\n\n## Message\n\nStorage error: {0}\n\n## Suggestion\n\nCheck storage backend connectivity\n",
        ),
        "AUTHS-E4904" => Some(
            "# AUTHS-E4904\n\n**Crate:** `auths-id`  \n**Type:** `InceptionError::Validation`\n\n## Message\n\nValidation error: {0}\n",
        ),
        "AUTHS-E4905" => Some(
            "# AUTHS-E4905\n\n**Crate:** `auths-id`  \n**Type:** `InceptionError::Serialization`\n\n## Message\n\nSerialization error: {0}\n",
        ),

        // --- auths-id (IncrementalError) ---
        "AUTHS-E4951" => Some(
            "# AUTHS-E4951\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::Kel`\n\n## Message\n\nKEL error: {0}\n",
        ),
        "AUTHS-E4952" => Some(
            "# AUTHS-E4952\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::ChainContinuity`\n\n## Message\n\nChain continuity error: expected previous SAID {expected}, got {actual}\n",
        ),
        "AUTHS-E4953" => Some(
            "# AUTHS-E4953\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::SequenceError`\n\n## Message\n\nSequence error: expected {expected}, got {actual}\n",
        ),
        "AUTHS-E4954" => Some(
            "# AUTHS-E4954\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::MalformedSequence`\n\n## Message\n\nMalformed sequence number: {raw:?}\n",
        ),
        "AUTHS-E4955" => Some(
            "# AUTHS-E4955\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::InvalidEventType`\n\n## Message\n\nInvalid event type in KEL: {0}\n",
        ),
        "AUTHS-E4956" => Some(
            "# AUTHS-E4956\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::NonLinearHistory`\n\n## Message\n\nKEL history is non-linear: commit {commit} has {parent_count} parents (expected 1)\n",
        ),
        "AUTHS-E4957" => Some(
            "# AUTHS-E4957\n\n**Crate:** `auths-id`  \n**Type:** `IncrementalError::MissingParent`\n\n## Message\n\nKEL history is corrupted: commit {commit} has no parent but is not inception\n\n## Suggestion\n\nThe KEL commit history is corrupted\n",
        ),

        // --- auths-id (AnchorError) ---
        "AUTHS-E4961" => Some(
            "# AUTHS-E4961\n\n**Crate:** `auths-id`  \n**Type:** `AnchorError::Kel`\n\n## Message\n\nKEL error: {0}\n",
        ),
        "AUTHS-E4962" => Some(
            "# AUTHS-E4962\n\n**Crate:** `auths-id`  \n**Type:** `AnchorError::Validation`\n\n## Message\n\nValidation error: {0}\n",
        ),
        "AUTHS-E4963" => Some(
            "# AUTHS-E4963\n\n**Crate:** `auths-id`  \n**Type:** `AnchorError::Serialization`\n\n## Message\n\nSerialization error: {0}\n",
        ),
        "AUTHS-E4964" => Some(
            "# AUTHS-E4964\n\n**Crate:** `auths-id`  \n**Type:** `AnchorError::InvalidDid`\n\n## Message\n\nInvalid DID format: {0}\n\n## Suggestion\n\nUse the format 'did:keri:E<prefix>'\n",
        ),
        "AUTHS-E4965" => Some(
            "# AUTHS-E4965\n\n**Crate:** `auths-id`  \n**Type:** `AnchorError::NotFound`\n\n## Message\n\nKEL not found for prefix: {0}\n\n## Suggestion\n\nInitialize the identity first with 'auths init'\n",
        ),

        // --- auths-id (WitnessIntegrationError) ---
        "AUTHS-E4971" => Some(
            "# AUTHS-E4971\n\n**Crate:** `auths-id`  \n**Type:** `WitnessIntegrationError::Collection`\n\n## Message\n\nReceipt collection failed: {0}\n",
        ),
        "AUTHS-E4972" => Some(
            "# AUTHS-E4972\n\n**Crate:** `auths-id`  \n**Type:** `WitnessIntegrationError::Storage`\n\n## Message\n\nReceipt storage failed: {0}\n\n## Suggestion\n\nCheck storage backend permissions\n",
        ),
        "AUTHS-E4973" => Some(
            "# AUTHS-E4973\n\n**Crate:** `auths-id`  \n**Type:** `WitnessIntegrationError::Runtime`\n\n## Message\n\nTokio runtime error: {0}\n",
        ),

        // --- auths-id (CacheError) ---
        "AUTHS-E4981" => Some(
            "# AUTHS-E4981\n\n**Crate:** `auths-id`  \n**Type:** `CacheError::Io`\n\n## Message\n\nI/O error: {0}\n",
        ),
        "AUTHS-E4982" => Some(
            "# AUTHS-E4982\n\n**Crate:** `auths-id`  \n**Type:** `CacheError::Json`\n\n## Message\n\nJSON serialization error: {0}\n",
        ),

        // --- auths-id (HookError) ---
        "AUTHS-E4991" => Some(
            "# AUTHS-E4991\n\n**Crate:** `auths-id`  \n**Type:** `HookError::Io`\n\n## Message\n\nIO error: {0}\n\n## Suggestion\n\nCheck file permissions on the Git hooks directory\n",
        ),
        "AUTHS-E4992" => Some(
            "# AUTHS-E4992\n\n**Crate:** `auths-id`  \n**Type:** `HookError::NotGitRepo`\n\n## Message\n\nNot a Git repository: {0}\n\n## Suggestion\n\nEnsure the path points to a valid Git repository\n",
        ),

        // --- auths-sdk (SetupError) ---
        "AUTHS-E5001" => Some(
            "# AUTHS-E5001\n\n**Crate:** `auths-sdk`  \n**Type:** `SetupError::IdentityAlreadyExists`\n\n## Message\n\nidentity already exists: {did}\n",
        ),
        "AUTHS-E5002" => Some(
            "# AUTHS-E5002\n\n**Crate:** `auths-sdk`  \n**Type:** `SetupError::KeychainUnavailable`\n\n## Message\n\nkeychain unavailable ({backend}): {reason}\n",
        ),
        "AUTHS-E5004" => Some(
            "# AUTHS-E5004\n\n**Crate:** `auths-sdk`  \n**Type:** `SetupError::GitConfigError`\n\n## Message\n\ngit config error: {0}\n",
        ),
        "AUTHS-E5006" => Some(
            "# AUTHS-E5006\n\n**Crate:** `auths-sdk`  \n**Type:** `SetupError::PlatformVerificationFailed`\n\n## Message\n\nplatform verification failed: {0}\n",
        ),
        "AUTHS-E5007" => Some(
            "# AUTHS-E5007\n\n**Crate:** `auths-sdk`  \n**Type:** `SetupError::InvalidSetupConfig`\n\n## Message\n\ninvalid setup config: {0}\n\n## Suggestion\n\nCheck identity setup configuration parameters\n",
        ),

        // --- auths-sdk (DeviceError) ---
        "AUTHS-E5101" => Some(
            "# AUTHS-E5101\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceError::IdentityNotFound`\n\n## Message\n\nidentity not found: {did}\n\n## Suggestion\n\nRun `auths init` to create an identity first\n",
        ),
        "AUTHS-E5102" => Some(
            "# AUTHS-E5102\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceError::DeviceNotFound`\n\n## Message\n\ndevice not found: {did}\n\n## Suggestion\n\nRun `auths device list` to see linked devices\n",
        ),
        "AUTHS-E5103" => Some(
            "# AUTHS-E5103\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceError::AttestationError`\n\n## Message\n\nattestation error: {0}\n",
        ),
        "AUTHS-E5105" => Some(
            "# AUTHS-E5105\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceError::DeviceDidMismatch`\n\n## Message\n\ndevice DID mismatch: expected {expected}, got {actual}\n\n## Suggestion\n\nCheck that --device matches the key name\n",
        ),

        // --- auths-sdk (DeviceExtensionError) ---
        "AUTHS-E5201" => Some(
            "# AUTHS-E5201\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceExtensionError::IdentityNotFound`\n\n## Message\n\nidentity not found\n\n## Suggestion\n\nRun `auths init` to create an identity first\n",
        ),
        "AUTHS-E5202" => Some(
            "# AUTHS-E5202\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceExtensionError::NoAttestationFound`\n\n## Message\n\nno attestation found for device {device_did}\n",
        ),
        "AUTHS-E5203" => Some(
            "# AUTHS-E5203\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceExtensionError::AlreadyRevoked`\n\n## Message\n\ndevice {device_did} is already revoked\n",
        ),
        "AUTHS-E5204" => Some(
            "# AUTHS-E5204\n\n**Crate:** `auths-sdk`  \n**Type:** `DeviceExtensionError::AttestationFailed`\n\n## Message\n\nattestation creation failed: {0}\n",
        ),

        // --- auths-sdk (RotationError) ---
        "AUTHS-E5301" => Some(
            "# AUTHS-E5301\n\n**Crate:** `auths-sdk`  \n**Type:** `RotationError::IdentityNotFound`\n\n## Message\n\nidentity not found at {path}\n\n## Suggestion\n\nRun `auths init` to create an identity first\n",
        ),
        "AUTHS-E5302" => Some(
            "# AUTHS-E5302\n\n**Crate:** `auths-sdk`  \n**Type:** `RotationError::KeyNotFound`\n\n## Message\n\nkey not found: {0}\n\n## Suggestion\n\nRun `auths key list` to see available keys\n",
        ),
        "AUTHS-E5303" => Some(
            "# AUTHS-E5303\n\n**Crate:** `auths-sdk`  \n**Type:** `RotationError::KeyDecryptionFailed`\n\n## Message\n\nkey decryption failed: {0}\n\n## Suggestion\n\nCheck your passphrase and try again\n",
        ),
        "AUTHS-E5304" => Some(
            "# AUTHS-E5304\n\n**Crate:** `auths-sdk`  \n**Type:** `RotationError::KelHistoryFailed`\n\n## Message\n\nKEL history error: {0}\n\n## Suggestion\n\nRun `auths doctor` to check KEL integrity\n",
        ),
        "AUTHS-E5305" => Some(
            "# AUTHS-E5305\n\n**Crate:** `auths-sdk`  \n**Type:** `RotationError::RotationFailed`\n\n## Message\n\nrotation failed: {0}\n",
        ),
        "AUTHS-E5306" => Some(
            "# AUTHS-E5306\n\n**Crate:** `auths-sdk`  \n**Type:** `RotationError::PartialRotation`\n\n## Message\n\nrotation event committed to KEL but keychain write failed — manual recovery required: {0}\n",
        ),

        // --- auths-sdk (RegistrationError) ---
        "AUTHS-E5401" => Some(
            "# AUTHS-E5401\n\n**Crate:** `auths-sdk`  \n**Type:** `RegistrationError::AlreadyRegistered`\n\n## Message\n\nidentity already registered at this registry\n",
        ),
        "AUTHS-E5402" => Some(
            "# AUTHS-E5402\n\n**Crate:** `auths-sdk`  \n**Type:** `RegistrationError::QuotaExceeded`\n\n## Message\n\nregistration quota exceeded — try again later\n\n## Suggestion\n\nWait a few minutes and try again\n",
        ),
        "AUTHS-E5403" => Some(
            "# AUTHS-E5403\n\n**Crate:** `auths-sdk`  \n**Type:** `RegistrationError::InvalidDidFormat`\n\n## Message\n\ninvalid DID format: {did}\n",
        ),
        "AUTHS-E5404" => Some(
            "# AUTHS-E5404\n\n**Crate:** `auths-sdk`  \n**Type:** `RegistrationError::IdentityLoadError`\n\n## Message\n\nidentity load error: {0}\n\n## Suggestion\n\nRun `auths doctor` to check local identity data\n",
        ),
        "AUTHS-E5405" => Some(
            "# AUTHS-E5405\n\n**Crate:** `auths-sdk`  \n**Type:** `RegistrationError::RegistryReadError`\n\n## Message\n\nregistry read error: {0}\n\n## Suggestion\n\nRun `auths doctor` to check local identity data\n",
        ),
        "AUTHS-E5406" => Some(
            "# AUTHS-E5406\n\n**Crate:** `auths-sdk`  \n**Type:** `RegistrationError::SerializationError`\n\n## Message\n\nserialization error: {0}\n\n## Suggestion\n\nRun `auths doctor` to check local identity data\n",
        ),

        // --- auths-sdk (McpAuthError) ---
        "AUTHS-E5501" => Some(
            "# AUTHS-E5501\n\n**Crate:** `auths-sdk`  \n**Type:** `McpAuthError::BridgeUnreachable`\n\n## Message\n\nbridge unreachable: {0}\n\n## Suggestion\n\nCheck network connectivity to the OIDC bridge\n",
        ),
        "AUTHS-E5502" => Some(
            "# AUTHS-E5502\n\n**Crate:** `auths-sdk`  \n**Type:** `McpAuthError::TokenExchangeFailed`\n\n## Message\n\ntoken exchange failed (HTTP {status}): {body}\n\n## Suggestion\n\nVerify your credentials and try again\n",
        ),
        "AUTHS-E5503" => Some(
            "# AUTHS-E5503\n\n**Crate:** `auths-sdk`  \n**Type:** `McpAuthError::InvalidResponse`\n\n## Message\n\ninvalid response: {0}\n",
        ),
        "AUTHS-E5504" => Some(
            "# AUTHS-E5504\n\n**Crate:** `auths-sdk`  \n**Type:** `McpAuthError::InsufficientCapabilities`\n\n## Message\n\ninsufficient capabilities: requested {requested:?}\n",
        ),

        // --- auths-sdk (TrustError) ---
        "AUTHS-E5551" => Some(
            "# AUTHS-E5551\n\n**Crate:** `auths-sdk`  \n**Type:** `TrustError::UnknownIdentity`\n\n## Message\n\nUnknown identity '{did}' and trust policy is '{policy}'\n",
        ),
        "AUTHS-E5552" => Some(
            "# AUTHS-E5552\n\n**Crate:** `auths-sdk`  \n**Type:** `TrustError::KeyResolutionFailed`\n\n## Message\n\nFailed to resolve public key for identity {did}\n",
        ),
        "AUTHS-E5553" => Some(
            "# AUTHS-E5553\n\n**Crate:** `auths-sdk`  \n**Type:** `TrustError::InvalidTrustStore`\n\n## Message\n\nInvalid trust store: {0}\n",
        ),
        "AUTHS-E5554" => Some(
            "# AUTHS-E5554\n\n**Crate:** `auths-sdk`  \n**Type:** `TrustError::TofuRequiresInteraction`\n\n## Message\n\nTOFU trust decision required but running in non-interactive mode\n",
        ),

        // --- auths-sdk (OrgError) ---
        "AUTHS-E5601" => Some(
            "# AUTHS-E5601\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::AdminNotFound`\n\n## Message\n\nno admin with the given public key found in organization '{org}'\n",
        ),
        "AUTHS-E5602" => Some(
            "# AUTHS-E5602\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::MemberNotFound`\n\n## Message\n\nmember '{did}' not found in organization '{org}'\n",
        ),
        "AUTHS-E5603" => Some(
            "# AUTHS-E5603\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::AlreadyRevoked`\n\n## Message\n\nmember '{did}' is already revoked\n",
        ),
        "AUTHS-E5604" => Some(
            "# AUTHS-E5604\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::InvalidCapability`\n\n## Message\n\ninvalid capability '{cap}': {reason}\n",
        ),
        "AUTHS-E5605" => Some(
            "# AUTHS-E5605\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::InvalidDid`\n\n## Message\n\ninvalid organization DID: {0}\n\n## Suggestion\n\nOrganization DIDs must be valid did:keri identifiers\n",
        ),
        "AUTHS-E5606" => Some(
            "# AUTHS-E5606\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::InvalidPublicKey`\n\n## Message\n\ninvalid public key: {0}\n\n## Suggestion\n\nPublic keys must be hex-encoded: 64 chars Ed25519 or 66 chars P-256 compressed SEC1\n",
        ),
        "AUTHS-E5607" => Some(
            "# AUTHS-E5607\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::Signing`\n\n## Message\n\nsigning error: {0}\n",
        ),
        "AUTHS-E5608" => Some(
            "# AUTHS-E5608\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::Identity`\n\n## Message\n\nidentity error: {0}\n",
        ),
        "AUTHS-E5609" => Some(
            "# AUTHS-E5609\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::KeyStorage`\n\n## Message\n\nkey storage error: {0}\n",
        ),
        "AUTHS-E5610" => Some(
            "# AUTHS-E5610\n\n**Crate:** `auths-sdk`  \n**Type:** `OrgError::Storage`\n\n## Message\n\nstorage error: {0}\n",
        ),

        // --- auths-sdk (ApprovalError) ---
        "AUTHS-E5701" => Some(
            "# AUTHS-E5701\n\n**Crate:** `auths-sdk`  \n**Type:** `ApprovalError::NotApprovalRequired`\n\n## Message\n\ndecision is not RequiresApproval\n",
        ),
        "AUTHS-E5702" => Some(
            "# AUTHS-E5702\n\n**Crate:** `auths-sdk`  \n**Type:** `ApprovalError::RequestNotFound`\n\n## Message\n\napproval request not found: {hash}\n",
        ),
        "AUTHS-E5703" => Some(
            "# AUTHS-E5703\n\n**Crate:** `auths-sdk`  \n**Type:** `ApprovalError::RequestExpired`\n\n## Message\n\napproval request expired at {expires_at}\n\n## Suggestion\n\nSubmit a new approval request\n",
        ),
        "AUTHS-E5704" => Some(
            "# AUTHS-E5704\n\n**Crate:** `auths-sdk`  \n**Type:** `ApprovalError::ApprovalAlreadyUsed`\n\n## Message\n\napproval already used (JTI: {jti})\n\n## Suggestion\n\nSubmit a new approval request\n",
        ),
        "AUTHS-E5705" => Some(
            "# AUTHS-E5705\n\n**Crate:** `auths-sdk`  \n**Type:** `ApprovalError::PartialApproval`\n\n## Message\n\napproval partially applied — attestation stored but nonce/cleanup failed: {0}\n\n## Suggestion\n\nCheck approval status and retry if needed\n",
        ),
        "AUTHS-E5706" => Some(
            "# AUTHS-E5706\n\n**Crate:** `auths-sdk`  \n**Type:** `ApprovalError::ApprovalStorage`\n\n## Message\n\nstorage error: {0}\n\n## Suggestion\n\nCheck file permissions and disk space\n",
        ),

        // --- auths-sdk (AllowedSignersError) ---
        "AUTHS-E5801" => Some(
            "# AUTHS-E5801\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::InvalidEmail`\n\n## Message\n\ninvalid email address: {0}\n\n## Suggestion\n\nEmail must be in user@domain.tld format\n",
        ),
        "AUTHS-E5802" => Some(
            "# AUTHS-E5802\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::InvalidKey`\n\n## Message\n\ninvalid SSH key: {0}\n",
        ),
        "AUTHS-E5803" => Some(
            "# AUTHS-E5803\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::FileRead`\n\n## Message\n\nfailed to read {path}: {source}\n\n## Suggestion\n\nCheck file exists and has correct permissions\n",
        ),
        "AUTHS-E5804" => Some(
            "# AUTHS-E5804\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::FileWrite`\n\n## Message\n\nfailed to write {path}: {source}\n\n## Suggestion\n\nCheck directory exists and has write permissions\n",
        ),
        "AUTHS-E5805" => Some(
            "# AUTHS-E5805\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::ParseError`\n\n## Message\n\nline {line}: {detail}\n",
        ),
        "AUTHS-E5806" => Some(
            "# AUTHS-E5806\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::DuplicatePrincipal`\n\n## Message\n\nprincipal already exists: {0}\n",
        ),
        "AUTHS-E5807" => Some(
            "# AUTHS-E5807\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::AttestationEntryProtected`\n\n## Message\n\ncannot remove attestation-managed entry: {0}\n",
        ),
        "AUTHS-E5808" => Some(
            "# AUTHS-E5808\n\n**Crate:** `auths-sdk`  \n**Type:** `AllowedSignersError::Storage`\n\n## Message\n\nattestation storage error: {0}\n\n## Suggestion\n\nCheck the auths repository at ~/.auths\n",
        ),

        // --- auths-sdk (ArtifactSigningError) ---
        "AUTHS-E5850" => Some(
            "# AUTHS-E5850\n\n**Crate:** `auths-sdk`  \n**Type:** `ArtifactSigningError::IdentityNotFound`\n\n## Message\n\nidentity not found in configured identity storage\n",
        ),
        "AUTHS-E5851" => Some(
            "# AUTHS-E5851\n\n**Crate:** `auths-sdk`  \n**Type:** `ArtifactSigningError::KeyResolutionFailed`\n\n## Message\n\nkey resolution failed: {0}\n",
        ),
        "AUTHS-E5852" => Some(
            "# AUTHS-E5852\n\n**Crate:** `auths-sdk`  \n**Type:** `ArtifactSigningError::KeyDecryptionFailed`\n\n## Message\n\nkey decryption failed: {0}\n\n## Suggestion\n\nCheck your passphrase and try again\n",
        ),
        "AUTHS-E5853" => Some(
            "# AUTHS-E5853\n\n**Crate:** `auths-sdk`  \n**Type:** `ArtifactSigningError::DigestFailed`\n\n## Message\n\ndigest computation failed: {0}\n\n## Suggestion\n\nVerify the file exists and is readable\n",
        ),
        "AUTHS-E5854" => Some(
            "# AUTHS-E5854\n\n**Crate:** `auths-sdk`  \n**Type:** `ArtifactSigningError::AttestationFailed`\n\n## Message\n\nattestation creation failed: {0}\n\n## Suggestion\n\nCheck identity storage with `auths status`\n",
        ),
        "AUTHS-E5855" => Some(
            "# AUTHS-E5855\n\n**Crate:** `auths-sdk`  \n**Type:** `ArtifactSigningError::ResignFailed`\n\n## Message\n\nattestation re-signing failed: {0}\n",
        ),

        // --- auths-sdk (SigningError) ---
        "AUTHS-E5901" => Some(
            "# AUTHS-E5901\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::IdentityFrozen`\n\n## Message\n\nidentity is frozen: {0}\n\n## Suggestion\n\nTo unfreeze: auths emergency unfreeze\n",
        ),
        "AUTHS-E5902" => Some(
            "# AUTHS-E5902\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::KeyResolution`\n\n## Message\n\nkey resolution failed: {0}\n\n## Suggestion\n\nRun `auths key list` to check available keys\n",
        ),
        "AUTHS-E5903" => Some(
            "# AUTHS-E5903\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::SigningFailed`\n\n## Message\n\nsigning operation failed: {0}\n",
        ),
        "AUTHS-E5904" => Some(
            "# AUTHS-E5904\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::InvalidPassphrase`\n\n## Message\n\ninvalid passphrase\n\n## Suggestion\n\nCheck your passphrase and try again\n",
        ),
        "AUTHS-E5905" => Some(
            "# AUTHS-E5905\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::PemEncoding`\n\n## Message\n\nPEM encoding failed: {0}\n",
        ),
        "AUTHS-E5906" => Some(
            "# AUTHS-E5906\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::AgentUnavailable`\n\n## Message\n\nagent unavailable: {0}\n\n## Suggestion\n\nStart the agent with `auths agent start`\n",
        ),
        "AUTHS-E5907" => Some(
            "# AUTHS-E5907\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::AgentSigningFailed`\n\n## Message\n\nagent signing failed\n\n## Suggestion\n\nCheck agent logs with `auths agent status`\n",
        ),
        "AUTHS-E5908" => Some(
            "# AUTHS-E5908\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::PassphraseExhausted`\n\n## Message\n\npassphrase exhausted after {attempts} attempt(s)\n",
        ),
        "AUTHS-E5909" => Some(
            "# AUTHS-E5909\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::KeychainUnavailable`\n\n## Message\n\nkeychain unavailable: {0}\n\n## Suggestion\n\nRun `auths doctor` to diagnose keychain issues\n",
        ),
        "AUTHS-E5910" => Some(
            "# AUTHS-E5910\n\n**Crate:** `auths-sdk`  \n**Type:** `SigningError::KeyDecryptionFailed`\n\n## Message\n\nkey decryption failed: {0}\n\n## Suggestion\n\nCheck your passphrase and try again\n",
        ),

        // --- auths-sdk (AuthChallengeError) ---
        "AUTHS-E6001" => Some(
            "# AUTHS-E6001\n\n**Crate:** `auths-sdk`  \n**Type:** `AuthChallengeError::EmptyNonce`\n\n## Message\n\nnonce must not be empty\n\n## Suggestion\n\nProvide the nonce from the authentication challenge\n",
        ),
        "AUTHS-E6002" => Some(
            "# AUTHS-E6002\n\n**Crate:** `auths-sdk`  \n**Type:** `AuthChallengeError::EmptyDomain`\n\n## Message\n\ndomain must not be empty\n\n## Suggestion\n\nProvide the domain (e.g. auths.dev)\n",
        ),
        "AUTHS-E6003" => Some(
            "# AUTHS-E6003\n\n**Crate:** `auths-sdk`  \n**Type:** `AuthChallengeError::Canonicalization`\n\n## Message\n\ncanonical JSON serialization failed: {0}\n",
        ),
        "AUTHS-E6004" => Some(
            "# AUTHS-E6004\n\n**Crate:** `auths-sdk`  \n**Type:** `AuthChallengeError::SigningFailed`\n\n## Message\n\nsigning failed: {0}\n",
        ),

        // --- auths-oidc-port (OidcError) ---
        "AUTHS-E8001" => Some(
            "# AUTHS-E8001\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::JwtDecode`\n\n## Message\n\nJWT decode failed: {0}\n",
        ),
        "AUTHS-E8002" => Some(
            "# AUTHS-E8002\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::SignatureVerificationFailed`\n\n## Message\n\nsignature verification failed\n",
        ),
        "AUTHS-E8003" => Some(
            "# AUTHS-E8003\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::ClaimsValidationFailed`\n\n## Message\n\nclaim validation failed - {claim}: {reason}\n",
        ),
        "AUTHS-E8004" => Some(
            "# AUTHS-E8004\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::UnknownKeyId`\n\n## Message\n\nunknown key ID: {0}\n",
        ),
        "AUTHS-E8005" => Some(
            "# AUTHS-E8005\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::JwksResolutionFailed`\n\n## Message\n\nJWKS resolution failed: {0}\n",
        ),
        "AUTHS-E8006" => Some(
            "# AUTHS-E8006\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::AlgorithmMismatch`\n\n## Message\n\nalgorithm mismatch: expected {expected}, got {got}\n",
        ),
        "AUTHS-E8007" => Some(
            "# AUTHS-E8007\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::ClockSkewExceeded`\n\n## Message\n\ntoken expired (exp: {token_exp}, now: {current_time}, leeway: {leeway}s)\n",
        ),
        "AUTHS-E8008" => Some(
            "# AUTHS-E8008\n\n**Crate:** `auths-oidc-port`  \n**Type:** `OidcError::TokenReplayDetected`\n\n## Message\n\ntoken replay detected (jti: {0})\n",
        ),

        _ => None,
    }
}

/// Returns a sorted slice of all registered error codes.
pub fn all_codes() -> &'static [&'static str] {
    static CODES: &[&str] = &[
        "AUTHS-E1001",
        "AUTHS-E1003",
        "AUTHS-E1004",
        "AUTHS-E1005",
        "AUTHS-E1101",
        "AUTHS-E1102",
        "AUTHS-E1103",
        "AUTHS-E1104",
        "AUTHS-E1201",
        "AUTHS-E1202",
        "AUTHS-E1203",
        "AUTHS-E1204",
        "AUTHS-E1301",
        "AUTHS-E1302",
        "AUTHS-E2001",
        "AUTHS-E2002",
        "AUTHS-E2003",
        "AUTHS-E2004",
        "AUTHS-E2005",
        "AUTHS-E2006",
        "AUTHS-E2007",
        "AUTHS-E2008",
        "AUTHS-E2009",
        "AUTHS-E2010",
        "AUTHS-E2011",
        "AUTHS-E2012",
        "AUTHS-E2013",
        "AUTHS-E2014",
        "AUTHS-E2015",
        "AUTHS-E2016",
        "AUTHS-E2017",
        "AUTHS-E2018",
        "AUTHS-E2101",
        "AUTHS-E2102",
        "AUTHS-E2103",
        "AUTHS-E2104",
        "AUTHS-E2105",
        "AUTHS-E2106",
        "AUTHS-E2107",
        "AUTHS-E2108",
        "AUTHS-E2109",
        "AUTHS-E3001",
        "AUTHS-E3002",
        "AUTHS-E3003",
        "AUTHS-E3004",
        "AUTHS-E3005",
        "AUTHS-E3006",
        "AUTHS-E3007",
        "AUTHS-E3008",
        "AUTHS-E3009",
        "AUTHS-E3010",
        "AUTHS-E3011",
        "AUTHS-E3012",
        "AUTHS-E3013",
        "AUTHS-E3014",
        "AUTHS-E3015",
        "AUTHS-E3016",
        "AUTHS-E3017",
        "AUTHS-E3018",
        "AUTHS-E3019",
        "AUTHS-E3020",
        "AUTHS-E3021",
        "AUTHS-E3022",
        "AUTHS-E3023",
        "AUTHS-E3024",
        "AUTHS-E3101",
        "AUTHS-E3102",
        "AUTHS-E3103",
        "AUTHS-E3104",
        "AUTHS-E3105",
        "AUTHS-E3106",
        "AUTHS-E3107",
        "AUTHS-E3201",
        "AUTHS-E3202",
        "AUTHS-E3203",
        "AUTHS-E3204",
        "AUTHS-E3205",
        "AUTHS-E3206",
        "AUTHS-E3207",
        "AUTHS-E3301",
        "AUTHS-E3302",
        "AUTHS-E3303",
        "AUTHS-E3304",
        "AUTHS-E3305",
        "AUTHS-E3401",
        "AUTHS-E3402",
        "AUTHS-E3403",
        "AUTHS-E3404",
        "AUTHS-E3405",
        "AUTHS-E3406",
        "AUTHS-E3407",
        "AUTHS-E3408",
        "AUTHS-E3409",
        "AUTHS-E3501",
        "AUTHS-E3502",
        "AUTHS-E3503",
        "AUTHS-E3504",
        "AUTHS-E3505",
        "AUTHS-E3601",
        "AUTHS-E3602",
        "AUTHS-E3603",
        "AUTHS-E3604",
        "AUTHS-E3605",
        "AUTHS-E3606",
        "AUTHS-E3701",
        "AUTHS-E3702",
        "AUTHS-E3703",
        "AUTHS-E3704",
        "AUTHS-E3801",
        "AUTHS-E3802",
        "AUTHS-E3803",
        "AUTHS-E3804",
        "AUTHS-E3805",
        "AUTHS-E3806",
        "AUTHS-E3901",
        "AUTHS-E3902",
        "AUTHS-E3903",
        "AUTHS-E3951",
        "AUTHS-E3952",
        "AUTHS-E3961",
        "AUTHS-E3962",
        "AUTHS-E3963",
        "AUTHS-E3964",
        "AUTHS-E3965",
        "AUTHS-E3966",
        "AUTHS-E3967",
        "AUTHS-E3968",
        "AUTHS-E4001",
        "AUTHS-E4002",
        "AUTHS-E4003",
        "AUTHS-E4004",
        "AUTHS-E4101",
        "AUTHS-E4102",
        "AUTHS-E4103",
        "AUTHS-E4104",
        "AUTHS-E4105",
        "AUTHS-E4106",
        "AUTHS-E4107",
        "AUTHS-E4201",
        "AUTHS-E4202",
        "AUTHS-E4203",
        "AUTHS-E4204",
        "AUTHS-E4205",
        "AUTHS-E4206",
        "AUTHS-E4207",
        "AUTHS-E4208",
        "AUTHS-E4301",
        "AUTHS-E4302",
        "AUTHS-E4303",
        "AUTHS-E4304",
        "AUTHS-E4305",
        "AUTHS-E4401",
        "AUTHS-E4402",
        "AUTHS-E4403",
        "AUTHS-E4404",
        "AUTHS-E4405",
        "AUTHS-E4406",
        "AUTHS-E4407",
        "AUTHS-E4408",
        "AUTHS-E4409",
        "AUTHS-E4410",
        "AUTHS-E4411",
        "AUTHS-E4501",
        "AUTHS-E4502",
        "AUTHS-E4503",
        "AUTHS-E4504",
        "AUTHS-E4505",
        "AUTHS-E4506",
        "AUTHS-E4507",
        "AUTHS-E4508",
        "AUTHS-E4509",
        "AUTHS-E4510",
        "AUTHS-E4601",
        "AUTHS-E4602",
        "AUTHS-E4603",
        "AUTHS-E4604",
        "AUTHS-E4605",
        "AUTHS-E4606",
        "AUTHS-E4607",
        "AUTHS-E4701",
        "AUTHS-E4702",
        "AUTHS-E4703",
        "AUTHS-E4704",
        "AUTHS-E4705",
        "AUTHS-E4706",
        "AUTHS-E4707",
        "AUTHS-E4708",
        "AUTHS-E4801",
        "AUTHS-E4802",
        "AUTHS-E4803",
        "AUTHS-E4804",
        "AUTHS-E4805",
        "AUTHS-E4806",
        "AUTHS-E4807",
        "AUTHS-E4851",
        "AUTHS-E4852",
        "AUTHS-E4853",
        "AUTHS-E4861",
        "AUTHS-E4862",
        "AUTHS-E4863",
        "AUTHS-E4864",
        "AUTHS-E4865",
        "AUTHS-E4866",
        "AUTHS-E4867",
        "AUTHS-E4868",
        "AUTHS-E4869",
        "AUTHS-E4870",
        "AUTHS-E4871",
        "AUTHS-E4872",
        "AUTHS-E4873",
        "AUTHS-E4874",
        "AUTHS-E4875",
        "AUTHS-E4876",
        "AUTHS-E4877",
        "AUTHS-E4901",
        "AUTHS-E4902",
        "AUTHS-E4903",
        "AUTHS-E4904",
        "AUTHS-E4905",
        "AUTHS-E4951",
        "AUTHS-E4952",
        "AUTHS-E4953",
        "AUTHS-E4954",
        "AUTHS-E4955",
        "AUTHS-E4956",
        "AUTHS-E4957",
        "AUTHS-E4961",
        "AUTHS-E4962",
        "AUTHS-E4963",
        "AUTHS-E4964",
        "AUTHS-E4965",
        "AUTHS-E4971",
        "AUTHS-E4972",
        "AUTHS-E4973",
        "AUTHS-E4981",
        "AUTHS-E4982",
        "AUTHS-E4991",
        "AUTHS-E4992",
        "AUTHS-E5001",
        "AUTHS-E5002",
        "AUTHS-E5004",
        "AUTHS-E5006",
        "AUTHS-E5007",
        "AUTHS-E5101",
        "AUTHS-E5102",
        "AUTHS-E5103",
        "AUTHS-E5105",
        "AUTHS-E5201",
        "AUTHS-E5202",
        "AUTHS-E5203",
        "AUTHS-E5204",
        "AUTHS-E5301",
        "AUTHS-E5302",
        "AUTHS-E5303",
        "AUTHS-E5304",
        "AUTHS-E5305",
        "AUTHS-E5306",
        "AUTHS-E5401",
        "AUTHS-E5402",
        "AUTHS-E5403",
        "AUTHS-E5404",
        "AUTHS-E5405",
        "AUTHS-E5406",
        "AUTHS-E5501",
        "AUTHS-E5502",
        "AUTHS-E5503",
        "AUTHS-E5504",
        "AUTHS-E5551",
        "AUTHS-E5552",
        "AUTHS-E5553",
        "AUTHS-E5554",
        "AUTHS-E5601",
        "AUTHS-E5602",
        "AUTHS-E5603",
        "AUTHS-E5604",
        "AUTHS-E5605",
        "AUTHS-E5606",
        "AUTHS-E5607",
        "AUTHS-E5608",
        "AUTHS-E5609",
        "AUTHS-E5610",
        "AUTHS-E5701",
        "AUTHS-E5702",
        "AUTHS-E5703",
        "AUTHS-E5704",
        "AUTHS-E5705",
        "AUTHS-E5706",
        "AUTHS-E5801",
        "AUTHS-E5802",
        "AUTHS-E5803",
        "AUTHS-E5804",
        "AUTHS-E5805",
        "AUTHS-E5806",
        "AUTHS-E5807",
        "AUTHS-E5808",
        "AUTHS-E5850",
        "AUTHS-E5851",
        "AUTHS-E5852",
        "AUTHS-E5853",
        "AUTHS-E5854",
        "AUTHS-E5855",
        "AUTHS-E5901",
        "AUTHS-E5902",
        "AUTHS-E5903",
        "AUTHS-E5904",
        "AUTHS-E5905",
        "AUTHS-E5906",
        "AUTHS-E5907",
        "AUTHS-E5908",
        "AUTHS-E5909",
        "AUTHS-E5910",
        "AUTHS-E6001",
        "AUTHS-E6002",
        "AUTHS-E6003",
        "AUTHS-E6004",
        "AUTHS-E8001",
        "AUTHS-E8002",
        "AUTHS-E8003",
        "AUTHS-E8004",
        "AUTHS-E8005",
        "AUTHS-E8006",
        "AUTHS-E8007",
        "AUTHS-E8008",
    ];
    CODES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_returns_content_for_known_code() {
        assert!(explain("AUTHS-E1001").is_some());
    }

    #[test]
    fn explain_returns_none_for_unknown_code() {
        assert!(explain("AUTHS-E9999").is_none());
    }

    #[test]
    fn all_codes_is_sorted() {
        let codes = all_codes();
        assert!(!codes.is_empty());
        for window in codes.windows(2) {
            assert!(
                window[0] < window[1],
                "codes not sorted: {} >= {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn all_codes_count_matches_registry() {
        assert_eq!(all_codes().len(), 323);
    }
}
