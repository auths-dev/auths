use auths_sdk::domains::signing::service::{self as signing, SigningConfig, SigningError};
use auths_sdk::workflows::signing::{
    CommitSigningContext, CommitSigningParams, CommitSigningWorkflow,
};

#[test]
fn test_validate_freeze_state_unfrozen() {
    let temp = tempfile::tempdir().unwrap();
    let result = signing::validate_freeze_state(temp.path(), chrono::Utc::now());
    assert!(result.is_ok(), "unfrozen state should pass validation");
}

#[test]
fn test_construct_signature_payload() {
    let data = b"test data";
    let result = signing::construct_signature_payload(data, "git");
    assert!(result.is_ok());

    let payload = result.unwrap();
    assert_eq!(
        &payload[0..6],
        b"SSHSIG",
        "payload must start with SSHSIG magic"
    );
    assert_eq!(&payload[6..10], &3u32.to_be_bytes(), "namespace length");
    assert_eq!(&payload[10..13], b"git");
}

#[test]
fn test_sign_with_known_seed() {
    use auths_core::crypto::ssh::SecureSeed;

    let seed = SecureSeed::new([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]);

    let pem = signing::sign_with_seed(&seed, b"test data", "git", auths_crypto::CurveType::Ed25519)
        .unwrap();
    assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
    assert!(pem.contains("-----END SSH SIGNATURE-----"));
}

#[test]
fn test_signing_error_is_thiserror() {
    let err = SigningError::IdentityFrozen("test freeze".to_string());
    assert!(err.to_string().contains("frozen"));

    let err = SigningError::InvalidPassphrase;
    assert_eq!(err.to_string(), "invalid passphrase");
}

#[test]
fn test_signing_config_fields() {
    let config = SigningConfig {
        namespace: "git".to_string(),
    };
    assert_eq!(config.namespace, "git");
}

// ---------------------------------------------------------------------------
// CommitSigningWorkflow tests
// ---------------------------------------------------------------------------

mod workflow {
    use super::*;
    use crate::cases::helpers::setup_signed_artifact_context;
    use auths_core::PrefilledPassphraseProvider;
    use auths_sdk::ports::agent::AgentSigningError;
    use auths_sdk::testing::fakes::FakeAgentProvider;
    use std::sync::Arc;

    #[test]
    fn agent_sign_succeeds_returns_pem() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();
        let fake_pem = "-----BEGIN SSH SIGNATURE-----\nfake\n-----END SSH SIGNATURE-----";
        let fake = Arc::new(FakeAgentProvider::signing_with(fake_pem));

        let ctx = signing_ctx_with_agent(&ctx, fake.clone());

        let params = CommitSigningParams::new(alias.as_str(), "git", b"test data".to_vec())
            .with_pubkey(auths_verifier::DevicePublicKey::ed25519(&[0u8; 32]));

        let result = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), fake_pem);

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn agent_unavailable_falls_through_to_direct_sign() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();
        let fake = Arc::new(FakeAgentProvider::unavailable());
        let ctx = signing_ctx_with_agent(&ctx, fake);

        let params = CommitSigningParams::new(alias.as_str(), "git", b"test data".to_vec())
            .with_max_passphrase_attempts(1);

        let result = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now());
        assert!(result.is_ok());
        let pem = result.unwrap();
        assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
    }

    #[test]
    fn agent_connection_failed_falls_through_to_direct_sign() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();
        let fake = Arc::new(FakeAgentProvider::sign_fails_with(
            AgentSigningError::ConnectionFailed("socket gone".into()),
        ));
        let ctx = signing_ctx_with_agent(&ctx, fake);

        let params = CommitSigningParams::new(alias.as_str(), "git", b"test data".to_vec())
            .with_max_passphrase_attempts(1);

        let result = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now());
        assert!(result.is_ok());
    }

    #[test]
    fn agent_signing_failed_is_fatal() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();
        let fake = Arc::new(FakeAgentProvider::sign_fails_with(
            AgentSigningError::SigningFailed("bad signature".into()),
        ));
        let ctx = signing_ctx_with_agent(&ctx, fake);

        let params = CommitSigningParams::new(alias.as_str(), "git", b"test data".to_vec())
            .with_pubkey(auths_verifier::DevicePublicKey::ed25519(&[0u8; 32]));

        let result = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SigningError::AgentSigningFailed(_)),
            "expected AgentSigningFailed, got: {err}"
        );
    }

    #[test]
    fn passphrase_exhaustion_returns_error() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();

        let wrong_provider = Arc::new(PrefilledPassphraseProvider::new("wrong-passphrase"))
            as Arc<dyn auths_core::signing::PassphraseProvider + Send + Sync>;
        let ctx = signing_ctx_with_provider(
            &ctx,
            Arc::new(FakeAgentProvider::unavailable()),
            wrong_provider,
        );

        let params = CommitSigningParams::new(alias.as_str(), "git", b"test data".to_vec())
            .with_max_passphrase_attempts(1);

        let result = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SigningError::PassphraseExhausted { attempts: 1 }),
            "expected PassphraseExhausted(1), got: {err}"
        );
    }

    #[test]
    fn add_identity_failure_is_non_fatal() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();
        let fake = Arc::new(FakeAgentProvider::unavailable());
        let ctx = signing_ctx_with_agent(&ctx, fake.clone());

        let params = CommitSigningParams::new(alias.as_str(), "git", b"test data".to_vec())
            .with_max_passphrase_attempts(1);

        let result = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now());
        assert!(
            result.is_ok(),
            "add_identity failure should not block signing"
        );
    }

    #[test]
    fn workflow_returns_sshsig_pem_format() {
        let (_tmp, alias, ctx) = setup_signed_artifact_context();
        let fake = Arc::new(FakeAgentProvider::unavailable());
        let ctx = signing_ctx_with_agent(&ctx, fake);

        let params = CommitSigningParams::new(alias.as_str(), "git", b"verify format".to_vec())
            .with_max_passphrase_attempts(1);

        let pem = CommitSigningWorkflow::execute(&ctx, params, chrono::Utc::now()).unwrap();
        assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(pem.contains("-----END SSH SIGNATURE-----"));
    }

    // --- helpers ---

    fn signing_ctx_with_agent(
        base: &auths_sdk::context::AuthsContext,
        agent: Arc<dyn auths_sdk::ports::agent::AgentSigningPort + Send + Sync>,
    ) -> CommitSigningContext {
        CommitSigningContext {
            key_storage: base.key_storage.clone(),
            passphrase_provider: base.passphrase_provider.clone(),
            agent_signing: agent,
        }
    }

    fn signing_ctx_with_provider(
        base: &auths_sdk::context::AuthsContext,
        agent: Arc<dyn auths_sdk::ports::agent::AgentSigningPort + Send + Sync>,
        passphrase: Arc<dyn auths_core::signing::PassphraseProvider + Send + Sync>,
    ) -> CommitSigningContext {
        CommitSigningContext {
            key_storage: base.key_storage.clone(),
            passphrase_provider: passphrase,
            agent_signing: agent,
        }
    }
}
