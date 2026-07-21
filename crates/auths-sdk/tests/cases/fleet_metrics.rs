//! Epic E1.15 — fleet metrics: counts + traceability derived from the KEL + walker.

use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::agents::{add_scoped, revoke};
use auths_sdk::domains::org::metrics::fleet_metrics;
use auths_sdk::identity::initialize_registry_identity;
use auths_sdk::witness::WitnessParams;
use auths_verifier::Prefix;

const PASS: &str = "Test-passphrase1!";

fn setup() -> (AuthsContext, KeyAlias, Prefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let provider = PrefilledPassphraseProvider::new(PASS);
    let boot = crate::cases::helpers::build_test_context(tmp.path(), Arc::new(keychain.clone()));
    // Bare org root (no delegated device #0) — mirror create_org. The fleet roster then holds
    // only the agents/members this test adds, so device #0 never inflates the counts.
    let (_org_did, org_alias) = initialize_registry_identity(
        Arc::clone(&boot.registry),
        &KeyAlias::new_unchecked("org-key"),
        &provider,
        &keychain,
        WitnessParams::Disabled,
        CurveType::default(),
        chrono::Utc::now(),
    )
    .expect("init bare org identity");
    let arc_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = crate::cases::helpers::build_test_context_with_provider(
        tmp.path(),
        Arc::new(keychain),
        Some(arc_provider),
    );
    let org_prefix = Prefix::new_unchecked(
        ctx.identity_storage
            .load_identity()
            .unwrap()
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    (ctx, org_alias, org_prefix, tmp)
}

#[test]
fn fleet_metrics_count_live_revoked_and_traceable() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let mut dids = Vec::new();
    for label in ["agent-1", "agent-2", "agent-3"] {
        let a = add_scoped(
            &ctx,
            &org_alias,
            &KeyAlias::new_unchecked(label.to_string()),
            CurveType::Ed25519,
            &[auths_keri::Capability::sign_commit()],
            None,
        )
        .expect("add agent");
        dids.push(a.agent_did);
    }
    // Revoke one.
    revoke(&ctx, &org_alias, &dids[0]).expect("revoke");

    let m = fleet_metrics(&ctx, &org_prefix).expect("metrics");
    assert_eq!(m.agents_total, 3);
    assert_eq!(m.agents_revoked, 1);
    assert_eq!(m.agents_live, 2);
    // Both live agents are direct delegates of the org → traceable to the root.
    assert_eq!(m.agents_traceable_to_human, 2);
    assert!((m.traceability_fraction - 1.0).abs() < f64::EPSILON);
    assert_eq!(m.revocation_effect_latency_positions, 0);
}
