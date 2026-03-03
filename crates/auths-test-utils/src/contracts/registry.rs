/// Contract test suite for [`RegistryBackend`] implementations.
///
/// Generates a module with `#[test]` cases that verify behavioural correctness
/// for any [`RegistryBackend`] implementation.
///
/// Args:
/// * `$name` — identifier for the generated module (e.g. `fake_backend`).
/// * `$setup` — expression evaluated fresh inside each test; must return
///   `(impl RegistryBackend, _guard)`. The `_guard` keeps any backing resource
///   (e.g. `TempDir`) alive for the duration of the test. For in-memory fakes,
///   pass `(FakeRegistryBackend::new(), ())`.
///
/// Usage:
/// ```ignore
/// // Fake (no guard needed):
/// registry_backend_contract_tests!(fake, (FakeRegistryBackend::new(), ()));
///
/// // Packed (TempDir guard):
/// registry_backend_contract_tests!(packed, {
///     let dir = tempfile::tempdir().unwrap();
///     let backend = GitRegistryBackend::from_config_unchecked(
///         RegistryConfig::single_tenant(dir.path()),
///     );
///     backend.init_if_needed().unwrap();
///     (backend, dir)
/// });
/// ```
#[macro_export]
macro_rules! registry_backend_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use std::ops::ControlFlow;

            use super::*;
            use auths_id::storage::registry::RegistryBackend as _;

            #[test]
            fn contract_append_and_get_event() {
                let (store, _guard) = $setup;
                let event = auths_test_utils::fixtures::test_inception_event("seed-append-get");
                let prefix = event.prefix().clone();
                store.append_event(&prefix, &event).unwrap();
                let got = store.get_event(&prefix, 0).unwrap();
                assert_eq!(got.said(), event.said());
            }

            #[test]
            fn contract_get_event_not_found() {
                use auths_id::keri::types::Prefix;

                let (store, _guard) = $setup;
                let prefix = Prefix::new_unchecked(
                    "EUnknownPrefix000000000000000000000000000000".to_string(),
                );
                let result = store.get_event(&prefix, 0);
                assert!(result.is_err(), "missing event should return Err");
            }

            #[test]
            fn contract_append_refuses_duplicate_sequence() {
                let (store, _guard) = $setup;
                let event = auths_test_utils::fixtures::test_inception_event("seed-dup");
                let prefix = event.prefix().clone();
                store.append_event(&prefix, &event).unwrap();
                // A second inception event with the same seed produces the same SAID/prefix,
                // so appending it again at seq 0 should fail.
                let again = auths_test_utils::fixtures::test_inception_event("seed-dup");
                let result = store.append_event(&prefix, &again);
                assert!(result.is_err(), "duplicate seq 0 should be rejected");
            }

            #[test]
            fn contract_get_tip_after_append() {
                let (store, _guard) = $setup;
                let event = auths_test_utils::fixtures::test_inception_event("seed-tip");
                let prefix = event.prefix().clone();
                store.append_event(&prefix, &event).unwrap();
                let tip = store.get_tip(&prefix).unwrap();
                assert_eq!(tip.sequence, 0);
                assert_eq!(&tip.said, event.said());
            }

            #[test]
            fn contract_get_key_state_not_found() {
                use auths_id::keri::types::Prefix;

                let (store, _guard) = $setup;
                let prefix = Prefix::new_unchecked(
                    "EUnknownPrefix000000000000000000000000000000".to_string(),
                );
                let result = store.get_key_state(&prefix);
                assert!(result.is_err(), "missing key state should return Err");
            }

            #[test]
            fn contract_write_and_get_key_state() {
                use auths_id::keri::state::KeyState;

                let (store, _guard) = $setup;
                // GitRegistryBackend requires the identity to exist before
                // write_key_state can update state.json, so append the ICP first.
                let event =
                    auths_test_utils::fixtures::test_inception_event("seed-write-key-state");
                let prefix = event.prefix().clone();
                store.append_event(&prefix, &event).unwrap();

                let ks = KeyState::from_inception(
                    prefix.clone(),
                    vec!["DTestKey".to_string()],
                    vec!["ETestNext".to_string()],
                    1,
                    1,
                    event.said().clone(),
                );
                store.write_key_state(&prefix, &ks).unwrap();
                let got = store.get_key_state(&prefix).unwrap();
                assert_eq!(got.prefix, prefix);
            }

            #[test]
            fn contract_visit_events_early_exit() {
                let (store, _guard) = $setup;
                let event = auths_test_utils::fixtures::test_inception_event("seed-visit-events");
                let prefix = event.prefix().clone();
                store.append_event(&prefix, &event).unwrap();

                let mut visited = 0usize;
                store
                    .visit_events(&prefix, 0, &mut |_| {
                        visited += 1;
                        ControlFlow::Break(())
                    })
                    .unwrap();
                assert_eq!(
                    visited, 1,
                    "early-exit visitor should visit exactly 1 event"
                );
            }

            #[test]
            fn contract_visit_identities_early_exit() {
                let (store, _guard) = $setup;
                let e0 = auths_test_utils::fixtures::test_inception_event("seed-ident-a");
                let e1 = auths_test_utils::fixtures::test_inception_event("seed-ident-b");
                store.append_event(e0.prefix(), &e0).unwrap();
                store.append_event(e1.prefix(), &e1).unwrap();

                let mut seen = 0usize;
                store
                    .visit_identities(&mut |_| {
                        seen += 1;
                        ControlFlow::Break(())
                    })
                    .unwrap();
                assert_eq!(
                    seen, 1,
                    "early-exit visitor should stop after first identity"
                );
            }

            #[test]
            fn contract_store_and_load_attestation() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let did = DeviceDID::new("did:key:zContractStoreLoad1");
                let att = auths_test_utils::fixtures::test_attestation(&did, "did:keri:EIssuer1");
                store.store_attestation(&att).unwrap();
                let loaded = store.load_attestation(&did).unwrap();
                assert!(
                    loaded.is_some(),
                    "attestation should be present after store"
                );
                assert_eq!(loaded.unwrap().subject, did);
            }

            #[test]
            fn contract_load_attestation_not_found() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let did = DeviceDID::new("did:key:zNotStored99");
                let result = store.load_attestation(&did).unwrap();
                assert!(result.is_none(), "missing attestation should return None");
            }

            #[test]
            fn contract_store_attestation_overwrites_latest() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let did = DeviceDID::new("did:key:zContractOverwrite1");
                let att1 = auths_test_utils::fixtures::test_attestation(&did, "did:keri:EIssuer1");
                let mut att2 =
                    auths_test_utils::fixtures::test_attestation(&did, "did:keri:EIssuer1");
                att2.rid = "updated-rid".to_string();

                store.store_attestation(&att1).unwrap();
                store.store_attestation(&att2).unwrap();

                let loaded = store.load_attestation(&did).unwrap().unwrap();
                assert_eq!(
                    loaded.rid, "updated-rid",
                    "second store should overwrite latest"
                );
            }

            #[test]
            fn contract_attestation_history_preserves_order() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let did = DeviceDID::new("did:key:zContractHistory1");

                for i in 0..3u32 {
                    let mut att =
                        auths_test_utils::fixtures::test_attestation(&did, "did:keri:EIssuer1");
                    att.rid = format!("rid-{}", i);
                    store.store_attestation(&att).unwrap();
                }

                let mut history = Vec::new();
                store
                    .visit_attestation_history(&did, &mut |att| {
                        history.push(att.rid.clone());
                        ControlFlow::Continue(())
                    })
                    .unwrap();

                assert_eq!(history.len(), 3);
                assert_eq!(history[0], "rid-0");
                assert_eq!(history[2], "rid-2");
            }

            #[test]
            fn contract_visit_attestation_history_early_exit() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let did = DeviceDID::new("did:key:zContractHistExit1");
                for i in 0..3u32 {
                    let mut att =
                        auths_test_utils::fixtures::test_attestation(&did, "did:keri:EIssuer1");
                    att.rid = format!("rid-{}", i);
                    store.store_attestation(&att).unwrap();
                }

                let mut count = 0usize;
                store
                    .visit_attestation_history(&did, &mut |_| {
                        count += 1;
                        ControlFlow::Break(())
                    })
                    .unwrap();
                assert_eq!(count, 1, "early-exit visitor should stop after first entry");
            }

            #[test]
            fn contract_visit_devices_early_exit() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let did1 = DeviceDID::new("did:key:zContractDev1");
                let did2 = DeviceDID::new("did:key:zContractDev2");
                store
                    .store_attestation(&auths_test_utils::fixtures::test_attestation(
                        &did1,
                        "did:keri:EIssuer1",
                    ))
                    .unwrap();
                store
                    .store_attestation(&auths_test_utils::fixtures::test_attestation(
                        &did2,
                        "did:keri:EIssuer1",
                    ))
                    .unwrap();

                let mut seen = 0usize;
                store
                    .visit_devices(&mut |_| {
                        seen += 1;
                        ControlFlow::Break(())
                    })
                    .unwrap();
                assert_eq!(seen, 1, "early-exit visitor should stop after first device");
            }

            #[test]
            fn contract_store_and_visit_org_member() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let org = "ETestOrgPrefix";
                let did = DeviceDID::new("did:key:zMemberContract1");
                let mut att =
                    auths_test_utils::fixtures::test_attestation(&did, "did:keri:ETestOrgPrefix");
                att.rid = "org-rid".to_string();

                store.store_org_member(org, &att).unwrap();

                let mut found = false;
                store
                    .visit_org_member_attestations(org, &mut |entry| {
                        if entry.did == did {
                            found = true;
                        }
                        ControlFlow::Continue(())
                    })
                    .unwrap();
                assert!(found, "org member should be visible after store");
            }

            #[test]
            fn contract_metadata_reflects_counts() {
                use auths_verifier::types::DeviceDID;

                let (store, _guard) = $setup;
                let event = auths_test_utils::fixtures::test_inception_event("seed-metadata");
                let prefix = event.prefix().clone();
                store.append_event(&prefix, &event).unwrap();

                let did = DeviceDID::new("did:key:zContractMeta1");
                store
                    .store_attestation(&auths_test_utils::fixtures::test_attestation(
                        &did,
                        "did:keri:EIssuer1",
                    ))
                    .unwrap();

                let meta = store.metadata().unwrap();
                assert!(
                    meta.identity_count >= 1,
                    "at least one identity should be counted"
                );
                assert!(
                    meta.device_count >= 1,
                    "at least one device should be counted"
                );
            }
        }
    };
}
