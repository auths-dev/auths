use auths_storage::git::{GitRegistryBackend, RegistryConfig};

auths_test_utils::registry_backend_contract_tests!(
    fake,
    (
        auths_test_utils::fakes::registry::FakeRegistryBackend::new(),
        ()
    )
);

auths_test_utils::registry_backend_contract_tests!(packed, {
    let dir = tempfile::tempdir().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (backend, dir)
});
