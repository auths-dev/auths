use auths_storage::git::{GitRegistryBackend, RegistryConfig};

auths_id::registry_backend_contract_tests!(
    fake,
    (auths_id::testing::fakes::FakeRegistryBackend::new(), ())
);

auths_id::registry_backend_contract_tests!(packed, {
    let dir = tempfile::tempdir().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (backend, dir)
});
