use clap::Args;

#[derive(Args, Debug, Clone, Default)]
pub struct RegistryOverrides {
    #[arg(
        long = "identity-ref",
        value_name = "GIT_REF",
        help = "Override Git ref for the identity commit [default: refs/auths/identity]"
    )]
    pub identity_ref: Option<String>,

    #[arg(
        long = "identity-blob",
        value_name = "FILENAME",
        help = "Override blob filename for identity data [default: identity.json]"
    )]
    pub identity_blob: Option<String>,

    #[arg(
        long = "attestation-prefix",
        value_name = "GIT_REF_PREFIX",
        help = "Override base Git ref prefix for device authorizations [default: refs/auths/keys]"
    )]
    pub attestation_prefix: Option<String>,

    #[arg(
        long = "attestation-blob",
        value_name = "FILENAME",
        help = "Override blob filename for device authorization data [default: attestation.json]"
    )]
    pub attestation_blob: Option<String>,
}
