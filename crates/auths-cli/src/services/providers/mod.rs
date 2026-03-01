pub mod github;

use anyhow::Result;

use crate::ux::format::Output;
use auths_core::signing::PassphraseProvider;

pub struct PlatformAuth {
    pub username: String,
    pub proof_url: String,
}

pub struct ClaimContext<'a> {
    pub out: &'a Output,
    pub controller_did: &'a str,
    pub key_alias: &'a str,
    pub passphrase_provider: &'a dyn PassphraseProvider,
    pub http_client: &'a reqwest::Client,
}

pub trait PlatformClaimProvider {
    fn platform_name(&self) -> &'static str;
    fn authenticate_and_publish(&self, ctx: &ClaimContext) -> Result<PlatformAuth>;
}
