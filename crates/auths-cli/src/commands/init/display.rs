//! Display functions for init command results.

use crate::ux::format::Output;

pub(crate) fn display_developer_result(
    out: &Output,
    result: &auths_sdk::result::DeveloperIdentityResult,
    registered: Option<&str>,
) {
    out.newline();
    if registered.is_some() {
        out.print_heading("You are on the Web of Trust!");
    } else {
        out.print_heading("Your identity is ready!");
    }
    out.newline();
    out.println(&format!("  Identity: {}", out.info(&result.identity_did)));
    out.println(&format!("  Key alias: {}", out.info(&result.key_alias)));
    if let Some(registry) = registered {
        out.println(&format!("  Registry: {}", out.info(registry)));
        let did_prefix = result
            .identity_did
            .strip_prefix("did:keri:")
            .unwrap_or(&result.identity_did);
        out.println(&format!(
            "  Profile: {}",
            out.info(&format!("https://auths.dev/registry/identity/{did_prefix}"))
        ));
    }
    out.newline();
    out.print_success("Your next commit will be signed with Auths!");
    out.println("  Run `auths status` to check your identity");
}

pub(crate) fn display_ci_result(
    out: &Output,
    result: &auths_sdk::result::CiIdentityResult,
    ci_vendor: Option<&str>,
) {
    out.print_success(&format!("CI identity: {}", &result.identity_did));
    out.newline();

    out.print_heading("Add these to your CI secrets:");
    out.println("─".repeat(50).as_str());
    for line in &result.env_block {
        println!("{}", line);
    }
    out.println("─".repeat(50).as_str());
    out.newline();

    if let Some(vendor) = ci_vendor {
        write_ci_vendor_hints(out, vendor);
    }

    out.print_success("CI setup complete!");
    out.println("  Add the environment variables to your CI secrets");
    out.println("  Commits made in CI will be signed with the ephemeral identity");
}

pub(crate) fn display_agent_result(out: &Output, result: &auths_sdk::result::AgentIdentityResult) {
    out.print_heading("Agent Setup Complete!");
    out.newline();
    let did_display = result
        .agent_did
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| "<pending>".to_string());
    out.println(&format!("  Identity: {}", out.info(&did_display)));
    let cap_display: Vec<String> = result.capabilities.iter().map(|c| c.to_string()).collect();
    out.println(&format!("  Capabilities: {}", cap_display.join(", ")));
    out.newline();
    out.print_success("Agent is ready to sign commits!");
    out.println("  Start the agent: auths agent start");
    out.println("  Check status: auths agent status");
}

pub(crate) fn display_agent_dry_run(
    out: &Output,
    config: &auths_sdk::types::CreateAgentIdentityConfig,
) {
    out.print_heading("Dry Run — no files or identities will be created");
    out.newline();
    out.println(&format!("  Storage: {}", config.registry_path.display()));
    out.println(&format!("  Capabilities: {:?}", config.capabilities));
    if let Some(secs) = config.expires_in {
        out.println(&format!("  Expires in: {}s", secs));
    }
    out.newline();
    out.print_info("TOML config that would be generated:");
    let provisioning_config = auths_id::agent_identity::AgentProvisioningConfig {
        agent_name: config.alias.to_string(),
        capabilities: config.capabilities.iter().map(|c| c.to_string()).collect(),
        expires_in: config.expires_in,
        delegated_by: None,
        storage_mode: auths_id::agent_identity::AgentStorageMode::Persistent { repo_path: None },
    };
    out.println(&auths_id::agent_identity::format_agent_toml(
        "did:keri:E<pending>",
        "agent-key",
        &provisioning_config,
    ));
}

fn write_ci_vendor_hints(out: &Output, vendor: &str) {
    out.newline();
    out.print_heading(&format!("Hints for {}", vendor));

    match vendor {
        "GitHub Actions" => {
            out.println("Add to your workflow (.github/workflows/*.yml):");
            out.newline();
            out.println("  env:");
            out.println("    AUTHS_KEYCHAIN_BACKEND: memory");
            out.newline();
            out.println("  steps:");
            out.println("    - uses: actions/checkout@v4");
            out.println("    - run: auths init --profile ci --non-interactive");
        }
        "GitLab CI" => {
            out.println("Add to .gitlab-ci.yml:");
            out.newline();
            out.println("  variables:");
            out.println("    AUTHS_KEYCHAIN_BACKEND: memory");
            out.newline();
            out.println("  before_script:");
            out.println("    - auths init --profile ci --non-interactive");
        }
        _ => {
            out.println("Set these environment variables in your CI:");
            out.println("  AUTHS_KEYCHAIN_BACKEND=memory");
        }
    }
    out.newline();
}
