//! Display functions for init command results.

use crate::ux::format::{JsonResponse, Output, is_json_mode};

pub(crate) fn display_developer_result(
    out: &Output,
    result: &auths_sdk::result::DeveloperIdentityResult,
    registered: Option<&str>,
) {
    if is_json_mode() {
        let _ = JsonResponse::success(
            "init",
            serde_json::json!({
                "profile": "developer",
                "identity": result.identity_did.to_string(),
                "device": result.device_did.to_string(),
                "key_alias": result.key_alias.to_string(),
                "registry": registered,
            }),
        )
        .print();
        return;
    }
    out.newline();
    if registered.is_some() {
        out.print_heading("You are on the Web of Trust!");
    } else {
        out.print_heading("Your identity is ready!");
    }
    out.newline();
    out.println(&format!(
        "  Identity: {}",
        out.info(&crate::ux::product_id(&result.identity_did))
    ));
    out.println(&format!("  Key name: {}", out.info(&result.key_alias)));
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
    out.key_value("Next step     ", "auths demo   or   auths sign <file>");
    out.key_value("Share identity", "auths id export-bundle");
    out.newline();
    out.print_success("Your next `git commit` will be signed and verifiable with Auths!");
    out.println("  Verify any commit:  auths verify HEAD");
    out.println("  Check your setup:   auths status");
}

#[allow(clippy::print_stdout)]
pub(crate) fn display_ci_result(
    out: &Output,
    result: &auths_sdk::result::CiIdentityResult,
    ci_vendor: Option<&str>,
) {
    if is_json_mode() {
        let _ = JsonResponse::success(
            "init",
            serde_json::json!({
                "profile": "ci",
                "identity": result.identity_did.to_string(),
                "env": result.env_block,
            }),
        )
        .print();
        return;
    }
    out.print_success(&format!("CI identity: {}", &result.identity_did));
    out.newline();

    out.print_heading("Add these to your CI secrets:");
    out.println("─".repeat(50).as_str());
    // The env block is DATA, not prose: it must survive
    // `auths init --profile ci > secrets.env`, so it goes to stdout while the
    // surrounding guidance stays on stderr.
    for line in &result.env_block {
        println!("{line}");
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
    if is_json_mode() {
        let did_json = result.agent_did.as_ref().map(|d| d.to_string());
        let caps: Vec<String> = result.capabilities.iter().map(|c| c.to_string()).collect();
        let _ = JsonResponse::success(
            "init",
            serde_json::json!({
                "profile": "agent",
                "identity": did_json,
                "capabilities": caps,
            }),
        )
        .print();
        return;
    }
    out.print_heading("Agent Setup Complete!");
    out.newline();
    let did_display = result
        .agent_did
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| "<pending>".to_string());
    out.println(&format!(
        "  Identity: {}",
        out.info(&crate::ux::product_id(&did_display))
    ));
    let cap_display: Vec<String> = result.capabilities.iter().map(|c| c.to_string()).collect();
    out.println(&format!("  Capabilities: {}", cap_display.join(", ")));
    out.newline();
    out.print_success("Agent is ready to sign commits!");
    out.println("  Start the agent: auths daemon start");
    out.println("  Check status: auths daemon status");
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
    out.print_info(
        "An agent is a delegated identity under your root — after `auths init`, create one with \
         `auths id agent add`.",
    );
    out.print_info("TOML config that would be generated:");
    let provisioning_config = auths_sdk::identity::AgentProvisioningConfig {
        agent_name: config.alias.to_string(),
        capabilities: config.capabilities.clone(),
        expires_in: config.expires_in,
        delegated_by: None,
        storage_mode: auths_sdk::identity::AgentStorageMode::Persistent { repo_path: None },
    };
    out.println(&auths_sdk::identity::format_agent_toml(
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
            out.println("Add to your workflow (.github/workflows/*.yml) — init and sign in the");
            out.println("same job so the file-backed key persists between steps:");
            out.newline();
            out.println("  steps:");
            out.println("    - uses: actions/checkout@v4");
            out.println("    - run: auths init --profile ci --non-interactive");
            out.println("    - run: auths sign HEAD");
        }
        "GitLab CI" => {
            out.println("Add to .gitlab-ci.yml — init and sign in the same job so the");
            out.println("file-backed key persists between steps:");
            out.newline();
            out.println("  script:");
            out.println("    - auths init --profile ci --non-interactive");
            out.println("    - auths sign HEAD");
        }
        _ => {
            out.println("Run init and sign in the same CI job so the file-backed key persists:");
            out.println("  auths init --profile ci --non-interactive && auths sign HEAD");
        }
    }
    out.newline();
}
